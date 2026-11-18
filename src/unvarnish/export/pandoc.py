from __future__ import annotations

import logging
import re
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from xml.sax.saxutils import escape

from unvarnish.config import BrandingConfig
from unvarnish.export.graphviz import render_with_dot
from unvarnish.export.markdown import prepare_markdown
from unvarnish.render.diagram import Diagram

TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
IMAGE_FORMAT = {"docx": "png", "html": "svg", "pdf": "svg"}
DEFAULT_AUTHOR = "Unvarnish"
CORE_XML = "docProps/core.xml"
# Characters XML 1.0 forbids: escape() leaves them, and one in core.xml makes Word refuse the file.
XML_INVALID_RE = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
log = logging.getLogger("unvarnish.export")


def bundled_asset(name: str) -> Path:
    return Path(str(resources.files("unvarnish.export").joinpath("assets", name)))


def document_title(md: str, fallback: str) -> str:
    m = TITLE_RE.search(md)
    return m.group(1) if m else fallback


def build_pandoc_command(src: Path, fmt: str, out: Path, *, title: str, resource_dir: Path,
                         reference_docx: Path | None, css: Path | None,
                         pandoc: str = "pandoc", lang: str = "en",
                         pdf_tagged: bool = True,
                         author: str | None = None) -> list[str]:
    # Model-written and scanned text comes from the client's untrusted code, so any HTML in it
    # (a quoted <script>, List<String>) must reach the reader as text. pandoc 3.1's gfm reader
    # ignores -raw_html, so the bundled filter turns whatever raw HTML remains into text.
    cmd = [pandoc, str(src), "-f", "gfm-raw_html", f"--resource-path={resource_dir}",
           f"--lua-filter={bundled_asset('inert-html.lua')}",
           f"--metadata=pagetitle:{title}", f"--metadata=lang:{lang}", "-o", str(out)]
    if fmt == "docx":
        cmd += ["-t", "docx"]
        if reference_docx is not None:
            cmd.append(f"--reference-doc={reference_docx}")
    elif fmt == "html":
        # HTML only, after inert-html.lua: a <main> landmark and row headers in summary
        # tables. Word and PDF keep the commands they had, so their output does not change.
        cmd += ["-t", "html5", "--standalone", "--embed-resources",
                f"--lua-filter={bundled_asset('html-a11y.lua')}"]
        if css is not None:
            cmd.append(f"--css={css}")
    elif fmt == "pdf":
        cmd += ["-t", "html5", "--standalone", "--pdf-engine=weasyprint"]
        if pdf_tagged:
            # PDF/UA-1 makes weasyprint tag the structure (headings, tables, lists) and mark the
            # file as tagged, so assistive technology can follow it instead of one flat run of
            # text. The exporter turns it off for a weasyprint that would hide the links.
            cmd.append("--pdf-engine-opt=--pdf-variant=pdf/ua-1")
        if css is not None:
            cmd.append(f"--css={css}")
    else:
        raise ValueError(f"unknown export format {fmt!r}")
    if author and fmt in ("html", "pdf"):
        # The html5 template prints `author` only in the title block, which needs `title`, and
        # only `pagetitle` is set: so it becomes <meta name="author"> (weasyprint's PDF /Author)
        # and never a visible byline. DOCX gets its author after pandoc instead.
        cmd.append(f"--metadata=author:{author}")
    return cmd


def _set_core_element(core: str, tag: str, value: str) -> str:
    element = f"<dc:{tag}>{escape(XML_INVALID_RE.sub('', value))}</dc:{tag}>"
    pattern = re.compile(rf"<dc:{tag}\s*/>|<dc:{tag}>.*?</dc:{tag}>", re.DOTALL)
    if pattern.search(core):
        return pattern.sub(lambda _: element, core, count=1)
    return core.replace("</cp:coreProperties>", element + "</cp:coreProperties>", 1)


def set_docx_core_properties(docx: Path, *, title: str, creator: str) -> None:
    """Fill the Word document's Title and Author properties (docProps/core.xml).

    pandoc fills dc:title and dc:creator only from `title` and `author` metadata, and the docx
    writer then also prints both as Title and Author paragraphs above the report's own H1. So
    the properties are written here, after pandoc, and the body stays exactly as rendered."""
    tmp = docx.with_name(docx.name + ".tmp")
    try:
        with zipfile.ZipFile(docx) as src, zipfile.ZipFile(tmp, "w") as dst:
            for info in src.infolist():  # keep the order: [Content_Types].xml stays first
                data = src.read(info)
                if info.filename == CORE_XML:
                    core = data.decode("utf-8")
                    core = _set_core_element(core, "title", title)
                    core = _set_core_element(core, "creator", creator)
                    data = core.encode("utf-8")
                dst.writestr(info, data)
        shutil.move(tmp, docx)
    finally:
        tmp.unlink(missing_ok=True)


def run_pandoc(cmd: list[str], cwd: Path | None = None) -> None:
    """Run pandoc. The working directory defaults to the command's --resource-path: pandoc
    3.1.x writes its PDF intermediate HTML into the cwd, and weasyprint then resolves image
    paths against it, so running anywhere else silently drops every diagram."""
    if cwd is None:
        cwd = next((Path(a.split("=", 1)[1]) for a in cmd if a.startswith("--resource-path=")),
                   None)
    proc = subprocess.run(cmd, capture_output=True, timeout=600, cwd=cwd)
    err = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        raise RuntimeError(f"pandoc exited {proc.returncode}: {err[:400]}")
    lost = [line for line in err.splitlines() if "Failed to load image" in line]
    if lost:  # weasyprint drops the image and pandoc still exits 0: never ship that silently
        raise RuntimeError(f"pandoc: {len(lost)} image(s) could not be loaded: {lost[0][:300]}")


def _branding(fmt: str, branding: BrandingConfig,
              template: Path | None) -> tuple[Path | None, Path | None]:
    """(reference_docx, css) for this format: --template, then config, then bundled."""
    if fmt == "docx":
        ref = template or (Path(branding.reference_docx) if branding.reference_docx else None)
        return ref or bundled_asset("reference.docx"), None
    css = template or (Path(branding.html_css) if branding.html_css else None)
    return None, css or bundled_asset("report.css")


def export_markdown(md_path: Path, fmt: str, out: Path, *, diagrams: dict[str, Diagram],
                    branding: BrandingConfig, template: Path | None, work_dir: Path,
                    render: Callable[[str, str], bytes] = render_with_dot,
                    pandoc: str = "pandoc",
                    runner: Callable[[list[str]], None] | None = None,
                    lang: str = "en", author: str = DEFAULT_AUTHOR,
                    pdf_tagged: bool = True) -> list[str]:
    """Convert one rendered Markdown document; returns diagram failures (non-fatal)."""
    md_path, out, work_dir = md_path.resolve(), out.resolve(), work_dir.resolve()
    template = template.resolve() if template is not None else None
    work_dir.mkdir(parents=True, exist_ok=True)
    md = md_path.read_text(encoding="utf-8")
    prepared, failures = prepare_markdown(md, diagrams, work_dir / "images",
                                          image_format=IMAGE_FORMAT[fmt], render=render)
    src = work_dir / md_path.name
    src.write_text(prepared, encoding="utf-8")
    reference_docx, css = _branding(fmt, branding, template)
    out.parent.mkdir(parents=True, exist_ok=True)
    title = document_title(md, md_path.stem)
    cmd = build_pandoc_command(src, fmt, out, title=title,
                               resource_dir=work_dir, reference_docx=reference_docx, css=css,
                               pandoc=pandoc, lang=lang, pdf_tagged=pdf_tagged,
                               author=author or DEFAULT_AUTHOR)
    (runner or run_pandoc)(cmd)
    if fmt == "docx" and zipfile.is_zipfile(out):  # a test runner may stand in for pandoc
        try:
            set_docx_core_properties(out, title=title, creator=author or DEFAULT_AUTHOR)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:  # pandoc's file still stands
            log.warning("could not set Title and Author in %s: %r", out.name, exc)
    return failures
