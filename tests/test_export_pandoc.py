import base64
import re
import shutil
import zipfile
from pathlib import Path

import pytest

from unvarnish.config import BrandingConfig
from unvarnish.export.markdown import prepare_markdown
from unvarnish.export.pandoc import build_pandoc_command, bundled_asset, export_markdown
from unvarnish.export.tools import (
    INSTALL_HINTS,
    MIN_WEASYPRINT_TAGGED,
    ToolsMissing,
    installed_weasyprint_version,
    missing_tools,
    untagged_pdf_reason,
)
from unvarnish.render.diagram import Diagram, Node

SAMPLE = """# Sample: Findings

**Client:** Acme

## Summary

| Measure | Value |
|---|---|
| Files | 12 |

<!-- unvarnish-diagram: context -->
```mermaid
flowchart LR
    n0["x"]
```

Done.
"""


def test_missing_tools_lists_each_with_hints():
    present = {"pandoc": "/usr/bin/pandoc"}
    missing = missing_tools(["docx", "pdf"], which=lambda t: present.get(t))
    assert missing == ["dot", "weasyprint"]
    assert missing_tools(["html"], which=lambda t: "/x") == []
    msg = str(ToolsMissing(missing))
    assert "dot" in msg and "weasyprint" in msg and "brew install graphviz" in msg
    assert all(tool in INSTALL_HINTS for tool in ("pandoc", "dot", "weasyprint"))


def test_bundled_assets_exist():
    assert bundled_asset("report.css").read_text().strip().startswith(("body", "/*", ":root"))
    assert bundled_asset("reference.docx").stat().st_size > 1000


def test_build_pandoc_command_per_format(tmp_path: Path):
    src = tmp_path / "doc.md"
    docx = build_pandoc_command(src, "docx", tmp_path / "o.docx", title="T",
                                resource_dir=tmp_path, reference_docx=Path("/r.docx"), css=None)
    assert docx[:4] == ["pandoc", str(src), "-f", "gfm-raw_html"]
    assert "--reference-doc=/r.docx" in docx
    assert f"--lua-filter={bundled_asset('inert-html.lua')}" in docx
    assert "-t" in docx and docx[docx.index("-t") + 1] == "docx"
    html = build_pandoc_command(src, "html", tmp_path / "o.html", title="T",
                                resource_dir=tmp_path, reference_docx=None, css=Path("/s.css"))
    assert "--standalone" in html and "--embed-resources" in html and "--css=/s.css" in html
    assert "--metadata=pagetitle:T" in html and f"--resource-path={tmp_path}" in html
    pdf = build_pandoc_command(src, "pdf", tmp_path / "o.pdf", title="T",
                               resource_dir=tmp_path, reference_docx=None, css=Path("/s.css"))
    assert "--pdf-engine=weasyprint" in pdf and "--css=/s.css" in pdf
    assert all(any(a.startswith("--lua-filter=") for a in c) for c in (docx, html, pdf))


def test_html_accessibility_filter_is_scoped_to_html(tmp_path: Path):
    """The <main> and row-header filter runs for HTML only, after the inert-HTML filter (whose
    pass would otherwise turn its raw <main> markers into text). Word and PDF get exactly the
    commands they had before it, so their output cannot change."""
    a11y = f"--lua-filter={bundled_asset('html-a11y.lua')}"
    inert = f"--lua-filter={bundled_asset('inert-html.lua')}"
    assert bundled_asset("html-a11y.lua").is_file()
    cmds = {fmt: build_pandoc_command(tmp_path / "a.md", fmt, tmp_path / f"o.{fmt}", title="T",
                                      resource_dir=tmp_path, reference_docx=None, css=None)
            for fmt in ("docx", "html", "pdf")}
    assert a11y in cmds["html"] and cmds["html"].index(inert) < cmds["html"].index(a11y)
    for fmt in ("docx", "pdf"):
        assert [a for a in cmds[fmt] if a.startswith("--lua-filter=")] == [inert]


TABLES = """# Doc

| Severity | S | Total |
|---|---:|---:|
| High | 1 | 1 |
| **Total** | 1 | 1 |

| Finding | Severity | Location |
|---|---|---|
| Hardcoded key | high | `a.py:1` |
"""


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="pandoc needed")
def test_html_row_headers_only_in_summary_tables(tmp_path: Path):
    from html.parser import HTMLParser

    class Cells(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tables: list[list[tuple[str, str | None]]] = []
            self.main_open = False

        def handle_starttag(self, tag, attrs):
            if tag == "main":
                self.main_open = True
            elif tag == "table":
                self.tables.append([])
            elif tag in ("th", "td"):
                self.tables[-1].append((tag, dict(attrs).get("scope")))

    md = tmp_path / "doc.md"
    md.write_text(TABLES, encoding="utf-8")
    export_markdown(md, "html", tmp_path / "o.html", diagrams={}, branding=BrandingConfig(),
                    template=None, work_dir=tmp_path / "work")
    page = Cells()
    page.feed((tmp_path / "o.html").read_text(encoding="utf-8"))
    summary, listing = page.tables
    assert page.main_open
    assert summary == [("th", "col")] * 3 + [("th", "row"), ("td", None), ("td", None)] * 2
    # a list of findings is not a summary: its first column stays data cells
    assert listing == [("th", "col")] * 3 + [("td", None)] * 3


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_export_markdown_html_and_docx(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE)
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="ctx node")])}
    failures = export_markdown(md, "html", tmp_path / "out.html", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work")
    html = (tmp_path / "out.html").read_text()
    inlined = "".join(base64.b64decode(b).decode("utf-8", "replace") for b in
                      re.findall(r"data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)", html))
    assert failures == [] and "<table" in html and "ctx node" in html + inlined
    assert "data:image/svg+xml" in html or "<svg" in html  # inlined, self-contained
    assert "<title>Sample: Findings</title>" in html
    failures = export_markdown(md, "docx", tmp_path / "out.docx", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work2")
    assert failures == [] and (tmp_path / "out.docx").stat().st_size > 5000


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None
                    or shutil.which("weasyprint") is None, reason="pdf toolchain needed")
def test_export_markdown_pdf(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE)
    export_markdown(md, "pdf", tmp_path / "out.pdf", diagrams={}, branding=BrandingConfig(),
                    template=None, work_dir=tmp_path / "work")
    assert (tmp_path / "out.pdf").read_bytes()[:5] == b"%PDF-"


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="pandoc needed")
def test_export_markdown_reports_pandoc_failure(tmp_path: Path):
    md = tmp_path / "doc.md"
    md.write_text("# x\n")
    with pytest.raises(RuntimeError, match="pandoc"):
        export_markdown(md, "docx", tmp_path / "out.docx", diagrams={},
                        branding=BrandingConfig(reference_docx="/nonexistent/ref.docx"),
                        template=None, work_dir=tmp_path / "w")


HOSTILE = """# Demo: Findings

#### Finding <img src=x onerror=alert(2)>

Summary <script>alert(1)</script> returns List<String>.

<!-- unvarnish-diagram: context -->
```mermaid
flowchart LR
    n0["x"]
```
"""


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_raw_html_in_model_text_is_inert(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(HOSTILE)
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="ctx node")])}
    failures = export_markdown(md, "html", tmp_path / "out.html", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work")
    html = (tmp_path / "out.html").read_text()
    assert failures == [] and "data:image/svg+xml" in html  # the diagram still embeds
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "List&lt;String&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html
    assert "unvarnish-diagram" not in html
    export_markdown(md, "docx", tmp_path / "out.docx", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work2")
    with zipfile.ZipFile(tmp_path / "out.docx") as z:
        body = z.read("word/document.xml").decode("utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body and "List&lt;String&gt;" in body


def test_orphan_diagram_marker_is_dropped(tmp_path: Path):
    md = "# T\n\n<!-- unvarnish-diagram: gone -->\n\nText.\n"
    out, failures = prepare_markdown(md, {}, tmp_path / "images")
    assert "unvarnish-diagram" not in out and "Text." in out


HOSTILE_MARKDOWN = """# Demo: Findings

#### Finding ![leak]({secret}) and ![remote](https://example.invalid/pixel.png)

Summary [click](javascript:alert(1)), <javascript:alert(2)>, [data](data:text/html,x),
[local](file:///etc/passwd) and [spaced](java script:alert(3)). See [docs](https://example.com/docs)
and [mail](mailto:a@example.com). Paths: [abs](/etc/passwd), [proto](//evil.example/share/x),
[unc](\\\\evil\\share), [rel](../../x.txt), [top](#summary), ![fake](images/missing.svg).

<!-- unvarnish-diagram: context -->
```mermaid
flowchart LR
    n0["x"]
```
"""


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_model_text_cannot_embed_files_or_script_links(tmp_path: Path):
    marker = "UNVARNISH-PRIVATE-MARKER-7f3a"
    secret = tmp_path / "private.svg"
    secret.write_text(f'<svg xmlns="http://www.w3.org/2000/svg"><text>{marker}</text></svg>')
    md = tmp_path / "findings.md"
    md.write_text(HOSTILE_MARKDOWN.format(secret=secret))
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="ctx node")])}
    failures = export_markdown(md, "html", tmp_path / "out.html", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work")
    html = (tmp_path / "out.html").read_text()
    inlined = "".join(base64.b64decode(b).decode("utf-8", "replace") for b in
                      re.findall(r"base64,([A-Za-z0-9+/=]+)", html))
    assert failures == [] and "ctx node" in html + inlined  # the diagram still embeds
    assert marker not in html and marker not in inlined
    assert "example.invalid/pixel.png" not in re.findall(r'src="([^"]*)"', html)
    hrefs = re.findall(r'href="([^"]*)"', html)
    assert "https://example.com/docs" in hrefs and "mailto:a@example.com" in hrefs
    assert all(h.startswith(("https:", "mailto:", "#")) for h in hrefs), hrefs
    assert "images/missing.svg" not in re.findall(r'src="([^"]*)"', html)
    assert "javascript:alert(1)" in html  # shown as text, not dropped
    export_markdown(md, "docx", tmp_path / "out.docx", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work2")
    with zipfile.ZipFile(tmp_path / "out.docx") as z:
        names = z.namelist()
        rels = z.read("word/_rels/document.xml.rels").decode("utf-8")
        media = b"".join(z.read(n) for n in names if n.startswith("word/media/"))
    assert marker.encode() not in media and "javascript:" not in rels
    assert any(n.startswith("word/media/") for n in names)  # the diagram is still there
    if shutil.which("weasyprint") is not None:  # PDF link annotations must not point at files
        export_markdown(md, "pdf", tmp_path / "out.pdf", diagrams=diagrams,
                        branding=BrandingConfig(), template=None, work_dir=tmp_path / "work3")
        pdf = (tmp_path / "out.pdf").read_bytes()
        assert b"file:" not in pdf and b"javascript:" not in pdf.lower()


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_html_export_sets_lang_and_diagram_alt(tmp_path: Path):
    md = tmp_path / "architecture.md"
    md.write_text(SAMPLE.replace("unvarnish-diagram: context", "unvarnish-diagram: modules"))
    diagrams = {"modules": Diagram(title="t: modules", nodes=[Node(id="a", label="a.py")])}
    export_markdown(md, "html", tmp_path / "out.html", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work")
    html = (tmp_path / "out.html").read_text()
    assert re.search(r'<html[^>]*\slang="en"', html)
    alts = re.findall(r'<img[^>]*\salt="([^"]*)"', html)
    assert alts and all(a and a != "modules" for a in alts)
    assert alts[0].startswith("Module map:")
    export_markdown(md, "html", tmp_path / "fr.html", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "w2",
                    lang="fr")
    assert re.search(r'<html[^>]*\slang="fr"', (tmp_path / "fr.html").read_text())


def test_diagram_alt_text_is_a_sentence_for_every_known_diagram(tmp_path: Path):
    from unvarnish.export.markdown import diagram_alt_text
    for name in ("context", "modules", "integration"):
        alt = diagram_alt_text(name, Diagram(title=f"tool: {name}"))
        assert alt != name and ":" in alt and len(alt.split()) >= 4
    other = diagram_alt_text("custom", Diagram(title="My [odd] chart"))
    assert "[" not in other and "]" not in other and "My" in other


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_docx_export_carries_diagram_alt_text(tmp_path: Path):
    md = tmp_path / "architecture.md"
    md.write_text(SAMPLE)
    diagrams = {"context": Diagram(title="t: context", nodes=[Node(id="a", label="x")])}
    export_markdown(md, "docx", tmp_path / "out.docx", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work")
    with zipfile.ZipFile(tmp_path / "out.docx") as z:
        doc = z.read("word/document.xml").decode("utf-8")
    descr = re.findall(r'<wp:docPr[^>]*\sdescr="([^"]*)"', doc)
    assert descr and descr[0].startswith("Context diagram:")


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None
                    or shutil.which("weasyprint") is None, reason="pdf toolchain needed")
def test_pdf_export_declares_lang(tmp_path: Path):
    import zlib

    md = tmp_path / "architecture.md"
    md.write_text(SAMPLE)
    diagrams = {"context": Diagram(title="t: context", nodes=[Node(id="a", label="x")])}
    export_markdown(md, "pdf", tmp_path / "out.pdf", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work",
                    lang="de")
    pdf = (tmp_path / "out.pdf").read_bytes()
    streams = [pdf]  # weasyprint puts the catalog's /Lang in a compressed object stream
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.DOTALL):
        try:
            streams.append(zlib.decompress(m.group(1)))
        except zlib.error:
            continue
    assert any(re.search(rb"/Lang\s*\(de\)", s) for s in streams)


def test_build_pandoc_command_passes_lang(tmp_path: Path):
    cmd = build_pandoc_command(tmp_path / "a.md", "html", tmp_path / "a.html", title="T",
                               resource_dir=tmp_path, reference_docx=None, css=None,
                               lang="en-GB")
    assert "--metadata=lang:en-GB" in cmd
    default = build_pandoc_command(tmp_path / "a.md", "docx", tmp_path / "a.docx", title="T",
                                   resource_dir=tmp_path, reference_docx=None, css=None)
    assert "--metadata=lang:en" in default


def test_pdf_command_asks_weasyprint_for_a_tagged_pdf(tmp_path: Path):
    pdf = build_pandoc_command(tmp_path / "a.md", "pdf", tmp_path / "a.pdf", title="T",
                               resource_dir=tmp_path, reference_docx=None, css=None)
    assert "--pdf-engine-opt=--pdf-variant=pdf/ua-1" in pdf
    for fmt in ("html", "docx"):
        other = build_pandoc_command(tmp_path / "a.md", fmt, tmp_path / f"a.{fmt}", title="T",
                                     resource_dir=tmp_path, reference_docx=None, css=None)
        assert not any(a.startswith("--pdf-engine-opt") for a in other)


def test_pdf_command_without_tagging_leaves_out_the_variant(tmp_path: Path):
    pdf = build_pandoc_command(tmp_path / "a.md", "pdf", tmp_path / "a.pdf", title="T",
                               resource_dir=tmp_path, reference_docx=None, css=None,
                               pdf_tagged=False)
    assert "--pdf-engine=weasyprint" in pdf
    assert not any(a.startswith("--pdf-engine-opt") for a in pdf)


@pytest.mark.parametrize(("output", "version"), [
    (b"WeasyPrint version 70.0\n", (70, 0)),
    (b"WeasyPrint version 61.1\n", (61, 1)),
    (b"weasyprint version 66.0.1", (66, 0, 1)),
    (b"something else entirely", None),
])
def test_installed_weasyprint_version_parses_its_banner(monkeypatch, output, version):
    import subprocess

    from unvarnish.export import tools

    def fake_run(cmd, **kw):
        assert cmd == ["weasyprint", "--version"]
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr=b"")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    assert installed_weasyprint_version() == version


def test_installed_weasyprint_version_is_none_when_it_cannot_run(monkeypatch):
    from unvarnish.export import tools

    def broken(cmd, **kw):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(tools.subprocess, "run", broken)
    assert installed_weasyprint_version() is None


def test_untagged_pdf_reason_names_the_version_and_the_way_out():
    assert MIN_WEASYPRINT_TAGGED == (66, 0)
    assert untagged_pdf_reason((66, 0)) is None
    assert untagged_pdf_reason((70, 0)) is None
    old = untagged_pdf_reason((61, 1))
    assert old is not None
    assert "61.1" in old and "66.0" in old and "untagged" in old and "Docker image" in old
    unknown = untagged_pdf_reason(None)
    assert unknown is not None and "untagged" in unknown and "66.0" in unknown


def _pdf_objects(pdf: bytes) -> list[bytes]:
    """The file and every stream that inflates: weasyprint puts the catalog and the
    annotations in compressed object streams."""
    import zlib

    streams = [pdf]
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.DOTALL):
        try:
            streams.append(zlib.decompress(m.group(1)))
        except zlib.error:
            continue
    return streams


def _top_level(data: bytes, start: int) -> bytes:
    """The dictionary opening at `start`, with its nested dictionaries cut out."""
    depth, i, out = 0, start, bytearray()
    while i < len(data):
        pair = data[i:i + 2]
        if pair == b"<<":
            depth += 1
            i += 2
            continue
        if pair == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                break
            continue
        if depth == 1:
            out.append(data[i])
        i += 1
    return bytes(out)


def _link_annotation_flags(streams: list[bytes]) -> list[int]:
    """The /F value of every link annotation (0 when it has none)."""
    flags: list[int] = []
    for s in streams:
        for m in re.finditer(rb"/Subtype\s*/Link\b", s):
            depth, i = 0, m.start()
            while i > 0:  # walk back to the << that opens this annotation
                i -= 1
                if s[i:i + 2] == b">>":
                    depth += 1
                elif s[i:i + 2] == b"<<" and (i == 0 or s[i - 1:i] != b"<"):
                    if depth == 0:
                        break
                    depth -= 1
            own = _top_level(s, i)
            f = re.search(rb"/F\s+(\d+)", own)
            flags.append(int(f.group(1)) if f else 0)
    return flags


PDF_TOOLCHAIN = pytest.mark.skipif(
    shutil.which("pandoc") is None or shutil.which("dot") is None
    or shutil.which("weasyprint") is None, reason="pdf toolchain needed")


def _export_linked_pdf(tmp_path: Path, *, pdf_tagged: bool) -> list[bytes]:
    md = tmp_path / "architecture.md"
    md.write_text(SAMPLE.replace("Done.", "See [pandoc](https://pandoc.org/) for more."),
                  encoding="utf-8")
    diagrams = {"context": Diagram(title="t: context", nodes=[Node(id="a", label="x")])}
    failures = export_markdown(md, "pdf", tmp_path / "out.pdf", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work", lang="de", pdf_tagged=pdf_tagged)
    assert failures == []
    return _pdf_objects((tmp_path / "out.pdf").read_bytes())


@PDF_TOOLCHAIN
def test_pdf_export_is_tagged_and_its_links_stay_visible(tmp_path: Path):
    version = installed_weasyprint_version()
    if untagged_pdf_reason(version) is not None:
        pytest.skip(f"weasyprint {version} predates tagged PDFs with visible links")
    streams = _export_linked_pdf(tmp_path, pdf_tagged=True)
    for marker in (rb"/MarkInfo\s*<<\s*/Marked\s+true", rb"/StructTreeRoot",
                   rb"/Lang\s*\(de\)"):
        assert any(re.search(marker, s) for s in streams), marker
    flags = _link_annotation_flags(streams)
    assert flags, "no link annotation in the PDF"
    assert not any(f & 2 for f in flags), f"a link annotation is Hidden: /F {flags}"


@PDF_TOOLCHAIN
def test_pdf_export_from_an_older_weasyprint_is_untagged_with_visible_links(tmp_path: Path):
    version = installed_weasyprint_version()
    if untagged_pdf_reason(version) is None:
        pytest.skip(f"weasyprint {version} tags PDFs")
    streams = _export_linked_pdf(tmp_path, pdf_tagged=False)
    assert not any(re.search(rb"/StructTreeRoot", s) for s in streams)
    assert any(re.search(rb"/Lang\s*\(de\)", s) for s in streams)
    flags = _link_annotation_flags(streams)
    assert flags and not any(f & 2 for f in flags), flags


def test_link_annotation_flags_reads_only_the_annotation_itself():
    data = (b"<</Type /Annot /Subtype /Link /Rect [0 0 1 1] /BS <</W 0>> "
            b"/A <</S /URI /URI (x) /F 7>> /F 2>> "
            b"<</Type /Annot /Subtype /Link /A <</F 2>> >>")
    assert _link_annotation_flags([data]) == [2, 0]


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_docx_core_properties(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE.replace("# Sample: Findings", "# Sample & <Co>: Findings"))
    export_markdown(md, "docx", tmp_path / "out.docx", diagrams={}, branding=BrandingConfig(),
                    template=None, work_dir=tmp_path / "work", lang="de",
                    author="Dana Q. Consultant")
    with zipfile.ZipFile(tmp_path / "out.docx") as z:
        core = z.read("docProps/core.xml").decode("utf-8")
        doc = z.read("word/document.xml").decode("utf-8")
        names = z.namelist()
    assert "<dc:title>Sample &amp; &lt;Co&gt;: Findings</dc:title>" in core
    assert "<dc:creator>Dana Q. Consultant</dc:creator>" in core
    assert "<dc:language>de</dc:language>" in core
    assert names[0] == "[Content_Types].xml"
    # exactly one top-level title in the body: the H1, no extra Title or Author paragraph
    assert doc.count('w:val="Heading1"') == 1
    assert 'w:val="Title"' not in doc and 'w:val="Author"' not in doc


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_docx_creator_defaults_to_unvarnish(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE)
    export_markdown(md, "docx", tmp_path / "out.docx", diagrams={}, branding=BrandingConfig(),
                    template=None, work_dir=tmp_path / "work")
    with zipfile.ZipFile(tmp_path / "out.docx") as z:
        core = z.read("docProps/core.xml").decode("utf-8")
    assert "<dc:title>Sample: Findings</dc:title>" in core
    assert "<dc:creator>Unvarnish</dc:creator>" in core


def test_docx_core_properties_drop_characters_xml_forbids(tmp_path: Path):
    from xml.etree import ElementTree

    from unvarnish.export.pandoc import set_docx_core_properties

    docx = tmp_path / "a.docx"
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("docProps/core.xml",
                   '<cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc">'
                   "<dc:title/></cp:coreProperties>")
    set_docx_core_properties(docx, title="bad\x01 \\1 title", creator="O'Brien & Sons")
    with zipfile.ZipFile(docx) as z:
        core = z.read("docProps/core.xml").decode("utf-8")
        assert z.namelist() == ["[Content_Types].xml", "docProps/core.xml"]
    ElementTree.fromstring(core)  # well-formed
    assert "<dc:title>bad \\1 title</dc:title>" in core
    assert "<dc:creator>O'Brien &amp; Sons</dc:creator>" in core
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("css_path", [
    bundled_asset("report.css"),
    Path(__file__).resolve().parents[1] / "branding" / "bonham" / "report.css",
], ids=["bundled", "branding"])
def test_links_are_underlined_on_screen_and_in_print(css_path: Path):
    css = css_path.read_text(encoding="utf-8")
    link_rules = re.findall(r"(?<![\w-])a\s*\{([^}]*)\}", css)
    assert link_rules, "no rule for links"
    assert not any(re.search(r"text-decoration\s*:\s*none", r) for r in link_rules)
    screen = css.split("@media print", 1)[0]
    assert re.search(r"(?<![\w-])a\s*\{[^}]*text-decoration\s*:\s*underline", screen)


@pytest.mark.parametrize("css_path", [
    bundled_asset("report.css"),
    Path(__file__).resolve().parents[1] / "branding" / "bonham" / "report.css",
], ids=["bundled", "branding"])
def test_row_headers_are_styled_like_data_cells(css_path: Path):
    css = css_path.read_text(encoding="utf-8")
    rule = re.search(r"^tbody th\s*\{([^}]*)\}", css, re.MULTILINE)
    assert rule, "no rule for row headers"
    assert re.search(r"font-weight\s*:\s*normal", rule.group(1))
    assert re.search(r"background\s*:\s*none", rule.group(1))
    assert re.search(r"td,\s*tbody th\s*\{[^}]*border-bottom", css)
