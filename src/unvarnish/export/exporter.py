from __future__ import annotations

import json
import logging
import shutil
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.artifacts import read_artifact
from unvarnish.config import BrandingConfig
from unvarnish.engagement import Engagement
from unvarnish.export.findings_data import csv_text, load_findings, sarif_documents
from unvarnish.export.graphviz import render_with_dot
from unvarnish.export.pandoc import DEFAULT_AUTHOR, export_markdown, run_pandoc
from unvarnish.export.tools import check_toolchain
from unvarnish.render.diagram import Diagram
from unvarnish.schemas.diagrams import DiagramSet

log = logging.getLogger("unvarnish.export")
DOC_NAMES = ("architecture", "findings", "requirements", "comparison")
FORMATS = ("docx", "html", "pdf")  # the documents; `--format all` and the default
DATA_FORMATS = ("sarif", "csv")  # each tool's findings as data; opt-in, no pandoc
ENGAGEMENT = "engagement"


class ExportItem(BaseModel):
    doc: str
    tool: str
    fmt: str
    path: str | None = None  # relative to the engagement root
    status: Literal["ok", "skipped", "failed"]
    detail: str = ""


class ExportReport(BaseModel):
    items: list[ExportItem] = Field(default_factory=list)

    @property
    def ok(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "ok"]

    @property
    def failed(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "failed"]

    @property
    def skipped(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "skipped"]


def template_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".docx", ".css"):
        return suffix[1:]
    raise ValueError(f"--template must be a .docx or .css file, not {path.name}")


def check_template(template: Path | None, formats: Sequence[str]) -> None:
    if template is None:
        return
    kind = template_kind(template)
    wants_docx = "docx" in formats
    wants_css = any(f in formats for f in ("html", "pdf"))
    if wants_docx and not wants_css and kind != "docx":
        raise ValueError(f"--template for docx must be a .docx reference document, "
                         f"not {template.name}")
    if wants_css and not wants_docx and kind != "css":
        raise ValueError(f"--template for html/pdf must be a .css stylesheet, "
                         f"not {template.name}")
    if wants_docx and wants_css:
        raise ValueError("--template applies to one kind of output; pass --format docx or "
                         "--format html/pdf with it")


def resolve_branding(eng: Engagement, template: Path | None,
                     formats: Sequence[str]) -> tuple[BrandingConfig, Path | None]:
    """Config paths resolve against the engagement (it is meant to be zipped and moved);
    --template resolves against the cwd. Every file that will be used must exist."""
    b = eng.config.report.branding

    def res(p: str | None) -> Path | None:
        return None if not p else (Path(p) if Path(p).is_absolute() else eng.root / p)

    ref, css = res(b.reference_docx), res(b.html_css)
    template = template.resolve() if template is not None else None
    checks: list[tuple[str, Path]] = []
    if template is not None:
        checks.append(("--template", template))
    else:
        if "docx" in formats and ref is not None:
            checks.append(("report.branding.reference_docx", ref))
        if any(f in formats for f in ("html", "pdf")) and css is not None:
            checks.append(("report.branding.html_css", css))
    for label, path in checks:
        if not path.is_file():
            raise ValueError(f"{label} not found: {path}")
    return BrandingConfig(reference_docx=str(ref) if ref else None,
                          html_css=str(css) if css else None), template


def _sources(eng: Engagement, docs: Sequence[str], tools: Sequence[str]
             ) -> list[tuple[str, str, Path, Path]]:
    """(doc, tool, markdown path, diagrams path) for every requested document."""
    out: list[tuple[str, str, Path, Path]] = []
    for tool in tools:
        p = eng.tool_paths(tool)
        for doc in docs:
            if doc == "comparison":
                continue
            md = {"architecture": p.architecture_doc, "findings": p.findings_doc,
                  "requirements": p.requirements_doc}[doc]
            out.append((doc, tool, md, p.diagrams))
    if "comparison" in docs:
        out.append(("comparison", ENGAGEMENT, eng.comparison_doc, eng.comparison_diagrams))
    return out


def _unique(path: Path) -> Path:
    """`path`, or `name-2.ext`, `name-3.ext`, ... when an earlier export took the name."""
    n = 2
    candidate = path
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}-{n}{path.suffix}")
        n += 1
    return candidate


def _diagrams(path: Path) -> dict[str, Diagram]:
    if not path.exists():
        return {}
    try:
        return read_artifact(path, DiagramSet).data.diagrams
    except Exception as exc:
        log.warning("ignoring unreadable %s: %r", path, exc)
        return {}


def export_engagement(eng: Engagement, *, formats: Sequence[str], docs: Sequence[str] | None,
                      tools: Sequence[str] | None, template: Path | None,
                      timestamp: str | None = None,
                      render: Callable[[str, str], bytes] = render_with_dot,
                      pandoc: str = "pandoc") -> ExportReport:
    """Export every requested document in every requested format, and each tool's findings
    as SARIF or CSV when asked. Raises ToolsMissing and ValueError before touching exports/;
    per-file conversion failures are recorded."""
    data_formats = [f for f in formats if f in DATA_FORMATS]
    formats = [f for f in formats if f not in DATA_FORMATS]
    if template is not None and not formats:
        raise ValueError("--template applies to docx, html and pdf, not to sarif or csv")
    check_template(template, formats)  # the user's own mistakes first, whatever is installed
    branding, template = resolve_branding(eng, template, formats)
    if formats:  # sarif and csv are written here, without pandoc
        check_toolchain(formats, which=shutil.which)
    # Naming tools exports their documents; the engagement comparison only when asked for.
    docs = list(docs or (DOC_NAMES if tools is None else
                         [d for d in DOC_NAMES if d != "comparison"]))
    tools = list(tools or eng.tool_names())
    stamp = timestamp or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    report = ExportReport()
    eng.exports_dir.mkdir(parents=True, exist_ok=True)
    for doc, tool, md, diagrams_path in _sources(eng, docs, tools):
        for fmt in formats:
            item = ExportItem(doc=doc, tool=tool, fmt=fmt, status="skipped")
            if not md.exists():
                item.detail = f"not rendered: {md.relative_to(eng.root)} does not exist"
                report.items.append(item)
                continue
            out = _unique(eng.exports_dir / f"{doc}-{tool}-{stamp}.{fmt}")
            with tempfile.TemporaryDirectory(prefix="unvarnish-export-") as tmp:
                try:
                    failures = export_markdown(
                        md, fmt, out, diagrams=_diagrams(diagrams_path),
                        branding=branding, template=template,
                        work_dir=Path(tmp), render=render, pandoc=pandoc,
                        # run_pandoc is looked up here so tests can patch this module
                        runner=run_pandoc, lang=eng.config.report.lang,
                        author=eng.config.consultant or DEFAULT_AUTHOR)
                except Exception as exc:  # one failed conversion never kills the export
                    log.exception("export %s/%s/%s failed", doc, tool, fmt)
                    item.status, item.detail = "failed", str(exc)[:300]
                    out.unlink(missing_ok=True)
                    report.items.append(item)
                    continue
            item.status = "ok"
            item.path = out.relative_to(eng.root).as_posix()
            item.detail = "; ".join(failures) if failures else ""
            report.items.append(item)
    if "findings" in docs:  # sarif and csv are the findings document's data
        for tool in tools:
            for fmt in data_formats:
                report.items += _export_findings_data(eng, tool, fmt, stamp)
    return report


def _export_findings_data(eng: Engagement, tool: str, fmt: str, stamp: str) -> list[ExportItem]:
    """exports/findings-<tool>-<stamp>.<fmt>; a SARIF log over GitHub's per-run result limit
    is split into -part1, -part2, ... files, one run each."""
    p = eng.tool_paths(tool)
    if not p.scanner_findings.exists():
        return [ExportItem(doc="findings", tool=tool, fmt=fmt, status="skipped",
                           detail=f"not scanned: {p.scanner_findings.relative_to(eng.root)} "
                                  "does not exist")]
    written: list[Path] = []
    try:
        findings = load_findings(p)
        if fmt == "csv":
            payloads = [csv_text(findings)]
        else:
            payloads = [json.dumps(d, indent=2, ensure_ascii=False) + "\n"
                        for d in sarif_documents(tool, findings)]
        many = len(payloads) > 1
        for n, text in enumerate(payloads, start=1):
            out = _unique(eng.exports_dir /
                          f"findings-{tool}-{stamp}{f'-part{n}' if many else ''}.{fmt}")
            out.write_text(text, encoding="utf-8", newline="")
            written.append(out)
    except Exception as exc:  # one failed export never kills the others
        log.exception("export findings/%s/%s failed", tool, fmt)
        for out in written:
            out.unlink(missing_ok=True)
        return [ExportItem(doc="findings", tool=tool, fmt=fmt, status="failed",
                           detail=str(exc)[:300])]
    detail = (f"split into {len(written)} files: GitHub accepts at most 25,000 results per run"
              if len(written) > 1 else "")
    return [ExportItem(doc="findings", tool=tool, fmt=fmt, status="ok", detail=detail,
                       path=out.relative_to(eng.root).as_posix()) for out in written]
