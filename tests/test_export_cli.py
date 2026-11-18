import shutil
from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.cli import app
from unvarnish.export import exporter as exporter_module
from unvarnish.export.exporter import check_template, export_engagement, template_kind
from unvarnish.phases.compare import run_comparison

runner = CliRunner()
HAVE_TOOLS = shutil.which("pandoc") is not None and shutil.which("dot") is not None


def _rendered(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    return engagement


def test_template_kind_and_mismatch():
    assert template_kind(Path("brand.docx")) == "docx" and template_kind(Path("x.CSS")) == "css"
    with pytest.raises(ValueError, match="docx"):
        check_template(Path("brand.css"), ["docx"])
    with pytest.raises(ValueError, match="css"):
        check_template(Path("brand.docx"), ["html"])
    check_template(Path("brand.docx"), ["docx"])
    check_template(None, ["docx", "html", "pdf"])


def test_export_missing_tools_exits_2_with_hints(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: None)
    out = runner.invoke(app, ["export", "--format", "html", "-e", str(engagement.root)])
    assert out.exit_code == 2, out.output
    assert "pandoc" in out.output and "dot" in out.output and "brew install" in out.output
    assert list(engagement.exports_dir.iterdir()) == []


def test_export_unknown_doc_or_tool_exits_2(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--doc", "poetry", "-e", str(engagement.root)])
    assert out.exit_code == 2 and "unknown document" in out.output
    out = runner.invoke(app, ["export", "nope", "-e", str(engagement.root)])
    assert out.exit_code == 2 and "unknown tool" in out.output


def test_export_format_and_doc_are_case_insensitive(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--format", "CSV", "--doc", "Findings",
                              "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert list(engagement.exports_dir.glob("findings-*.csv"))


def test_export_html_format_and_doc_are_case_insensitive(engagement, synthetic_repo,
                                                         monkeypatch):
    import functools

    from unvarnish import cli

    _rendered(engagement, synthetic_repo)
    monkeypatch.setattr(exporter_module, "run_pandoc", _fake_pandoc_ok)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    monkeypatch.setattr(cli, "export_engagement",
                        functools.partial(export_engagement, render=_fake_render))
    out = runner.invoke(app, ["export", "alpha", "--format", "HTML", "--doc", "Findings",
                              "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert [p.name.split("-")[0] for p in engagement.exports_dir.glob("*.html")] == ["findings"]


def test_export_template_kind_mismatch_exits_2(engagement, synthetic_repo, tmp_path):
    _rendered(engagement, synthetic_repo)
    css = tmp_path / "brand.css"
    css.write_text("body{}")
    out = runner.invoke(app, ["export", "--format", "docx", "--template", str(css),
                              "-e", str(engagement.root)])
    assert out.exit_code == 2 and "docx" in out.output


def _fake_render(src: str, fmt: str) -> bytes:
    return b"<svg/>" if fmt == "svg" else b"\x89PNG\r\n\x1a\n"


def _fake_pandoc_ok(cmd):
    Path(cmd[cmd.index("-o") + 1]).write_bytes(b"converted")


def test_export_skips_missing_documents(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    engagement.tool_paths("beta").architecture_doc.unlink()
    monkeypatch.setattr(exporter_module, "run_pandoc", _fake_pandoc_ok)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["html"], docs=None, tools=None,
                               template=None, timestamp="20261017-120000", render=_fake_render)
    skipped = [i for i in report.items if i.status == "skipped"]
    assert [(i.doc, i.tool) for i in skipped] == [("architecture", "beta")]
    assert "not rendered" in skipped[0].detail
    ok = [i for i in report.items if i.status == "ok"]
    assert {i.path for i in ok} >= {"exports/findings-alpha-20261017-120000.html",
                                    "exports/comparison-engagement-20261017-120000.html"}
    assert all(Path(engagement.root, i.path).exists() for i in ok)


def test_export_records_conversion_failures(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)

    def flaky(cmd):
        if "findings" in cmd[1]:
            raise RuntimeError("pandoc exited 1: boom")
        _fake_pandoc_ok(cmd)

    monkeypatch.setattr(exporter_module, "run_pandoc", flaky)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["docx"], docs=["findings", "requirements"],
                               tools=["alpha"], template=None, render=_fake_render)
    assert [(i.doc, i.status) for i in report.items] == [("findings", "failed"),
                                                         ("requirements", "ok")]
    assert "boom" in report.failed[0].detail


def test_export_passes_report_lang_to_pandoc(engagement, synthetic_repo, monkeypatch):
    from unvarnish.config import EngagementConfig

    _rendered(engagement, synthetic_repo)
    data = engagement.config.model_dump()
    data["report"]["lang"] = "en-GB"
    engagement.config = EngagementConfig.model_validate(data)
    seen: list[list[str]] = []

    def capture(cmd):
        seen.append(cmd)
        _fake_pandoc_ok(cmd)

    monkeypatch.setattr(exporter_module, "run_pandoc", capture)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    export_engagement(engagement, formats=["html"], docs=["findings"], tools=["alpha"],
                      template=None, render=_fake_render)
    assert seen and all("--metadata=lang:en-GB" in cmd for cmd in seen)


@pytest.mark.parametrize("bad", ["en\n", "en:x", "en --lua-filter=x.lua", "-en", "e", "en_GB",
                                 " en", "en-", ""])
def test_report_lang_rejects_anything_but_a_language_tag(bad):
    from pydantic import ValidationError

    from unvarnish.config import ReportConfig

    with pytest.raises(ValidationError):
        ReportConfig(lang=bad)
    assert ReportConfig().lang == "en" and ReportConfig(lang="zh-Hant-TW").lang == "zh-Hant-TW"


@pytest.mark.skipif(not HAVE_TOOLS, reason="pandoc and graphviz needed")
def test_export_cli_end_to_end(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--format", "html", "--doc", "findings",
                              "--doc", "comparison", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    produced = sorted(p.name for p in engagement.exports_dir.glob("*.html"))
    assert len(produced) == 3  # findings for alpha and beta, plus the comparison
    html = next(engagement.exports_dir.glob("comparison-engagement-*.html")).read_text()
    assert "<table" in html and ("<svg" in html or "data:image/svg+xml" in html)
    out = runner.invoke(app, ["export", "--format", "docx", "alpha", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert len(list(engagement.exports_dir.glob("*-alpha-*.docx"))) == 3


@pytest.mark.skipif(not HAVE_TOOLS, reason="pandoc and graphviz needed")
def test_docx_export_credits_the_engagement_consultant(engagement, synthetic_repo):
    import zipfile

    _rendered(engagement, synthetic_repo)
    report = export_engagement(engagement, formats=["docx"], docs=["findings"],
                               tools=["alpha"], template=None)
    assert [i.status for i in report.items] == ["ok"]
    with zipfile.ZipFile(engagement.root / report.items[0].path) as z:
        core = z.read("docProps/core.xml").decode("utf-8")
    assert "<dc:creator>Bonham Technologies</dc:creator>" in core
    assert "<dc:title></dc:title>" not in core


def test_export_cli_nothing_to_export_exits_1(engagement, synthetic_repo, monkeypatch):
    from unvarnish.phases.ingest import ingest_tool

    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")  # never run
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    out = runner.invoke(app, ["export", "-e", str(engagement.root)])
    assert out.exit_code == 1 and "nothing to export" in out.output.lower()


@pytest.mark.parametrize("formats", [["csv"], ["sarif"], ["sarif", "docx"], ["sarif", "csv"]])
def test_export_data_format_without_findings_doc_exits_2(engagement, synthetic_repo, formats):
    # sarif and csv are the findings document's data: asking for them with a --doc list that
    # leaves findings out cannot work, and "run unvarnish run first" would send the user astray.
    _rendered(engagement, synthetic_repo)
    args = ["export", "--doc", "architecture", "-e", str(engagement.root)]
    for f in formats:
        args += ["--format", f]
    out = runner.invoke(app, args)
    assert out.exit_code == 2, out.output
    assert "sarif and csv come from the findings document" in out.output
    assert "--doc findings" in out.output
    assert "Nothing to export" not in out.output
    assert list(engagement.exports_dir.iterdir()) == []  # no work done, not even docx


def test_export_data_format_with_findings_doc_still_works(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--format", "sarif", "--doc", "architecture",
                              "--doc", "findings", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert list(engagement.exports_dir.glob("findings-*.sarif"))


class _Landmarks(HTMLParser):
    """Collects <main> nesting and, per table, its column headers and row header cells."""

    def __init__(self):
        super().__init__()
        self.mains, self.depth, self.in_main_h1 = 0, 0, False
        self.tables: list[dict] = []
        self._cell: dict | None = None
        self._section = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "main":
            self.mains += 1
            self.depth += 1
        elif tag == "h1" and self.depth:
            self.in_main_h1 = True
        elif tag == "table":
            self.tables.append({"in_main": bool(self.depth), "head": [], "rows": []})
        elif tag in ("thead", "tbody"):
            self._section = tag
        elif tag == "tr" and self._section == "tbody":
            self.tables[-1]["rows"].append([])
        elif tag in ("th", "td"):
            self._cell = {"tag": tag, "scope": a.get("scope"), "text": ""}

    def handle_endtag(self, tag):
        if tag == "main":
            self.depth -= 1
        elif tag in ("th", "td") and self._cell is not None:
            table = self.tables[-1]
            (table["head"] if self._section == "thead" else table["rows"][-1]).append(self._cell)
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell["text"] += data


@pytest.mark.skipif(not HAVE_TOOLS, reason="pandoc and graphviz needed")
def test_html_export_has_main_landmark_and_row_headers(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    report = export_engagement(engagement, formats=["html"], docs=["findings"],
                               tools=["alpha"], template=None)
    assert [i.status for i in report.items] == ["ok"]
    page = _Landmarks()
    page.feed((engagement.root / report.items[0].path).read_text(encoding="utf-8"))
    assert page.mains == 1 and page.in_main_h1
    assert page.tables and all(t["in_main"] for t in page.tables)
    severity = next(t for t in page.tables if t["head"][0]["text"] == "Severity")
    assert all(c == {**c, "tag": "th", "scope": "col"} for c in severity["head"])
    assert severity["rows"] and all(r[0]["tag"] == "th" and r[0]["scope"] == "row"
                                    for r in severity["rows"])
    assert all(c["tag"] == "td" for r in severity["rows"] for c in r[1:])
    labels = [r[0]["text"].strip() for r in severity["rows"]]
    assert labels[-1] == "Total"
    measure = next(t for t in page.tables if t["head"][0]["text"] == "Measure")
    assert all(r[0]["scope"] == "row" for r in measure["rows"])
