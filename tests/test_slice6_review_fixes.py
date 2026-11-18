"""Tests pinning the fixes from the slice 6 whole-branch review."""
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.cli import app
from unvarnish.config import BrandingConfig, UnsupportedSchemaVersion, load_config
from unvarnish.engagement import Engagement
from unvarnish.export import exporter as exporter_module
from unvarnish.export import pandoc as pandoc_module
from unvarnish.export.markdown import prepare_markdown
from unvarnish.export.pandoc import export_markdown
from unvarnish.export.tools import ToolsMissing, check_toolchain
from unvarnish.phases.compare import run_comparison
from unvarnish.render.diagram import Diagram, Node

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
FENCE = '```mermaid\nflowchart LR\n    n0["x"]\n```'


def _rendered(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    return engagement


def _fake_render(src: str, fmt: str) -> bytes:
    return b"<svg/>" if fmt == "svg" else b"\x89PNG\r\n\x1a\n"


# --- C1: pandoc runs inside the work dir with absolute paths -------------------------------

def test_pandoc_runs_in_the_work_dir_with_absolute_paths(tmp_path, monkeypatch):
    seen = {}

    class Proc:
        returncode = 0
        stderr = b""

    def fake_run(cmd, **kw):
        seen["cmd"], seen["cwd"] = cmd, kw.get("cwd")
        return Proc()

    monkeypatch.setattr(pandoc_module.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    md = tmp_path / "doc.md"
    md.write_text("# T\n")
    export_markdown(Path("doc.md"), "pdf", Path("out/doc.pdf"), diagrams={},
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "work")
    assert Path(seen["cwd"]) == tmp_path / "work"
    out = seen["cmd"][seen["cmd"].index("-o") + 1]
    assert Path(out).is_absolute() and Path(seen["cmd"][1]).is_absolute()


@pytest.mark.skipif(any(shutil.which(t) is None for t in ("pandoc", "dot", "weasyprint")),
                    reason="pdf toolchain needed")
def test_pdf_contains_the_diagram_from_another_cwd(tmp_path, monkeypatch):
    md = tmp_path / "doc.md"
    md.write_text(f"# T\n\n<!-- unvarnish-diagram: context -->\n{FENCE}\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="node " * 30)])}
    # run_pandoc raises when weasyprint reports an image it could not load, so a clean
    # return is the proof the diagram made it into the PDF
    export_markdown(md, "pdf", tmp_path / "with.pdf", diagrams=diagrams,
                    branding=BrandingConfig(), template=None, work_dir=tmp_path / "w1")
    assert (tmp_path / "with.pdf").read_bytes()[:5] == b"%PDF-"
    assert list(elsewhere.iterdir()) == []  # pandoc left nothing in the caller's cwd


def test_run_pandoc_fails_when_weasyprint_drops_an_image(monkeypatch):
    class Proc:
        returncode = 0
        stderr = b"ERROR: Failed to load image at 'file:///x/images/context.svg': URLError"

    monkeypatch.setattr(pandoc_module.subprocess, "run", lambda cmd, **kw: Proc())
    with pytest.raises(RuntimeError, match="could not be loaded"):
        pandoc_module.run_pandoc(["pandoc", "x.md", "-o", "x.pdf"])


# --- I2: diagram failures are shown, not hidden behind the output path ----------------------

def test_cli_warns_about_diagram_failures(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    engagement.tool_paths("alpha").diagrams.unlink()
    monkeypatch.setattr(exporter_module, "run_pandoc",
                        lambda cmd: Path(cmd[cmd.index("-o") + 1]).write_bytes(b"x"))
    monkeypatch.setattr(exporter_module, "check_toolchain", lambda formats, **kw: None)
    out = runner.invoke(app, ["export", "--format", "html", "--doc", "architecture", "alpha",
                              "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert "warning" in out.output.lower() and "context" in out.output


# --- I3: tolerant fence matching; leftover Mermaid recorded ---------------------------------

@pytest.mark.parametrize("md", [
    f"<!-- unvarnish-diagram: context -->\r\n{FENCE.replace(chr(10), chr(13) + chr(10))}\r\n",
    f"<!-- unvarnish-diagram: context -->  \n{FENCE}\n",
    f"<!--unvarnish-diagram: context-->\n\n{FENCE}\n",
])
def test_prepare_markdown_tolerates_hand_edits(tmp_path, md):
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="x")])}
    out, failures = prepare_markdown(md, diagrams, tmp_path / "img", render=_fake_render)
    assert "](img/context.svg)" in out and "```mermaid" not in out
    assert failures == []


def test_prepare_markdown_reports_unconverted_mermaid(tmp_path):
    out, failures = prepare_markdown(f"# x\n\n{FENCE}\n", {}, tmp_path / "img",
                                     render=_fake_render)
    assert "```mermaid" in out
    assert failures == ["1 Mermaid block without an unvarnish-diagram marker was left as text"]


# --- I4: schema guard covers strings, floats, and every command ------------------------------

@pytest.mark.parametrize("value", ['"2"', "2.0"])
def test_schema_guard_rejects_non_int_newer_versions(tmp_path, value):
    eng = Engagement.create(tmp_path / "e")
    eng.config_file.write_text(eng.config_file.read_text().replace(
        "schema_version: 1", f"schema_version: {value}"))
    with pytest.raises(UnsupportedSchemaVersion):
        load_config(eng.config_file)


def test_scanners_list_refuses_newer_schema(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    eng.config_file.write_text(eng.config_file.read_text().replace(
        "schema_version: 1", "schema_version: 2"))
    out = runner.invoke(app, ["scanners", "list", "-e", str(eng.root)])
    assert out.exit_code == 2 and "newer Unvarnish" in out.output


# --- I5: branding paths resolve against the engagement; missing files exit 2 ----------------

def test_branding_paths_resolve_against_the_engagement(engagement, synthetic_repo, monkeypatch,
                                                      tmp_path):
    _rendered(engagement, synthetic_repo)
    (engagement.root / "brand.css").write_text("body { color: teal; }")
    engagement.config.report.branding.html_css = "brand.css"
    engagement.save_config()
    seen: list[list[str]] = []

    def fake(cmd):
        seen.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_bytes(b"x")

    monkeypatch.setattr(exporter_module, "run_pandoc", fake)
    monkeypatch.setattr(exporter_module, "check_toolchain", lambda formats, **kw: None)
    monkeypatch.chdir(tmp_path)
    out = runner.invoke(app, ["export", "--format", "html", "--doc", "findings", "alpha",
                              "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert f"--css={engagement.root / 'brand.css'}" in seen[0]


def test_missing_branding_or_template_exits_2(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    monkeypatch.setattr(exporter_module, "check_toolchain", lambda formats, **kw: None)
    out = runner.invoke(app, ["export", "--format", "docx", "--template", "/nope/brand.docx",
                              "-e", str(engagement.root)])
    assert out.exit_code == 2 and "not found" in out.output
    engagement.config.report.branding.html_css = "missing.css"
    engagement.save_config()
    out = runner.invoke(app, ["export", "--format", "html", "-e", str(engagement.root)])
    assert out.exit_code == 2 and "missing.css" in out.output and "not found" in out.output


def test_all_conversions_failing_is_not_called_nothing_to_export(engagement, synthetic_repo,
                                                                  monkeypatch):
    _rendered(engagement, synthetic_repo)

    def boom(cmd):
        raise RuntimeError("pandoc exited 1: broken")

    monkeypatch.setattr(exporter_module, "run_pandoc", boom)
    monkeypatch.setattr(exporter_module, "check_toolchain", lambda formats, **kw: None)
    out = runner.invoke(app, ["export", "--format", "html", "-e", str(engagement.root)])
    assert out.exit_code == 1
    assert "nothing to export" not in out.output.lower() and "failed" in out.output.lower()


# --- I6: Docker image works for non-root users and host-owned repositories ------------------

@pytest.mark.skipif(not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout")
def test_dockerfile_hardening_for_linux_hosts():
    text = (ROOT / "Dockerfile").read_text()
    assert "safe.directory" in text and "HOME=/tmp" in text
    assert "python:3.13-slim-trixie" in text  # pinned: bookworm's pandoc is too old
    assert '--user "$(id -u):$(id -g)"' in (ROOT / "README.md").read_text()


# --- I7: a pandoc too old for --embed-resources is caught up front -------------------------

def test_check_toolchain_rejects_old_pandoc():
    which = lambda t: f"/usr/bin/{t}"  # noqa: E731
    with pytest.raises(ToolsMissing, match="2.19"):
        check_toolchain(["html"], which=which, pandoc_version=lambda: (2, 17))
    check_toolchain(["html"], which=which, pandoc_version=lambda: (3, 1, 11))
    with pytest.raises(ToolsMissing, match="dot"):
        check_toolchain(["html"], which=lambda t: None if t == "dot" else "/x",
                        pandoc_version=lambda: (3, 1))
