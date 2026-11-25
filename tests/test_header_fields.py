"""Document headers leave out fields `init` was not given (UNVAR-85)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.phases.compare import run_comparison

cli = CliRunner()


def _header(text: str) -> str:
    """The metadata line under the title."""
    return text.split("\n")[2]


def _docs(eng: Engagement) -> dict[str, str]:
    p = eng.tool_paths("alpha")
    return {
        "findings": p.findings_doc.read_text(encoding="utf-8"),
        "architecture": p.architecture_doc.read_text(encoding="utf-8"),
        "requirements": p.requirements_doc.read_text(encoding="utf-8"),
        "comparison": eng.comparison_doc.read_text(encoding="utf-8"),
    }


def _render(eng: Engagement, synthetic_repo: Path) -> dict[str, str]:
    stub = _compare_stub()
    _two_tools(eng, synthetic_repo, stub)
    run_comparison(eng, backend=stub)
    return _docs(eng)


def test_headers_leave_out_missing_client_and_consultant(tmp_path, synthetic_repo):
    eng = Engagement.create(tmp_path / "bare")
    for name, text in _render(eng, synthetic_repo).items():
        header = _header(text)
        assert "Client:" not in header, name
        assert "Prepared by:" not in header, name
        assert "—" not in header, name
        assert "**Generated:**" in header, name


def test_headers_keep_only_the_fields_given(tmp_path, synthetic_repo):
    eng = Engagement.create(tmp_path / "half", client="Acme")
    for name, text in _render(eng, synthetic_repo).items():
        header = _header(text)
        assert "Prepared by:" not in header and "—" not in header, name
        if name != "comparison":  # the comparison names the client in its title
            assert header.startswith("**Client:** Acme · **Generated:**"), name


def test_init_without_client_hints_documents_carry_no_name(tmp_path):
    result = cli.invoke(app, ["init", str(tmp_path / "e")])
    assert result.exit_code == 0, result.output
    assert "--client" in result.output
    assert "no client name" in result.output


def test_init_with_client_and_consultant_gives_no_hint(tmp_path):
    result = cli.invoke(app, ["init", str(tmp_path / "e"), "--client", "Acme",
                              "--consultant", "Bonham Technologies"])
    assert result.exit_code == 0, result.output
    assert "no client name" not in result.output and "no firm name" not in result.output
