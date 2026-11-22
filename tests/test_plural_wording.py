"""Client documents and scanner summaries use plural words, never "(s)" (UNVAR-57)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.test_scanner_bus_factor import _ctx, _git
from tests.test_scanner_hardcoded_infra import _scan
from unvarnish.phases import scan
from unvarnish.phases.base import build_context
from unvarnish.render.markdown import make_env
from unvarnish.scanners.bus_factor import BusFactorScanner
from unvarnish.util.plural import is_are, plural, pluralize

SRC = Path(__file__).resolve().parent.parent / "src" / "unvarnish"


@pytest.mark.parametrize(("n", "expected"), [
    (0, "0 findings"), (1, "1 finding"), (2, "2 findings"), (13, "13 findings"),
])
def test_plural_regular(n, expected):
    assert plural(n, "finding") == expected


@pytest.mark.parametrize(("n", "expected"), [
    (0, "0 vulnerabilities"), (1, "1 vulnerability"), (2, "2 vulnerabilities"),
])
def test_plural_y_ending(n, expected):
    assert plural(n, "vulnerability") == expected


def test_plural_irregular_and_sibilant():
    assert plural(2, "index", "indices") == "2 indices"
    assert plural(1, "index", "indices") == "1 index"
    assert plural(2, "match") == "2 matches"
    assert plural(2, "key") == "2 keys"


def test_pluralize_and_is_are():
    assert pluralize(1, "table") == "table"
    assert pluralize(0, "table") == "tables"
    assert is_are(1) == "is"
    assert is_are(0) == is_are(5) == "are"


def test_template_filters_registered():
    env = make_env()
    tpl = env.from_string("{{ n | plural('finding') }} {{ n | is_are }}")
    assert tpl.render(n=1) == "1 finding is"
    assert tpl.render(n=5) == "5 findings are"
    assert env.from_string("{{ 2 | plural('credential-like value') }}").render() == (
        "2 credential-like values")


def test_no_paren_s_in_user_facing_sources():
    # Every user-facing string: documents, scanner summaries, and since UNVAR-68 the console
    # and error messages too. Model prompts are left alone: rewording one bumps its prompt
    # version and re-spends model calls in every engagement.
    pattern = re.compile(r"(?<![.\w])(?!len\b|Counter\b|set\b|sum\b|Source\b)[A-Za-z]+\(s\)")
    prompts = SRC / "model" / "prompts"
    hits = [f"{p.relative_to(SRC)}:{i}" for p in SRC.rglob("*")
            if p.is_file() and p.suffix in {".py", ".j2"} and prompts not in p.parents
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if pattern.search(line)]
    assert hits == []


@pytest.mark.parametrize("authors", [[1.0], [0.97, 0.03]])
def test_bus_factor_summary_has_no_paren_s(authors):
    findings = BusFactorScanner().run(_ctx(_git(authors)))
    assert findings
    assert "(s)" not in findings[0].summary
    noun = "author" if len(authors) == 1 else "authors"
    assert f"{len(authors)} {noun} in total" in findings[0].summary


def test_one_distinct_value_is_singular(engagement, synthetic_repo):
    _, findings = _scan(engagement, synthetic_repo,
                        {"settings.py": 'PROXY = "10.0.12.7:3128"\n'})
    f = next(f for f in findings if f.title == "Hardcoded IP addresses")
    assert f.summary.startswith("1 distinct IP address hardcoded at 1 location,"), f.summary


def test_scanner_wording_version_is_in_the_scan_inputs_hash(ingested, monkeypatch):
    """A scan written before the wording changed reruns once (deterministic, no model calls),
    so a plain run after upgrading does not render the old "(s)" summaries."""
    eng, tool = ingested
    ctx = build_context(eng, tool)
    before = scan.ScanPhase().inputs_hash(ctx)
    monkeypatch.setattr(scan, "SCANNER_TEXT_VERSION", "changed")
    assert scan.ScanPhase().inputs_hash(ctx) != before


@pytest.mark.parametrize(("failed", "expected"), [
    (1, "The only conversion failed"), (2, "All 2 conversions failed"),
])
def test_export_all_failed_message_agrees(engagement, synthetic_repo, monkeypatch, failed,
                                          expected):
    from typer.testing import CliRunner

    from unvarnish import cli
    from unvarnish.export.exporter import ExportItem, ExportReport

    report = ExportReport(items=[ExportItem(doc="findings", tool="t", fmt=f, status="failed")
                                 for f in ["pdf", "docx"][:failed]])
    runner = CliRunner()
    runner.invoke(cli.app, ["add", "t", "--repo", str(synthetic_repo),
                            "-e", str(engagement.root)])
    monkeypatch.setattr(cli, "export_engagement", lambda *_a, **_k: report)
    r = runner.invoke(cli.app, ["export", "-e", str(engagement.root)], env={"COLUMNS": "400"})
    assert r.exit_code == 1
    assert expected in r.output and "All 1 " not in r.output


# ---------------------------------------------------------------- phase lines (UNVAR-81)

ONE_PLURAL = re.compile(
    r"(?<![\d,.])1 (commits|files|units|tools|capabilities|findings|modules|scanners|docs"
    r"|chunks|documents)\b")


def _one_file_repo(root: Path) -> Path:
    import subprocess

    root.mkdir()
    (root / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    env = {"GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@example.com",
           "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@example.com",
           "PATH": __import__("os").environ["PATH"], "HOME": str(root)}
    for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "one"]):
        subprocess.run(["git", *args], cwd=root, env=env, check=True)
    return root


def test_one_commit_one_file_tool_reads_in_the_singular(tmp_path, fake_llm):
    # UNVAR-81: UNVAR-68 fixed the console and error messages but the phase lines and status
    # cells still said "1 commits", "1 files", "1 units in 1 files" and "1 docs".
    from typer.testing import CliRunner

    from tests.conftest import model_config
    from unvarnish.cli import app
    from unvarnish.config import EngagementConfig
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "acme", client="Acme")
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(),
                                                  **model_config(fake_llm)})
    eng.save_config()
    fake_llm.autofill = True
    repo = _one_file_repo(tmp_path / "one")
    runner = CliRunner()
    wide = {"COLUMNS": "400"}
    added = runner.invoke(app, ["add", "one", "--repo", str(repo), "-e", str(eng.root)])
    assert added.exit_code == 0, added.output
    out = runner.invoke(app, ["run", "-e", str(eng.root)], env=wide)
    assert out.exit_code == 0, out.output
    assert re.search(r"\b1 commit\b", out.output) and re.search(r"\b1 file\b", out.output)
    assert "1 unit in 1 file" in out.output
    compared = runner.invoke(app, ["compare", "-e", str(eng.root)], env=wide)
    status = runner.invoke(app, ["status", "-e", str(eng.root)], env=wide)
    assert status.exit_code == 0, status.output
    text = "\n".join((out.output, compared.output, status.output))
    assert not ONE_PLURAL.search(text), ONE_PLURAL.findall(text)


def test_phase_messages_and_status_cells_use_plural():
    # Every count in a phase message or a status cell goes through util.plural, so a count of
    # one reads in the singular whatever the data (UNVAR-81).
    nouns = ("commits|files|units|tools|capabilities|findings|modules|scanners|docs|chunks"
             "|documents|rows|digests|blocks|stores")
    # A count, an optional fraction, then at most one word ("model findings", "matrix rows")
    # before the noun; "{n} without units" and "{n} of {m}" read fine as they are.
    pattern = re.compile(r"\{[^{}]*\}(?:/\{[^{}]*\})? (?:(?!without\b|of\b)[a-z/-]+ )?(?:"
                         + nouns + r")\b")
    files = [*(SRC / "phases").glob("*.py"), SRC / "cli.py", SRC / "model" / "estimate.py",
             SRC / "scanners" / "bus_factor.py", SRC / "scanners" / "vendored_bulk.py"]
    hits = [f"{p.relative_to(SRC)}:{i}" for p in files
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if pattern.search(line)]
    assert hits == []


@pytest.mark.parametrize(("routes", "verb", "pronoun"), [(1, "has", "it"), (2, "have", "them")])
def test_route_handler_sentence_agrees_in_number(routes, verb, pronoun):
    from types import SimpleNamespace

    from unvarnish.scanners.client_exposure import _routes_summary

    text = _routes_summary([SimpleNamespace(path="a.js")] * routes, 25)
    assert f" {verb} no authentication identifier" in text
    assert f"near {pronoun}." in text
