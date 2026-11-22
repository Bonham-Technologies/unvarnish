import json
import re
from pathlib import Path

from typer.testing import CliRunner

from unvarnish.cli import app

runner = CliRunner()


def _setup(tmp_path: Path, synthetic_repo: Path) -> Path:
    eng = tmp_path / "acme"
    assert runner.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = runner.invoke(app, ["add", "expense-bot", "--repo", str(synthetic_repo), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    return eng


def test_end_to_end_run(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    for phase in ("inventory", "git", "scan", "render"):
        assert phase in r.output
    doc = (eng / "tools" / "expense-bot" / "docs" / "findings.md").read_text()
    assert "Single-author concentration" in doc

    again = runner.invoke(app, ["run", "-e", str(eng)])
    assert again.exit_code == 0
    assert again.output.count("fresh") == 5  # extract is skipped: no model configured
    assert "no model configured" in again.output

    forced = runner.invoke(
        app, ["run", "expense-bot", "--phase", "scan", "--force", "-e", str(eng)]
    )
    assert forced.exit_code == 0, forced.output
    assert "scan" in forced.output and "inventory" not in forced.output


def test_dry_run_and_unknown_phase(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng)])
    assert dry.exit_code == 0, dry.output
    assert "inventory" in dry.output
    assert not (eng / "tools" / "expense-bot" / "inventory" / "census.json").exists()
    bad = runner.invoke(app, ["run", "--phase", "nope", "-e", str(eng)])
    assert bad.exit_code == 2
    assert "unknown phase" in bad.output
    upper = runner.invoke(app, ["run", "--dry-run", "--phase", "SCAN", "-e", str(eng)])
    assert upper.exit_code == 0, upper.output  # UNVAR-11: lower-cased like --format and --doc
    assert "scan" in upper.output and "inventory" not in upper.output


def test_run_unknown_tool_and_empty_engagement(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    r = runner.invoke(app, ["run", "ghost", "-e", str(eng)])
    assert r.exit_code == 2 and "ghost" in r.output
    empty = tmp_path / "empty"
    assert runner.invoke(app, ["init", str(empty)]).exit_code == 0
    r2 = runner.invoke(app, ["run", "-e", str(empty)])
    assert r2.exit_code == 2 and "no tools" in r2.output


def test_status(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    before = runner.invoke(app, ["status", "-e", str(eng)])
    assert before.exit_code == 0 and "missing" in before.output
    assert runner.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    after = runner.invoke(app, ["status", "-e", str(eng)])
    assert after.exit_code == 0
    # inventory, git, scan, split are fresh; render shows its document count; model phases
    # never ran because no model is configured
    assert after.output.count("fresh") == 4
    assert re.search(r"\b1 doc\b", after.output)  # singular since UNVAR-81


def test_scanners_list(tmp_path: Path):
    r = runner.invoke(app, ["scanners", "list"])
    assert r.exit_code == 0
    for name in ("secrets", "oversized_files", "hygiene", "bus_factor"):
        assert name in r.output
    assert "file_lines" in r.output


# --- fixes from the whole-branch review -------------------------------------
def test_failures_are_persisted_and_shown_in_status(tmp_path: Path):
    eng = tmp_path / "acme"
    assert runner.invoke(app, ["init", str(eng)]).exit_code == 0
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "package.json").write_text("[]")
    (pile / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["add", "pile", "--files", str(pile), "-e", str(eng)]).exit_code == 0
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 1, r.output
    failures = eng / "tools" / "pile" / "analysis" / "run-record.json"
    assert failures.exists()
    assert "package.json" in failures.read_text()
    st = runner.invoke(app, ["status", "-e", str(eng)])
    assert st.exit_code == 0
    assert "1 failure" in st.output


def test_phase_without_upstream_names_missing_phase(tmp_path: Path, synthetic_repo: Path):
    """UNVAR-5: on a freshly added tool, --phase scan says which phase to run first."""
    eng = _setup(tmp_path, synthetic_repo)
    r = runner.invoke(app, ["run", "expense-bot", "--phase", "scan", "-e", str(eng)],
                      env={"COLUMNS": "200"})
    assert r.exit_code != 0, r.output
    assert "needs inventory" in r.output and "--phase inventory" in r.output
    assert "FileNotFoundError" not in r.output
    status = runner.invoke(app, ["status", "-e", str(eng)],
                           env={"COLUMNS": "200"})
    assert "needs inventory" in status.output or "1 failure" in status.output

    # with inventory in place, the next missing upstream phase is named
    assert runner.invoke(app, ["run", "expense-bot", "--phase", "inventory",
                               "-e", str(eng)]).exit_code == 0
    r = runner.invoke(app, ["run", "expense-bot", "--phase", "scan", "-e", str(eng)],
                      env={"COLUMNS": "200"})
    assert r.exit_code != 0 and "needs git" in r.output, r.output


# --- UNVAR-17: a tool whose tool.yaml is gone ---------------------------------
MISSING_MSG = "tool.yaml not found; remove it from engagement.yaml or add it again"


def test_missing_tool_yaml_is_reported_not_raised(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    (eng / "tools" / "expense-bot" / "tool.yaml").unlink()
    env = {"COLUMNS": "200"}
    st = runner.invoke(app, ["status", "-e", str(eng)], env=env)
    assert st.exit_code == 0, st.output
    assert "missing" in st.output and MISSING_MSG in st.output
    assert "Traceback" not in st.output
    r = runner.invoke(app, ["run", "-e", str(eng)], env=env)
    assert r.exit_code == 2, r.output
    assert "expense-bot" in r.output and MISSING_MSG in r.output
    assert "Traceback" not in r.output
    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng)], env=env)
    assert dry.exit_code == 2 and "Traceback" not in dry.output


def test_run_continues_with_other_tools_when_one_is_missing(
        tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["add", "other", "--files", str(other),
                               "-e", str(eng)]).exit_code == 0
    (eng / "tools" / "expense-bot" / "tool.yaml").unlink()
    r = runner.invoke(app, ["run", "-e", str(eng)], env={"COLUMNS": "200"})
    assert r.exit_code == 2, r.output
    assert "Traceback" not in r.output
    assert (eng / "tools" / "other" / "inventory" / "census.json").exists()
    assert "expense-bot" in r.output and MISSING_MSG in r.output
    assert "could not run" in r.output


def test_export_and_ask_report_missing_tool_yaml(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    (eng / "tools" / "expense-bot" / "tool.yaml").unlink()
    for args in (["export"], ["ask", "what?"]):
        r = runner.invoke(app, [*args, "-e", str(eng)], env={"COLUMNS": "200"})
        assert r.exit_code == 2, (args, r.output)
        assert "expense-bot" in r.output and MISSING_MSG in r.output
        assert "Traceback" not in r.output


def test_missing_other_tool_does_not_block_a_named_tool(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["add", "other", "--files", str(other),
                               "-e", str(eng)]).exit_code == 0
    (eng / "tools" / "expense-bot" / "tool.yaml").unlink()
    env = {"COLUMNS": "200"}
    r = runner.invoke(app, ["run", "other", "-e", str(eng)], env=env)
    assert r.exit_code == 0, r.output
    assert MISSING_MSG not in r.output
    # ask scoped to a present tool is not refused because of the missing one
    a = runner.invoke(app, ["ask", "what?", "--tool", "other", "-e", str(eng)], env=env)
    assert MISSING_MSG not in a.output, a.output
    assert "Traceback" not in a.output
    # ask scoped to the missing tool is refused with the one-line message
    m = runner.invoke(app, ["ask", "what?", "--tool", "expense-bot", "-e", str(eng)], env=env)
    assert m.exit_code == 2 and MISSING_MSG in m.output, m.output


def _docs(tool_dir: Path) -> dict[str, bytes]:
    return {p.relative_to(tool_dir).as_posix(): p.read_bytes()
            for p in sorted((tool_dir / "docs").rglob("*")) if p.is_file()}


def test_linked_tool_whose_directory_is_gone_fails_and_keeps_its_documents(
        tmp_path: Path, synthetic_repo: Path, fake_llm):
    """UNVAR-31: a linked folder that was deleted was analysed as an empty tool, and render
    overwrote its findings with "0 / 0" files. Inventory now fails, naming the path."""
    import shutil

    from tests.conftest import model_config
    from unvarnish.config import EngagementConfig
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "acme", client="Acme")
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(),
                                                  **model_config(fake_llm)})
    eng.save_config()
    fake_llm.autofill = True
    pile = tmp_path / "pile"
    shutil.copytree(synthetic_repo, pile, ignore=shutil.ignore_patterns(".git"))
    added = runner.invoke(app, ["add", "linked", "--files", str(pile), "--link",
                                "-e", str(eng.root)])
    assert added.exit_code == 0, added.output
    first = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert first.exit_code == 0, first.output
    tool_dir = eng.root / "tools" / "linked"
    before = _docs(tool_dir)
    assert "docs/findings.md" in before

    shutil.rmtree(pile)
    again = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert again.exit_code != 0, again.output
    flat = " ".join(again.output.split())
    assert "does not exist" in flat
    record = json.loads((tool_dir / "analysis" / "run-record.json").read_text(encoding="utf-8"))
    assert record["data"]["failures"] == [
        f"inventory: source directory {pile} does not exist (linked tool; re-add or restore it)"]
    results = record["data"]["results"]
    assert results[0]["status"] == "failed"
    assert all(r["message"] == "skipped: upstream phase 'inventory' failed" for r in results[1:])
    assert _docs(tool_dir) == before  # nothing under docs/ was rewritten

    st = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert st.exit_code == 0, st.output
    assert "does not exist (linked tool" in " ".join(st.output.split())


def test_copied_tool_whose_source_is_gone_fails_inventory(tmp_path: Path,
                                                          synthetic_repo: Path):
    """The same for a copied tool whose tools/<name>/source was removed by hand."""
    import shutil

    eng = _setup(tmp_path, synthetic_repo)
    assert runner.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    tool_dir = eng / "tools" / "expense-bot"
    before = _docs(tool_dir)
    shutil.rmtree(tool_dir / "source")
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code != 0, r.output
    assert "does not exist" in " ".join(r.output.split())
    assert _docs(tool_dir) == before


def test_single_phase_that_reads_the_source_fails_when_it_is_gone(
        tmp_path: Path, synthetic_repo: Path):
    """UNVAR-31: `run --phase scan --force` (or git, split, extract, verify) on a tool whose
    source is gone must not rewrite its artifacts from an empty tree; render, which reads only
    the saved analysis, still runs."""
    import shutil

    eng = _setup(tmp_path, synthetic_repo)
    assert runner.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    tool_dir = eng / "tools" / "expense-bot"
    findings = (tool_dir / "inventory" / "scanner-findings.json").read_bytes()
    shutil.rmtree(tool_dir / "source")
    r = runner.invoke(app, ["run", "--phase", "scan", "--force", "-e", str(eng)])
    assert r.exit_code != 0, r.output
    assert "does not exist" in " ".join(r.output.split())
    assert (tool_dir / "inventory" / "scanner-findings.json").read_bytes() == findings
    rendered = runner.invoke(app, ["run", "--phase", "render", "--force", "-e", str(eng)])
    assert rendered.exit_code == 0, rendered.output


def test_unreachable_model_server_is_not_reported_as_a_budget_stop(
        tmp_path: Path, synthetic_repo: Path, fake_llm):
    """UNVAR-78: a run whose model server was down showed "budget-stopped" and "never"."""
    from tests.conftest import model_config
    from unvarnish.config import EngagementConfig
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "acme", client="Acme")
    eng.config = EngagementConfig.model_validate(
        {**eng.config.model_dump(), **model_config(fake_llm, kind="openai_compatible")})
    eng.save_config()
    added = runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo),
                                "-e", str(eng.root)])
    assert added.exit_code == 0, added.output
    url = fake_llm.url
    fake_llm.stop()  # nothing listens on the port any more

    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    flat = " ".join(r.output.split())
    assert url in flat and "unvarnish config check" in flat

    st = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert st.exit_code == 0, st.output
    flat = " ".join(st.output.split())
    assert "unreachable" in flat and "budget-stopped" not in flat
    last = [line for line in st.output.splitlines() if "last run" in line]
    assert last and "never" not in last[0], st.output
