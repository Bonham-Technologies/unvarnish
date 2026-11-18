from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners.hygiene import HygieneScanner
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.scan import ScannerFindings


def _scan(eng: Engagement, name: str) -> ScannerFindings:
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert ScanPhase(scanners=[HygieneScanner()]).run(ctx).status == PhaseStatus.ok
    return read_artifact(ctx.paths.scanner_findings, ScannerFindings).data


def test_synthetic_repo_hygiene(ingested):
    out = _scan(*ingested)
    titles = {f.title for f in out.findings}
    assert "No automated tests" in titles
    assert "No continuous integration configuration" in titles
    assert "No license file" in titles
    assert "No linter or formatter configuration" in titles
    assert "No README" not in titles
    tests_f = next(f for f in out.findings if f.title == "No automated tests")
    assert tests_f.severity == Severity.medium and tests_f.category == Category.process
    assert tests_f.evidence[0].path == "."


def test_well_kept_tool_has_no_hygiene_findings(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "tests").mkdir(parents=True)
    (pile / ".github" / "workflows").mkdir(parents=True)
    (pile / "src").mkdir()
    (pile / "README.md").write_text("# ok\n")
    (pile / "LICENSE").write_text("MIT\n")
    (pile / "ruff.toml").write_text("line-length = 100\n")
    (pile / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    (pile / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")
    (pile / "src" / "x.py").write_text("def x():\n    return 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    assert out.findings == []


def test_todo_density_and_empty_handlers(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text(
        "# TODO one\n# FIXME two\n# HACK three\n"
        "try:\n    x = 1\nexcept:\n    pass\n"
        "try:\n    y = 2\nexcept Exception:\n    pass\n"
    )
    (pile / "b.js").write_text("try { f(); } catch (e) {}\ntry { g(); } catch (err) { }\n")
    (pile / "c.go").write_text("x, err := f()\nif err != nil {\n}\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    by_title = {f.title: f for f in out.findings}
    todo = by_title["High density of TODO/FIXME/HACK markers"]
    assert todo.severity == Severity.low
    assert len(todo.evidence) == 3
    empty = by_title["Swallowed errors"]
    assert empty.severity == Severity.medium and empty.category == Category.reliability
    paths = sorted({e.path for e in empty.evidence})
    assert paths == ["a.py", "b.js", "c.go"]
    assert len(empty.evidence) == 5


# --- fixes from the first real-repo run (ESCAPESUITE) -----------------------
def test_linter_config_in_subpackage_counts(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "mono"
    (pile / "apps" / "web").mkdir(parents=True)
    (pile / "apps" / "web" / "eslint.config.js").write_text("export default [];\n")
    (pile / "apps" / "web" / "index.js").write_text("const a = 1;\n")
    ingest_tool(engagement, "mono", str(pile), "files")
    out = _scan(engagement, "mono")
    assert "No linter or formatter configuration" not in {f.title for f in out.findings}
