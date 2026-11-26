"""Tests pinning the fixes from the slice 4 whole-branch review."""
from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.artifacts import read_artifact
from unvarnish.model.base import BackendError
from unvarnish.phases.base import PhaseStatus
from unvarnish.phases.compare import run_comparison
from unvarnish.phases.ingest import ingest_tool
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.comparison import Comparison


def _failures(engagement) -> list:
    if not engagement.comparison_failures.exists():
        return []
    return read_artifact(engagement.comparison_failures, Failures).data.items


def test_render_comparison_failures_do_not_accumulate(engagement, synthetic_repo):
    bad = _compare_stub(prose=BackendError("400"))
    _two_tools(engagement, synthetic_repo, bad)
    run_comparison(engagement, backend=bad)
    items = [f for f in _failures(engagement) if f.phase != "render_brief"]  # UNVAR-99's
    assert len(items) == 2 and all(f.phase == "render_comparison" for f in items)
    run_comparison(engagement, backend=bad, force=True)
    assert len(_failures(engagement)) == 3  # replaced, not appended (2 + the brief's one)
    good = _compare_stub()
    run_comparison(engagement, backend=good, force=True)
    assert _failures(engagement) == []  # a later success clears the phase's records


def test_model_analysed_is_consistent_after_a_failed_rollup(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    paths = engagement.tool_paths("alpha")
    paths.tool_model.unlink()  # what RollupToolPhase does when the tool call fails
    paths.capabilities.unlink()
    assert paths.model_findings.exists()  # verify still ran
    results = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    alpha_risk = next(r for r in cmp.risk_table if r.tool == "alpha")
    alpha_summary = next(s for s in cmp.summaries if s.tool == "alpha")
    assert alpha_risk.model_analysed is False and alpha_summary.model_analysed is False
    assert cmp.tools_with_model == ["beta"]
    doc = engagement.comparison_doc.read_text()
    assert "| `alpha` | *not model-analysed* |" in doc
    assert "| Model analysis | **no** | yes |" in doc


def test_unrun_tool_is_named_not_omitted(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    ingest_tool(engagement, "gamma", str(synthetic_repo), "repo")  # registered, never run
    results = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    assert "gamma" in (results[0].message or "")
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools_not_run == ["gamma"] and cmp.tools == ["alpha", "beta"]
    assert "gamma" in (cmp.skipped_reason or "")
    doc = engagement.comparison_doc.read_text()
    assert "gamma" in doc and "not run" in doc


def test_unreadable_tool_model_is_a_recorded_failure(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    engagement.tool_paths("beta").tool_model.write_text("{not json")
    results = run_comparison(engagement, backend=stub)
    assert results[0].status == PhaseStatus.ok and results[0].failures
    items = _failures(engagement)
    assert any(f.phase == "compare" and f.path == "beta" and "tool.json" in f.error
               for f in items)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools_with_model == ["alpha"]
