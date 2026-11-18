import json

from tests.stub_backend import StubBackend
from tests.test_render_documents import _phases, _stub
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.compare import (
    ENGAGEMENT_TOOL,
    ComparePhase,
    EngagementContext,
    load_tool_inputs,
    run_comparison,
)
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.comparison import Comparison
from unvarnish.schemas.cost import Usage

CONSOLIDATION = json.dumps({
    "union_capabilities": ["export reports", "bypass approval"],
    "abstract_requirements": [{"statement": "Finance can export a report",
                               "serves": ["alpha", "beta"]}],
    "recommended_approach": [{"capability": "export reports", "recommended_tool": "alpha",
                              "rationale": "single data store"}],
    "gaps": ["no audit trail"], "open_questions": ["who owns the data?"],
})


def _normalise(req) -> str:
    """Group capability lines with the same label across tools."""
    groups: dict[str, list[dict]] = {}
    for line in req.messages[0].content.splitlines():
        if " | " not in line:
            continue
        tool, cid, label, _desc, _flag = [p.strip() for p in line.split(" | ")]
        groups.setdefault(label, []).append({"tool": tool, "capability_id": cid})
    return json.dumps({"capabilities": [
        {"name": label.title(), "description": "d", "actor": "staff", "members": members}
        for label, members in groups.items()]})


def _compare_stub(**over) -> StubBackend:
    stub = _stub(CapabilityNormalisation=_normalise, Consolidation=CONSOLIDATION)
    stub.replies.update(over)
    return stub


def _two_tools(engagement: Engagement, synthetic_repo, stub, *, model_for=("alpha", "beta")):
    for name in ("alpha", "beta"):
        ingest_tool(engagement, name, str(synthetic_repo), "repo")
        ctx = build_context(engagement, name, budget=BudgetTracker(None))
        phases = _phases(stub) if name in model_for else [InventoryPhase(), GitPhase(),
                                                           ScanPhase()]
        results = PhaseRunner(phases).run(ctx)
        assert all(r.status == PhaseStatus.ok for r in results), name
    return EngagementContext(engagement=engagement, budget=BudgetTracker(None))


def test_load_tool_inputs_none_before_inventory(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    assert load_tool_inputs(engagement, "alpha") is None


def test_compare_two_tools(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok and not res.failures, res
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools == ["alpha", "beta"] == cmp.tools_with_model
    shared = next(r for r in cmp.capability_matrix if r.name == "Admin Can Export Report")
    assert shared.tools_covering == 2 and not shared.unmapped
    assert cmp.unmapped_capabilities == 0 and cmp.dropped_references == 0
    db = next(r for r in cmp.integration_map if r.name == "expenses db")
    assert db.tools == ["alpha", "beta"] and db.category == "data_store"
    assert [r.tool for r in cmp.risk_table] == ["alpha", "beta"]
    assert all(r.model_analysed for r in cmp.risk_table)
    assert cmp.consolidation and cmp.consolidation.gaps == ["no audit trail"]
    assert cmp.skipped_reason is None and cmp.backend == "stub"
    assert stub.count("CapabilityNormalisation") == 1 and stub.count("Consolidation") == 1
    assert is_fresh(ComparePhase(backend=stub), ectx)
    assert cmp.usage.total() > 0


def test_compare_single_tool_skips_matrix_and_proposal(engagement, synthetic_repo):
    stub = _compare_stub()
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    ectx = EngagementContext(engagement=engagement, budget=BudgetTracker(None))
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.capability_matrix == [] and cmp.consolidation is None
    assert cmp.skipped_reason and "one tool" in cmp.skipped_reason
    assert len(cmp.risk_table) == 1 and len(cmp.integration_map) >= 1
    assert stub.count("CapabilityNormalisation") == 0 and stub.count("Consolidation") == 0


def test_compare_includes_scanner_only_tool(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools == ["alpha", "beta"] and cmp.tools_with_model == ["alpha"]
    beta = next(r for r in cmp.risk_table if r.tool == "beta")
    assert not beta.model_analysed and beta.secrets_history == 2
    assert next(s for s in cmp.summaries if s.tool == "beta").purpose is None
    assert cmp.capability_matrix == [] and "one tool" in (cmp.skipped_reason or "")
    assert stub.count("CapabilityNormalisation") == 0


def test_compare_records_failed_consolidation(engagement, synthetic_repo):
    stub = _compare_stub(Consolidation="garbage")
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok and res.failures
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.consolidation is None and cmp.capability_matrix  # matrix survived
    assert "consolidation" in (cmp.skipped_reason or "").lower()
    items = read_artifact(engagement.comparison_failures, Failures).data.items
    assert items and items[0].phase == "compare" and items[0].unit_id == "consolidation"
    assert not is_fresh(  # a failed proposal is retried
        ComparePhase(backend=stub), ectx)


def test_compare_without_model_uses_per_tool_rows(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase().run(ectx)  # no injected backend, no models configured
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.capability_matrix and all(r.unmapped for r in cmp.capability_matrix)
    assert cmp.consolidation is None and "no model configured" in (cmp.skipped_reason or "")
    assert cmp.backend is None


def test_compare_budget_stop(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ectx = EngagementContext(engagement=engagement, budget=tracker)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.stopped
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.stopped_for_budget and cmp.consolidation is None
    assert not is_fresh(ComparePhase(backend=stub), ectx)


def test_compare_before_any_run_fails_clearly(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    res = ComparePhase().run(EngagementContext(engagement=engagement,
                                                budget=BudgetTracker(None)))
    assert res.status == PhaseStatus.failed and "unvarnish run" in (res.message or "")


def test_run_comparison_records_cost_under_engagement(engagement, synthetic_repo):
    from unvarnish.model.budget import load_ledger

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    results = run_comparison(engagement, backend=stub)
    assert results[0].phase == "compare" and results[0].status == PhaseStatus.ok
    entries = [e for e in load_ledger(engagement).entries if e.phase == "compare"]
    assert entries and entries[0].tool == ENGAGEMENT_TOOL
