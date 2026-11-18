import json

from tests.stub_backend import StubBackend
from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase, to_module_findings
from unvarnish.phases.split import SplitPhase
from unvarnish.schemas.analysis import CandidateFinding, ExtractState, FailureRecord, Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.rollup import Module, ModulesIndex, module_file_id

UNIT = json.dumps({
    "purpose": "Does a thing.", "interface": ["main"], "external_calls": [
        {"system": "db.internal", "kind": "db", "detail": "reads"}],
    "data_read": ["expenses"], "data_written": [], "auth_behaviour": None,
    "error_handling": None, "risks": [], "candidate_findings": [], "confidence": 0.8,
})
MODULE = json.dumps({
    "summary": "A module.", "responsibilities": ["one", "two"], "interface": ["main"],
    "dependencies_in": [], "dependencies_out": ["os"],
    "candidate_findings": [
        {"category": "maintainability", "severity": "medium", "title": "Mixed responsibilities",
         "summary": "s", "impact": "i", "remediation": "r", "line_start": 1, "line_end": 1,
         "excerpt": "x", "confidence": 0.9},
        {"category": "security", "severity": "high", "title": "Out of file",
         "summary": "s", "impact": "i", "remediation": "r", "line_start": 999999,
         "line_end": 999999, "excerpt": "y", "confidence": 0.9},
    ],
    "confidence": 0.7,
})


def _stub(module_reply=MODULE) -> StubBackend:
    return StubBackend({"UnitExtraction": UNIT, "ModuleRollup": module_reply})


def _extracted(engagement, tool, stub, budget=None):
    ctx = build_context(engagement, tool, budget=budget)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    assert ExtractPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    return ctx


def test_to_module_findings_drops_out_of_range():
    cands = [CandidateFinding(category=Category.security, severity=Severity.high, title="in",
                              summary="s", impact="i", remediation="r", line_start=3,
                              line_end=4, confidence=0.5),
             CandidateFinding(category=Category.security, severity=Severity.high, title="out",
                              summary="s", impact="i", remediation="r", line_start=0,
                              line_end=4, confidence=0.5),
             CandidateFinding(category=Category.security, severity=Severity.high, title="past",
                              summary="s", impact="i", remediation="r", line_start=9,
                              line_end=11, confidence=0.5)]
    findings, dropped = to_module_findings(cands, "a.py", 10, "t", "m")
    assert [f.title for f in findings] == ["in"] and dropped == 2
    assert findings[0].evidence[0].path == "a.py" and findings[0].model == "m"


def test_rollup_writes_module_artifacts_and_index(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert idx.failed == [] and idx.skipped == []
    paths = [d.path for d in idx.modules]
    assert "app.py" in paths and paths == sorted(paths)
    app = next(d for d in idx.modules if d.path == "app.py")
    assert app.external_systems == ["db.internal"] and app.data_read == ["expenses"]
    assert app.findings == 1 and app.units >= 2
    module = read_artifact(ctx.paths.module_dir / f"{module_file_id('app.py')}.json", Module)
    assert module.data.dropped_findings == 1
    assert module.data.findings[0].title == "Mixed responsibilities"
    assert is_fresh(RollupModulesPhase(backend=stub), ctx)
    # one-unit modules are derived from their unit without a model call
    assert stub.count("ModuleRollup") == len([d for d in idx.modules if d.units > 1])


def test_rollup_is_resumable(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    RollupModulesPhase(backend=stub).run(ctx)
    before = stub.count("ModuleRollup")
    RollupModulesPhase(backend=stub).run(ctx)
    assert stub.count("ModuleRollup") == before


def test_rollup_skips_modules_without_units(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    for p in ctx.paths.unit_dir.glob("*.json"):
        art = json.loads(p.read_text())
        if art["data"]["unit"]["path"] == "README.md":
            p.unlink()
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert "README.md" in idx.skipped
    assert "README.md" not in [d.path for d in idx.modules]


def test_rollup_records_failures_and_continues(ingested):
    eng, tool = ingested
    stub = _stub(module_reply="not json")
    ctx = _extracted(eng, tool, stub)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok and res.failures
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert all(d.units == 1 for d in idx.modules) and "app.py" in idx.failed
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert {f.phase for f in items} == {"rollup_modules"}
    assert all(f.attempts == 3 for f in items)


def test_rollup_failure_stays_stale_and_a_plain_rerun_retries_only_it(ingested):
    """UNVAR-29: a failed module keeps the phase stale; the next run retries just it."""
    eng, tool = ingested
    broken = {"on": True}

    def module_reply(req):  # app.py's attempts and its repair call all fail while broken
        first = req.messages[0].content
        failing = "File: app.py" in first or "Malformed output:\nnot json" in first
        return "not json" if broken["on"] and failing else MODULE

    stub = _stub(module_reply=module_reply)
    ctx = _extracted(eng, tool, stub)
    phase = RollupModulesPhase(backend=stub)
    res = PhaseRunner([phase]).run(ctx)[0]
    assert res.status == PhaseStatus.ok and "1 failed; rerun to retry" in res.message
    assert not is_fresh(phase, ctx)
    broken["on"] = False
    before = stub.count("ModuleRollup")
    res = PhaseRunner([phase]).run(ctx)[0]
    assert res.status == PhaseStatus.ok and res.message.split(", ")[1] == "0 failed"
    assert stub.count("ModuleRollup") == before + 1  # app.py only; the rest are kept
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert idx.failed == [] and "app.py" in [d.path for d in idx.modules]
    assert not read_artifact(ctx.paths.failures, Failures).data.items
    assert is_fresh(phase, ctx)


def test_rollup_stops_at_budget_and_stays_stale(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ctx = build_context(eng, tool, budget=tracker)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.stopped
    assert stub.count("ModuleRollup") == 0
    assert read_artifact(ctx.paths.modules_index, ModulesIndex).data.stopped_for_budget
    assert not is_fresh(RollupModulesPhase(backend=stub), ctx)


def test_rollup_skipped_without_model(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    res = RollupModulesPhase().run(ctx)
    assert res.status == PhaseStatus.skipped and "no model configured" in res.message


def test_failures_recorded_under_a_full_hash_still_keep_the_phase_stale(ingested):
    """UNVAR-29: staleness follows failures.json, so an engagement whose failures were
    recorded with a full inputs hash (before the fix) is retried by a plain rerun."""
    eng, tool = ingested
    broken = {"on": True}

    def module_reply(req):
        first = req.messages[0].content
        failing = "File: app.py" in first or "Malformed output:\nnot json" in first
        return "not json" if broken["on"] and failing else MODULE

    def unit_reply(req):
        first = req.messages[0].content
        failing = "File: app.py" in first or "Malformed output:\nnot json" in first
        return "not json" if broken["on"] and failing else UNIT

    stub = StubBackend({"UnitExtraction": unit_reply, "ModuleRollup": module_reply})
    ctx = build_context(eng, tool)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    extract, rollup = ExtractPhase(backend=stub), RollupModulesPhase(backend=stub)
    PhaseRunner([extract, rollup]).run(ctx)
    assert {f.phase for f in read_artifact(ctx.paths.failures, Failures).data.items} == {
        "extract"}
    for phase, path, model in ((extract, ctx.paths.extract_state, ExtractState),
                               (rollup, ctx.paths.modules_index, ModulesIndex)):
        art = read_artifact(path, model)  # what the pre-fix code wrote: the full hash
        write_artifact(path, art.data, produced_by=phase.name,
                       inputs_hash=phase.inputs_hash(ctx))
    failures = read_artifact(ctx.paths.failures, Failures).data
    failures.items.append(FailureRecord(phase="rollup_modules", unit_id="x", path="lib.py",
                                        error="timed out"))
    write_artifact(ctx.paths.failures, failures, produced_by="extract", inputs_hash="")
    assert not is_fresh(extract, ctx) and not is_fresh(rollup, ctx)
    broken["on"] = False
    PhaseRunner([extract, rollup]).run(ctx)
    assert not read_artifact(ctx.paths.failures, Failures).data.items
    assert read_artifact(ctx.paths.extract_state, ExtractState).data.units_failed == 0
    assert is_fresh(extract, ctx) and is_fresh(rollup, ctx)
