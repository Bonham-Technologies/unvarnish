import json

import pytest

from tests.conftest import model_config
from tests.fake_llm import FakeLLM
from unvarnish.artifacts import read_artifact
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, load_ledger
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.extract import ExtractPhase, to_findings
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.schemas.analysis import (
    CandidateFinding,
    ExtractState,
    Failures,
    Unit,
    UnitKind,
    UnitResult,
    UnitsIndex,
)
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Severity

GOOD = {
    "purpose": "Does a thing.", "interface": ["main"], "external_calls": [], "data_read": [],
    "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
    "candidate_findings": [], "confidence": 0.8,
}


def _good(body: dict) -> str:
    user = body["messages"][-1]["content"]
    out = dict(GOOD)
    if "lines " in user:
        rng = user.split("lines ", 1)[1].split("\n", 1)[0]
        lo, hi = (int(x) for x in rng.split("-"))
        out["candidate_findings"] = [
            {"category": "maintainability", "severity": "low", "title": "In range", "summary": "s",
             "impact": "i", "remediation": "r", "line_start": lo, "line_end": lo, "excerpt": "x",
             "confidence": 0.9},
            {"category": "security", "severity": "high", "title": "Out of range", "summary": "s",
             "impact": "i", "remediation": "r", "line_start": hi + 50, "line_end": hi + 51,
             "excerpt": "y", "confidence": 0.9},
        ]
    return json.dumps(out)


def _prepare(engagement: Engagement, tool: str, fake: FakeLLM, **cfg):
    conf = model_config(fake)
    conf.update(cfg)
    engagement.config = EngagementConfig.model_validate({**engagement.config.model_dump(), **conf})
    engagement.save_config()
    ctx = build_context(engagement, tool)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    return ctx


def test_budget_tracker():
    t = BudgetTracker(100)
    t.add(Usage(input_tokens=60))
    t.check()
    t.add(Usage(output_tokens=50))
    assert t.exceeded
    with pytest.raises(BudgetExceeded):
        t.check()
    BudgetTracker(None).add(Usage(input_tokens=10**9))  # unlimited never raises


def test_to_findings_drops_out_of_range():
    unit = Unit(id="u", tool="t", module_id="a.py", path="a.py", language="python",
                kind=UnitKind.function, line_start=10, line_end=20, byte_start=0, byte_end=1,
                token_estimate=1, split_method="structural")
    cands = [
        CandidateFinding(category=Category.security, severity=Severity.high, title="ok",
                         summary="s", impact="i", remediation="r", line_start=12, line_end=13,
                         excerpt="e", confidence=0.7),
        CandidateFinding(category=Category.security, severity=Severity.high, title="bad",
                         summary="s", impact="i", remediation="r", line_start=1, line_end=2,
                         excerpt=None, confidence=0.7),
    ]
    findings, dropped = to_findings(cands, unit, "t", "m")
    assert dropped == 1 and len(findings) == 1
    f = findings[0]
    assert f.source == "model" and f.model == "m" and f.confidence == 0.7
    assert f.evidence[0].path == "a.py" and f.evidence[0].line_start == 12
    assert f.verification is None


def test_extract_end_to_end(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 200))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.ok, r.message
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_total == len(idx.units) and state.units_done == len(idx.units)
    assert state.units_failed == 0 and state.usage.input_tokens > 0
    assert len(fake_llm.requests) == len(idx.units)
    results = [read_artifact(p, UnitResult).data for p in ctx.paths.unit_dir.glob("*.json")]
    assert len(results) == len(idx.units)
    assert all(res.findings and res.dropped_findings == 1 for res in results)
    assert all(f.title == "In range" for res in results for f in res.findings)
    app_reqs = [q for q in fake_llm.requests if "File: app.py" in q["messages"][-1]["content"]]
    assert "Neighbouring units" not in app_reqs[0]["messages"][-1]["content"]
    assert "Neighbouring units" in app_reqs[-1]["messages"][-1]["content"]
    assert fake_llm.requests[0]["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert load_ledger(eng).total().input_tokens == state.usage.input_tokens


def test_extract_resumes_without_recalling_done_units(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 200))
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    n = len(fake_llm.requests)
    assert PhaseRunner([ExtractPhase()]).run(ctx)[0].status == PhaseStatus.skipped  # fresh
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok  # forced: artifacts reused
    assert len(fake_llm.requests) == n


def test_extract_redoes_changed_unit(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 300))
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    n = len(fake_llm.requests)
    with (ctx.source_root / "README.md").open("a") as fh:
        fh.write("\nchanged\n")
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    assert len(fake_llm.requests) == n + 1
    assert "File: README.md" in fake_llm.requests[-1]["messages"][-1]["content"]


def test_extract_records_unit_failures_and_continues(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, pipeline={"concurrency": 1})
    calls = {"n": 0}

    def flaky(body):
        calls["n"] += 1
        return "not json at all" if calls["n"] <= 3 else _good(body)  # first unit fails 3x

    fake_llm.script(*([flaky] * 300))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.ok and r.failures
    failures = read_artifact(ctx.paths.failures, Failures).data
    assert len(failures.items) == 1 and failures.items[0].attempts == 3
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_failed == 1 and state.units_done == state.units_total - 1


def test_budget_cap_stops_cleanly(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, budget={"max_tokens": 150}, pipeline={"concurrency": 1})
    fake_llm.script(*([_good] * 300))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.stopped
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.stopped_for_budget is True and 1 <= state.units_done < state.units_total
    assert len(fake_llm.requests) == state.units_done
    results = PhaseRunner([ExtractPhase(), SplitPhase()]).run(ctx, force=True)
    assert results[1].status == PhaseStatus.skipped and "stopped" in (results[1].message or "")


def test_no_model_configured_skips(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.skipped and "no model configured" in (r.message or "")


# --- fixes from the whole-branch review -------------------------------------
def test_fatal_backend_error_stops_other_workers_and_writes_state(ingested, fake_llm: FakeLLM):
    from unvarnish.model.base import BackendUnavailable

    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, pipeline={"concurrency": 3})
    err = {"status": 401, "body": {"type": "error", "error": {
        "type": "authentication_error", "message": "bad key"}}}
    fake_llm.script(*([err] * 500))
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    assert len(idx.modules) > 3
    with pytest.raises(BackendUnavailable):
        ExtractPhase().run(ctx)
    assert len(fake_llm.requests) <= 3  # only the in-flight workers called before the stop
    assert ctx.paths.extract_state.exists() and ctx.paths.failures.exists()
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_done == 0


def test_budget_cap_with_threads_in_flight(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, budget={"max_tokens": 150}, pipeline={"concurrency": 4})
    fake_llm.script(*([_good] * 300))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.stopped
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    assert state.stopped_for_budget and state.units_done < len(idx.units)
    assert len(fake_llm.requests) <= state.units_done + 4


# --- UNVAR-32: an unexpected error in a worker ------------------------------
def test_worker_error_is_recorded_and_retried_by_a_plain_rerun(ingested, fake_llm: FakeLLM,
                                                               monkeypatch):
    """A non-backend exception in a worker (here, writing one unit's artifact) propagated out
    of the phase, yet the `finally` wrote extract-state with its full inputs hash: the phase
    looked fresh with units undone, and only --force would extract them. It is now a recorded
    failure for that module, like run_parallel's, so a plain rerun retries it."""
    import unvarnish.phases.extract as extract_module
    from unvarnish.phases.base import is_fresh

    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, pipeline={"concurrency": 1})
    fake_llm.script(*([_good] * 300))
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    module, unit_ids = next((m, ids) for m, ids in idx.modules.items() if len(ids) > 1)
    target = ctx.paths.unit_dir / f"{unit_ids[0]}.json"
    real_write = extract_module.write_artifact

    def failing_write(path, *args, **kwargs):
        if path == target:
            raise OSError(28, "No space left on device")
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(extract_module, "write_artifact", failing_write)
    r = PhaseRunner([ExtractPhase()]).run(ctx)[0]
    assert r.status == PhaseStatus.ok, r.message
    assert "1 failed; rerun to retry" in (r.message or "")
    items = [f for f in read_artifact(ctx.paths.failures, Failures).data.items
             if f.phase == "extract"]
    assert len(items) == 1 and items[0].unit_id == unit_ids[0] and items[0].path == module
    assert "No space left on device" in items[0].error
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_failed == 1 and state.units_done == state.units_total - len(unit_ids)
    assert not state.stopped_for_budget
    assert not is_fresh(ExtractPhase(), ctx)  # never fresh with units left undone

    monkeypatch.setattr(extract_module, "write_artifact", real_write)
    n = len(fake_llm.requests)
    again = PhaseRunner([ExtractPhase()]).run(ctx)[0]  # a plain rerun, no --force
    assert again.status == PhaseStatus.ok and "0 failed" in (again.message or ""), again.message
    # only the module left undone; the unit whose write failed comes from the response cache
    assert len(fake_llm.requests) - n == len(unit_ids) - 1
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_done == state.units_total and state.units_failed == 0
    assert is_fresh(ExtractPhase(), ctx)


def test_missing_module_file_is_a_recorded_failure(ingested, fake_llm: FakeLLM):
    """The ticket's repro: a module file deleted after split. The other modules are still
    extracted and the phase stays stale instead of claiming fresh at 0 units."""
    from unvarnish.phases.base import is_fresh

    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, pipeline={"concurrency": 2})
    fake_llm.script(*([_good] * 300))
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    module = "README.md"
    assert module in idx.modules
    (ctx.source_root / module).unlink()
    r = PhaseRunner([ExtractPhase()]).run(ctx)[0]
    assert r.status == PhaseStatus.ok, r.message
    items = [f for f in read_artifact(ctx.paths.failures, Failures).data.items
             if f.phase == "extract"]
    assert [(f.path, f.unit_id) for f in items] == [(module, None)]
    assert "FileNotFoundError" in items[0].error
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_done == state.units_total - len(idx.modules[module])
    assert not is_fresh(ExtractPhase(), ctx)


def test_extract_is_never_fresh_with_units_left_undone(ingested, fake_llm: FakeLLM,
                                                       monkeypatch):
    """Whatever ends the phase early (here, an interrupt raised in a worker, which the phase
    re-raises), extract-state records no inputs hash while units are left undone."""
    import unvarnish.phases.extract as extract_module
    from unvarnish.phases.base import is_fresh

    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, pipeline={"concurrency": 1})
    fake_llm.script(*([_good] * 300))
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    target = ctx.paths.unit_dir / f"{idx.units[0].id}.json"
    real_write = extract_module.write_artifact

    def interrupted_write(path, *args, **kwargs):
        if path == target:
            raise KeyboardInterrupt
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(extract_module, "write_artifact", interrupted_write)
    with pytest.raises(KeyboardInterrupt):
        ExtractPhase().run(ctx)
    state = read_artifact(ctx.paths.extract_state, ExtractState)
    assert state.data.units_done < state.data.units_total and not state.data.stopped_for_budget
    assert state.meta.inputs_hash == ""
    assert not is_fresh(ExtractPhase(), ctx)
