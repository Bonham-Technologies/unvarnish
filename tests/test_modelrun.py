import threading

import pytest

from tests.stub_backend import StubBackend
from unvarnish.artifacts import read_artifact
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    Message,
    ModelRefusal,
)
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import build_context
from unvarnish.phases.modelrun import (
    ItemOutcome,
    call_structured,
    has_failures,
    merge_failures,
    run_parallel,
)
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.verify import Verdict


def _req() -> CompletionRequest:
    return CompletionRequest(system="s", messages=[Message(role="user", content="u")])


def test_call_structured_returns_result():
    stub = StubBackend({"Verdict": '{"verdict": "confirmed", "reason": "ok"}'})
    res, failure = call_structured(stub, _req(), Verdict, phase="verify", item_id="f1",
                                   path="a.py", stop=threading.Event())
    assert failure is None and res is not None and res.parsed.verdict == "confirmed"


def test_call_structured_maps_recoverable_errors():
    stop = threading.Event()
    bad = StubBackend({"Verdict": "not json at all"})
    res, failure = call_structured(bad, _req(), Verdict, phase="verify", item_id="f1",
                                   path="a.py", stop=stop)
    assert res is None and failure.phase == "verify" and failure.attempts == 3
    assert failure.unit_id == "f1" and failure.path == "a.py"

    refusing = StubBackend({"Verdict": ModelRefusal("harmful")})
    _, failure = call_structured(refusing, _req(), Verdict, phase="verify", item_id="f1",
                                 path=None, stop=stop)
    assert failure.error == "refused (harmful)"

    erroring = StubBackend({"Verdict": BackendError("400 bad request")})
    _, failure = call_structured(erroring, _req(), Verdict, phase="verify", item_id="f1",
                                 path=None, stop=stop)
    assert "400" in failure.error
    assert not stop.is_set()


def test_call_structured_outage_sets_stop_and_raises():
    stop = threading.Event()
    down = StubBackend({"Verdict": BackendUnavailable("503")})
    with pytest.raises(BackendUnavailable):
        call_structured(down, _req(), Verdict, phase="verify", item_id="x", path=None, stop=stop)
    assert stop.is_set()


def test_run_parallel_stops_at_budget():
    budget = BudgetTracker(150)

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        return ItemOutcome(result=item, usage=Usage(input_tokens=100))

    out = run_parallel([1, 2, 3, 4, 5], worker, workers=1, budget=budget)
    assert out.processed == 2 and out.results == [1, 2]
    assert out.stopped_for_budget and out.stopped and out.fatal is None
    assert out.usage.total() == 200


def test_run_parallel_collects_failures_and_results():
    budget = BudgetTracker(None)

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        if item % 2:
            return ItemOutcome(failures=[FailureRecord(phase="p", error=f"odd {item}")])
        return ItemOutcome(result=item, usage=Usage(output_tokens=1))

    out = run_parallel(list(range(6)), worker, workers=3, budget=budget)
    assert sorted(out.results) == [0, 2, 4]
    assert sorted(f.error for f in out.failures) == ["odd 1", "odd 3", "odd 5"]
    assert out.processed == 6 and not out.stopped


def test_run_parallel_outage_cancels_the_rest():
    seen: list[int] = []

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        seen.append(item)
        if item == 0:
            stop.set()
            raise BackendUnavailable("down")
        return ItemOutcome(result=item)

    out = run_parallel(list(range(20)), worker, workers=1, budget=BudgetTracker(None))
    assert isinstance(out.fatal, BackendUnavailable)
    assert seen == [0]  # the stop event short-circuited every later item


def test_merge_failures_replaces_only_its_phase(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    merge_failures(ctx, "extract", [FailureRecord(phase="extract", error="e1")])
    merge_failures(ctx, "verify", [FailureRecord(phase="verify", error="v1")])
    merge_failures(ctx, "extract", [FailureRecord(phase="extract", error="e2")])
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert sorted((f.phase, f.error) for f in items) == [("extract", "e2"), ("verify", "v1")]


def test_has_failures_reads_only_its_phase(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    assert not has_failures(ctx, "extract")  # no failures.json yet
    merge_failures(ctx, "verify", [FailureRecord(phase="verify", error="v1")])
    assert has_failures(ctx, "verify") and not has_failures(ctx, "extract")
    ctx.paths.failures.write_text("{not json", encoding="utf-8")
    assert not has_failures(ctx, "verify")  # unreadable: fall back to the inputs hash
