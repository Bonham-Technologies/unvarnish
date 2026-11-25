"""UNVAR-94: opt-in Message Batches mode for the verify phase and the render prose calls."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import FakeLLM, anthropic_message
from tests.stub_backend import BatchStubBackend, StubBackend
from tests.test_render_documents import _prose, _verdict
from tests.test_rollup_modules import MODULE
from tests.test_rollup_tool import DIRECTORY, TOOL
from tests.test_verify import _unit_reply
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.config import BackendCapabilities, BackendConfig, EngagementConfig, Prices
from unvarnish.model.anthropic_backend import AnthropicBackend
from unvarnish.model.base import BackendError, CompletionRequest, Message
from unvarnish.model.batch import BATCH_RATE, find_batcher
from unvarnish.model.budget import BudgetTracker, load_ledger, record_cost
from unvarnish.model.cache import CachingBackend
from unvarnish.model.registry import build_backend
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.render import RenderPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.phases.verify import VerifyPhase
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.cost import CostEntry, CostLedger, Usage
from unvarnish.schemas.verify import ModelFindings

runner = CliRunner()
ENV = {"COLUMNS": "250"}
REPLIES = {"UnitExtraction": _unit_reply, "ModuleRollup": MODULE, "ToolRollup": TOOL,
           "DirectoryRollup": DIRECTORY, "Verdict": _verdict, "prose": _prose}


def _upstream(eng, tool):
    """Every phase before verify, synchronously, with a plain stub."""
    stub = StubBackend(REPLIES)
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    for phase in (InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(),
                  ExtractPhase(backend=stub), RollupModulesPhase(backend=stub),
                  RollupToolPhase(backend=stub)):
        assert phase.run(ctx).status == PhaseStatus.ok, phase.name
    return ctx


def _cached(backend, tmp_path: Path, name: str) -> CachingBackend:
    return CachingBackend(backend, tmp_path / f"cache-{name}")


def _data(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["data"]


# --- acceptance 1: no synchronous call, identical artifacts -----------------------------
def test_batched_verify_and_prose_send_no_sync_call_and_match_a_sync_run(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)

    sync = StubBackend(REPLIES)
    for phase in (VerifyPhase(backend=_cached(sync, tmp_path, "sync")),
                  RenderPhase(backend=_cached(sync, tmp_path, "sync"))):
        assert phase.run(ctx).status == PhaseStatus.ok
    assert sync.count("Verdict") and sync.count("prose")
    expected = {p: _data(p) for p in (ctx.paths.model_findings, ctx.paths.failures)}
    docs = {p: p.read_text(encoding="utf-8") for p in ctx.paths.docs.glob("*.md")}

    batched = BatchStubBackend(REPLIES)
    for phase in (VerifyPhase(backend=_cached(batched, tmp_path, "batch")),
                  RenderPhase(backend=_cached(batched, tmp_path, "batch"))):
        assert phase.run(ctx).status == PhaseStatus.ok
    assert batched.requests == []  # not one synchronous model call
    assert batched.count_batched("Verdict") == sync.count("Verdict")
    assert batched.count_batched("prose") == sync.count("prose")
    assert len(batched.batches) == 2  # one batch per phase
    for path, data in expected.items():
        assert _data(path) == data, path.name
    for path, text in docs.items():
        assert path.read_text(encoding="utf-8") == text, path.name
    assert not list(ctx.paths.analysis.glob("batches/*.json"))  # the state is gone once used


def test_batch_usage_is_recorded_at_the_batch_rate(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    batched = BatchStubBackend(REPLIES)
    assert VerifyPhase(backend=_cached(batched, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    entries = [e for e in load_ledger(eng).entries if e.phase == "verify"]
    assert [e.batch for e in entries] == [True]
    n = batched.count_batched("Verdict")
    assert entries[0].usage == Usage(input_tokens=100 * n, output_tokens=20 * n)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.usage == entries[0].usage


def test_a_run_without_batch_sends_nothing_in_batches(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES)
    stub.batch = False  # the default: `backends.<name>.batch` unset
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert stub.batches == {} and stub.count("Verdict")


def test_extract_and_rollups_stay_synchronous(ingested, tmp_path):
    eng, tool = ingested
    stub = BatchStubBackend(REPLIES)
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    backend = _cached(stub, tmp_path, "b")
    for phase in (InventoryPhase(), SplitPhase(), ExtractPhase(backend=backend),
                  RollupModulesPhase(backend=backend), RollupToolPhase(backend=backend)):
        assert phase.run(ctx).status == PhaseStatus.ok
    assert stub.batches == {} and stub.count("UnitExtraction")


# --- acceptance 2: a stop after submission resumes the stored batch -------------------------
def test_a_stop_while_polling_resumes_the_stored_batch(ingested, tmp_path):
    eng, tool = ingested
    _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES, polls=3)
    backend = _cached(stub, tmp_path, "b")
    tracker = BudgetTracker(None)
    stub.on_sleep = tracker.interrupt  # Ctrl-C while the batch is in progress
    ctx = build_context(eng, tool, budget=tracker)
    from unvarnish.phases.base import PhaseRunner

    first = PhaseRunner([VerifyPhase(backend=backend)]).run(ctx)
    assert first[0].status == PhaseStatus.stopped and stub.requests == []
    stopped = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert stopped.stopped_for_budget
    state = ctx.paths.analysis / "batches" / "verify.json"
    assert state.exists()
    stored = _data(state)
    assert [b["batch_id"] for b in stored["batches"]] == ["msgbatch_stub1"]
    assert "api_key" not in state.read_text(encoding="utf-8")

    stub.on_sleep = None
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    second = PhaseRunner([VerifyPhase(backend=backend)]).run(ctx)
    assert second[0].status == PhaseStatus.ok
    assert list(stub.batches) == ["msgbatch_stub1"]  # no second batch
    assert set(stub.status_checks) == {"msgbatch_stub1"}
    assert stub.requests == [] and not state.exists()
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.confirmed + mf.rejected == stub.count_batched("Verdict")


def test_a_stop_while_render_polls_still_writes_the_documents(ingested, tmp_path):
    # render runs after a stop (runs_after_stop): as synchronously, its prose falls back
    eng, tool = ingested
    _upstream(eng, tool)
    tracker = BudgetTracker(None)
    ctx = build_context(eng, tool, budget=tracker)
    assert VerifyPhase(backend=StubBackend(REPLIES)).run(ctx).status == PhaseStatus.ok
    stub = BatchStubBackend(REPLIES, polls=3)
    stub.on_sleep = tracker.interrupt
    res = RenderPhase(backend=_cached(stub, tmp_path, "b")).run(ctx)
    assert res.status == PhaseStatus.stopped and stub.requests == []
    assert "No model-written text" in ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert ctx.paths.batch_state("render").exists()


def test_a_stored_batch_the_api_no_longer_has_is_sent_again(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES)
    state = ctx.paths.batch_state("verify")
    state.parent.mkdir(parents=True, exist_ok=True)
    from unvarnish.artifacts import write_artifact
    from unvarnish.model.batch import BatchState, SubmittedBatch

    write_artifact(state, BatchState(backend="stub", model="stub-model", batches=[
        SubmittedBatch(batch_id="msgbatch_gone", keys=["k"])]), produced_by="verify",
        inputs_hash="")
    real = stub.batch_ended

    def ended(batch_id):
        if batch_id == "msgbatch_gone":
            raise BackendError("stub: batch msgbatch_gone: HTTP 404: not found")
        return real(batch_id)

    stub.batch_ended = ended
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert list(stub.batches) == ["msgbatch_stub1"] and stub.requests == []
    assert not state.exists()


def test_polling_waits_with_the_injected_sleeper(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES, polls=2)
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert len(stub.status_checks) == 3 and stub.sleeps and sum(stub.sleeps) >= 2 * 30


# --- acceptance 3: errored and expired requests are never dropped ---------------------------
def test_errored_and_expired_requests_are_retried_synchronously(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    seen: list[str] = []

    def fail(req):
        if req.schema_name != "Verdict" or len(seen) >= 2:
            return None
        seen.append(req.messages[0].content)
        return "expired" if len(seen) == 1 else "errored: overloaded_error"

    stub = BatchStubBackend(REPLIES, fail=fail)
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert stub.count("Verdict") == 2  # exactly the two that failed in the batch
    assert {r.messages[0].content for r in stub.requests} == set(seen)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.unverified == 1  # only the tool-level finding, as in a synchronous run
    assert mf.confirmed + mf.rejected == stub.count_batched("Verdict")


def test_a_request_that_fails_in_the_batch_and_again_is_in_failures_json(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend({**REPLIES, "Verdict": BackendError("400 bad request")})
    res = VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx)
    assert res.status == PhaseStatus.ok and res.failures
    items = [f for f in read_artifact(ctx.paths.failures, Failures).data.items
             if f.phase == "verify"]
    assert len(items) == stub.count_batched("Verdict") == stub.count("Verdict")


def test_a_failed_prose_batch_request_is_retried_synchronously(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    assert VerifyPhase(backend=StubBackend(REPLIES)).run(ctx).status == PhaseStatus.ok
    stub = BatchStubBackend(REPLIES, fail=lambda r: "expired")
    assert RenderPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert stub.count("prose") == stub.count_batched("prose") > 0
    assert "PROSE" in ctx.paths.findings_doc.read_text(encoding="utf-8")


def test_a_budget_already_spent_submits_no_batch(ingested, tmp_path):
    eng, tool = ingested
    _upstream(eng, tool)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    stub = BatchStubBackend(REPLIES)
    ctx = build_context(eng, tool, budget=tracker)
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.stopped
    assert stub.batches == {} and stub.requests == []


# --- the Anthropic backend's batch calls, against a fake client -----------------------------
class FakeBatches:
    def __init__(self, reply=lambda params: '{"ok": true}', statuses=("in_progress",),
                 outcome=lambda custom_id, params: "succeeded") -> None:
        self.reply, self.outcome = reply, outcome
        self.statuses = list(statuses)
        self.created: dict[str, list[dict]] = {}
        self.retrieved: list[str] = []

    def create(self, *, requests):
        batch_id = f"msgbatch_{len(self.created) + 1:02d}"
        self.created[batch_id] = list(requests)
        return SimpleNamespace(id=batch_id, processing_status="in_progress")

    def retrieve(self, batch_id):
        self.retrieved.append(batch_id)
        status = self.statuses.pop(0) if self.statuses else "ended"
        return SimpleNamespace(id=batch_id, processing_status=status,
                               request_counts=SimpleNamespace(processing=1, succeeded=0,
                                                              errored=0, canceled=0, expired=0))

    def results(self, batch_id):
        from anthropic.types.messages import MessageBatchIndividualResponse

        for item in self.created[batch_id]:
            params, custom_id = item["params"], item["custom_id"]
            kind = self.outcome(custom_id, params)
            if kind == "succeeded":
                result = {"type": "succeeded", "message": anthropic_message(
                    self.reply(params), model=params["model"], input_tokens=40,
                    output_tokens=9)}
            elif kind == "errored":
                result = {"type": "errored", "error": {"type": "error", "error": {
                    "type": "overloaded_error", "message": "Overloaded"}}}
            else:
                result = {"type": kind}
            yield MessageBatchIndividualResponse.model_validate(
                {"custom_id": custom_id, "result": result})


class FakeClient:
    def __init__(self, batches: FakeBatches) -> None:
        self.sync_calls: list[dict] = []
        self.base_url = "https://api.example.test"
        self.messages = SimpleNamespace(create=self._create, batches=batches)

    def _create(self, **kwargs):
        self.sync_calls.append(kwargs)
        raise AssertionError("a synchronous call in batch mode")


def _anthropic(batches: FakeBatches, sleeps: list[float] | None = None) -> AnthropicBackend:
    return AnthropicBackend(name="a", model="claude-opus-5-5", api_key="k", base_url=None,
                            capabilities=BackendCapabilities(), batch=True,
                            sleep=(sleeps.append if sleeps is not None else lambda s: None),
                            client=FakeClient(batches))


def _req(**kw) -> CompletionRequest:
    return CompletionRequest(system="S", messages=[Message(role="user", content="hi")],
                             output_schema={"type": "object"}, effort="low", **kw)


def test_anthropic_batch_params_match_the_synchronous_request(fake_llm: FakeLLM):
    fake_llm.script("x")
    sync = AnthropicBackend(name="a", model="claude-opus-5-5", api_key="k",
                            base_url=fake_llm.url, capabilities=BackendCapabilities())
    sync.complete(_req())
    sent = {k: v for k, v in fake_llm.requests[0].items() if k != "path"}
    batches = FakeBatches()
    batch_id = _anthropic(batches).submit_batch([("k1", _req())])
    assert batch_id == "msgbatch_01"
    (item,) = batches.created[batch_id]
    assert item["custom_id"] == "k1" and item["params"] == sent
    assert "timeout" not in item["params"]


def test_anthropic_batch_status_and_results():
    batches = FakeBatches(reply=lambda p: "hello", statuses=("in_progress", "ended"),
                          outcome=lambda cid, p: {"a": "succeeded", "b": "errored"}.get(cid,
                                                                                         "expired"))
    b = _anthropic(batches)
    batch_id = b.submit_batch([("a", _req()), ("b", _req()), ("c", _req())])
    assert b.batch_ended(batch_id) is False and b.batch_ended(batch_id) is True
    got = {r.custom_id: r for r in b.batch_results(batch_id)}
    assert got["a"].response.text == "hello" and got["a"].response.usage.input_tokens == 40
    assert got["a"].error is None
    assert got["b"].response is None and "overloaded_error" in got["b"].error
    assert got["c"].response is None and got["c"].error == "expired"


def test_verify_through_the_anthropic_backend_uses_only_the_batch_api(ingested, tmp_path):
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    sleeps: list[float] = []
    batches = FakeBatches(reply=lambda p: '{"verdict": "confirmed", "reason": "seen"}')
    backend = _anthropic(batches, sleeps)
    assert VerifyPhase(backend=_cached(backend, tmp_path, "a")).run(ctx).status == PhaseStatus.ok
    assert backend._client.sync_calls == []
    assert len(batches.created) == 1 and batches.retrieved == ["msgbatch_01"] * 2
    assert sleeps  # polled through the injected sleeper, never time.sleep
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.confirmed == len(batches.created["msgbatch_01"]) > 0
    for item in batches.created["msgbatch_01"]:
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["custom_id"])


# --- configuration ---------------------------------------------------------------------------
def test_batch_on_an_openai_compatible_backend_is_a_config_error():
    with pytest.raises(ValidationError, match="batch.*anthropic"):
        BackendConfig.model_validate({"type": "openai_compatible", "base_url": "http://x",
                                      "batch": True})
    assert BackendConfig.model_validate({"type": "anthropic", "batch": True}).batch
    assert not BackendConfig.model_validate({"type": "anthropic"}).batch


def test_batch_on_an_openai_compatible_backend_is_one_error_line(tmp_path, monkeypatch):
    monkeypatch.setenv("UNVARNISH_CONFIG_DIR", str(tmp_path / "user-config"))
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "e", client="Acme")
    text = eng.config_file.read_text(encoding="utf-8")
    eng.config_file.write_text(text + "backends:\n  local:\n    type: openai_compatible\n"
                               "    base_url: http://127.0.0.1:1/v1\n    batch: true\n",
                               encoding="utf-8")
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    errors = [line for line in r.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1 and "backends.local" in errors[0] and "anthropic" in errors[0]
    assert "Traceback" not in r.output


def test_build_backend_passes_batch_through(monkeypatch):
    monkeypatch.setenv("UNVARNISH_TEST_KEY", "k")
    cfg = BackendConfig(type="anthropic", api_key_env="UNVARNISH_TEST_KEY", batch=True)
    b = build_backend("a", cfg, "claude-opus-5-5")
    assert b.batch is True and find_batcher(CachingBackend(b, Path("/nonexistent"))) is b
    off = build_backend("a", BackendConfig(type="anthropic", api_key_env="UNVARNISH_TEST_KEY"),
                        "claude-opus-5-5")
    assert off.batch is False and find_batcher(off) is None


def _batch_engagement(tmp_path, fake: FakeLLM, prices: dict | None = None):
    from unvarnish.engagement import Engagement

    eng = Engagement.create(tmp_path / "e", client="Acme")
    data = {**eng.config.model_dump(), **model_config(fake)}
    data["backends"]["fake"]["batch"] = True
    if prices:
        data["budget"] = {"prices": prices}
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    return eng


def test_config_check_prints_a_retention_notice_when_batch_is_on(tmp_path, fake_llm):
    eng = _batch_engagement(tmp_path, fake_llm)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)], env=ENV)
    assert r.exit_code == 0, r.output
    notices = [line for line in r.output.splitlines() if "29 days" in line]
    assert len(notices) == 1, r.output
    assert "fake" in notices[0] and "zero data retention" in notices[0]
    eng.config.backends["fake"].batch = False
    eng.save_config()
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)], env=ENV)
    assert "29 days" not in r.output


# --- acceptance 4: cost and --dry-run at the batch rate -----------------------------------
PRICES = {"input_per_mtok": 10.0, "output_per_mtok": 50.0}


def test_the_ledger_prices_batch_entries_at_half():
    usage = Usage(input_tokens=1_000_000, output_tokens=100_000)
    now = datetime.now(UTC)
    ledger = CostLedger(entries=[
        CostEntry(tool="t", phase="verify", backend="a", model="m", usage=usage, at=now),
        CostEntry(tool="t", phase="verify", backend="a", model="m", usage=usage, at=now,
                  batch=True)])
    assert BATCH_RATE == 0.5
    assert ledger.estimate_usd(Prices(**PRICES)) == pytest.approx(15.0 + 7.5)


def test_cost_command_shows_the_batch_rate(tmp_path, fake_llm):
    eng = _batch_engagement(tmp_path, fake_llm, prices=PRICES)
    record_cost(eng, CostEntry(tool="t", phase="verify", backend="fake", model="fake-model",
                               usage=Usage(input_tokens=1_000_000), at=datetime.now(UTC),
                               batch=True))
    r = runner.invoke(app, ["cost", "-e", str(eng.root)], env=ENV)
    assert r.exit_code == 0, r.output
    assert "verify (batch)" in r.output
    assert "USD 5.00" in r.output and "batch rate" in r.output


def test_dry_run_estimates_batched_phases_at_the_batch_rate(ingested, fake_llm):
    eng, tool = ingested
    data = {**eng.config.model_dump(), **model_config(fake_llm)}
    data["budget"] = {"prices": PRICES}
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    sync = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    data["backends"]["fake"]["batch"] = True
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    batched = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert sync.exit_code == batched.exit_code == 0, batched.output

    def usd(output: str, phase: str) -> tuple[float, str]:
        m = re.search(rf"│\s*{phase}\s*│\s*estimate\s*│\s*≈ [\d,]+ tokens \(≈ USD ([\d,.]+)"
                      rf"([^)]*)\)", output)
        assert m, output
        return float(m.group(1).replace(",", "")), m.group(2)

    for phase in ("verify", "render"):
        full, note = usd(sync.output, phase)
        half, batch_note = usd(batched.output, phase)
        assert half == pytest.approx(full * BATCH_RATE, abs=0.011), phase
        assert "batch" not in note and "batch rate" in batch_note


# --- review fixes ------------------------------------------------------------------------------
def test_a_batch_collected_before_a_stop_is_not_collected_or_billed_again(ingested, tmp_path,
                                                                          monkeypatch):
    # A phase split over several batches: the first is collected, Ctrl-C lands while the
    # second is in progress. The rerun must collect only the second, so the ledger counts
    # every request once.
    import unvarnish.model.batch as batch_mod

    monkeypatch.setattr(batch_mod, "MAX_BATCH_REQUESTS", 1)
    eng, tool = ingested
    _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES, polls=0)
    real_submit = stub.submit_batch

    def submit(items):
        batch_id = real_submit(items)
        if batch_id != "msgbatch_stub1":
            stub._pending[batch_id] = 1  # still in progress at the first status check
        return batch_id

    stub.submit_batch = submit
    backend = _cached(stub, tmp_path, "b")
    tracker = BudgetTracker(None)
    stub.on_sleep = tracker.interrupt
    ctx = build_context(eng, tool, budget=tracker)
    assert VerifyPhase(backend=backend).run(ctx).status == PhaseStatus.stopped
    n = stub.count_batched("Verdict")
    assert n >= 2 and len(stub.batches) == n
    stored = [b["batch_id"] for b in _data(ctx.paths.batch_state("verify"))["batches"]]
    assert "msgbatch_stub1" not in stored  # already in the cache and in the ledger

    stub.on_sleep = None
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    assert VerifyPhase(backend=backend).run(ctx).status == PhaseStatus.ok
    assert len(stub.batches) == n and stub.requests == []  # no new batch, no call
    billed = Usage()
    for e in load_ledger(eng).entries:
        if e.phase == "verify":
            assert e.batch
            billed = billed + e.usage
    assert billed == Usage(input_tokens=100 * n, output_tokens=20 * n)



def test_a_rate_limited_status_check_keeps_waiting_for_the_batch(ingested, tmp_path):
    # A 429 on a status check is the poll's problem, not the batch's: abandoning the batch
    # would send its requests again and pay for them twice.
    import anthropic
    import httpx2

    eng, tool = ingested
    ctx = _upstream(eng, tool)
    batches = FakeBatches(reply=lambda p: '{"verdict": "confirmed", "reason": "seen"}')
    real_retrieve = batches.retrieve
    limited: list[str] = []

    def retrieve(batch_id):
        if not limited:
            limited.append(batch_id)
            resp = httpx2.Response(429, request=httpx2.Request(
                "GET", f"https://api.example.test/v1/messages/batches/{batch_id}"))
            raise anthropic.RateLimitError("rate limited", response=resp, body=None)
        return real_retrieve(batch_id)

    batches.retrieve = retrieve
    backend = _anthropic(batches)
    assert VerifyPhase(backend=_cached(backend, tmp_path, "a")).run(ctx).status == PhaseStatus.ok
    assert limited and len(batches.created) == 1 and backend._client.sync_calls == []
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.confirmed == len(batches.created["msgbatch_01"])


# --- QC fixes ----------------------------------------------------------------------------------

def test_rate_limited_results_are_fetched_again_not_paid_twice(ingested, tmp_path):
    from unvarnish.model.batch import BatchRetryLater

    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES)
    real = stub.batch_results
    tries: list[str] = []

    def results(batch_id):
        tries.append(batch_id)
        it = real(batch_id)
        yield next(it)  # one reply arrives, then the download is rate limited
        if len(tries) == 1:
            raise BatchRetryLater("stub: batch results: HTTP 429: rate limited")
        yield from it

    stub.batch_results = results
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    n = stub.count_batched("Verdict")
    assert len(tries) == 2 and len(stub.batches) == 1 and stub.requests == []
    billed = [e.usage for e in load_ledger(eng).entries if e.phase == "verify"]
    assert billed == [Usage(input_tokens=100 * n, output_tokens=20 * n)]  # each reply once
    assert not ctx.paths.batch_state("verify").exists()



def test_unreadable_results_of_a_fresh_batch_fall_back_to_calls(ingested, tmp_path):
    # As for a stored batch: a non-fatal error reading the results is that batch's problem;
    # the phase still ends ok, its requests going as ordinary calls.
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES)

    def results(batch_id):
        raise BackendError("stub: batch results: HTTP 404: not found")
        yield  # pragma: no cover - a generator

    stub.batch_results = results
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert stub.count("Verdict") == stub.count_batched("Verdict") > 0
    assert not ctx.paths.batch_state("verify").exists()



def test_anthropic_rate_limited_results_ask_to_retry_later():
    import anthropic
    import httpx2

    from unvarnish.model.batch import BatchRetryLater

    batches = FakeBatches()
    b = _anthropic(batches)
    batch_id = b.submit_batch([("a", _req())])

    def results(bid):
        resp = httpx2.Response(429, request=httpx2.Request(
            "GET", f"https://api.example.test/v1/messages/batches/{bid}/results"))
        raise anthropic.RateLimitError("rate limited", response=resp, body=None)

    batches.results = results
    with pytest.raises(BatchRetryLater):
        list(b.batch_results(batch_id))



def test_usage_of_a_collected_batch_reaches_the_ledger_when_a_later_one_fails(
        ingested, tmp_path, monkeypatch):
    import unvarnish.model.batch as batch_mod
    from unvarnish.model.base import BackendUnavailable

    monkeypatch.setattr(batch_mod, "MAX_BATCH_REQUESTS", 1)
    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES, polls=0)
    real = stub.batch_ended

    def ended(batch_id):
        if batch_id == "msgbatch_stub2":
            raise BackendUnavailable("stub: batch msgbatch_stub2: connection failed")
        return real(batch_id)

    stub.batch_ended = ended
    tracker = BudgetTracker(None)
    ctx = build_context(eng, tool, budget=tracker)
    backend = _cached(stub, tmp_path, "b")
    with pytest.raises(BackendUnavailable):
        VerifyPhase(backend=backend).run(ctx)
    first = [e.usage for e in load_ledger(eng).entries if e.phase == "verify"]
    assert first == [Usage(input_tokens=100, output_tokens=20)]  # batch 1, collected
    assert tracker.usage == Usage(input_tokens=100, output_tokens=20)

    stub.batch_ended = real
    n = stub.count_batched("Verdict")
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    assert VerifyPhase(backend=backend).run(ctx).status == PhaseStatus.ok
    assert len(stub.batches) == n and stub.requests == []
    billed = Usage()
    for e in load_ledger(eng).entries:
        if e.phase == "verify":
            billed = billed + e.usage
    assert billed == Usage(input_tokens=100 * n, output_tokens=20 * n)


def test_render_counts_its_batch_in_the_budget_when_a_document_raises(ingested, tmp_path):
    from unvarnish.model.base import BackendUnavailable

    eng, tool = ingested
    ctx = _upstream(eng, tool)
    assert VerifyPhase(backend=StubBackend(REPLIES)).run(ctx).status == PhaseStatus.ok
    seen: list[str] = []

    def fail(req):  # the first prose block is answered by the batch, the rest expire
        seen.append(req.messages[0].content)
        return None if len(seen) == 1 else "expired"

    def prose(req):  # replies inside the batch; an outage for the ordinary calls after it
        return BackendUnavailable("stub: outage") if stub.requests else _prose(req)

    stub = BatchStubBackend({**REPLIES, "prose": prose}, fail=fail)
    tracker = BudgetTracker(None)
    ctx = build_context(eng, tool, budget=tracker)
    with pytest.raises(BackendUnavailable):
        RenderPhase(backend=_cached(stub, tmp_path, "b")).run(ctx)
    assert tracker.usage == Usage(input_tokens=100, output_tokens=20)  # the batch's reply



def test_a_result_for_a_request_not_in_the_batch_is_not_cached(ingested, tmp_path):
    from unvarnish.model.base import CompletionResponse
    from unvarnish.model.batch import BatchResult

    eng, tool = ingested
    ctx = _upstream(eng, tool)
    stub = BatchStubBackend(REPLIES)
    real = stub.batch_results
    planted = CompletionResponse(text='{"verdict": "rejected"}', model="x")

    def results(batch_id):
        yield BatchResult(custom_id="../../escape", response=planted)
        yield BatchResult(custom_id="f" * 64, response=planted)
        yield from real(batch_id)

    stub.batch_results = results
    cache_dir = tmp_path / "cache-b"
    assert VerifyPhase(backend=_cached(stub, tmp_path, "b")).run(ctx).status == PhaseStatus.ok
    assert not (cache_dir / ("f" * 64 + ".json")).exists()
    assert not (tmp_path / "escape.json").exists()
    assert {p.stem for p in cache_dir.glob("*.json")} == {
        k for items in stub.batches.values() for k, _ in items}
