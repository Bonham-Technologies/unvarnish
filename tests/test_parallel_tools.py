"""Tools in one engagement run in parallel; `pipeline.concurrency` caps in-flight model calls
across all of them."""
import threading
import time

from typer.testing import CliRunner

from tests.test_cli_compare import _engagement
from unvarnish.cli import app
from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse, Message
from unvarnish.schemas.cost import Usage

runner = CliRunner()


class _Slow:
    name, model = "slow", "slow"
    capabilities = BackendCapabilities()

    def __init__(self):
        self.active = self.peak = 0
        self.lock = threading.Lock()

    def complete(self, req):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.05)
        with self.lock:
            self.active -= 1
        return CompletionResponse(text="ok", model="slow", usage=Usage())


def test_limited_backend_caps_in_flight_calls_across_users():
    from unvarnish.model.limit import LimitedBackend, limiter_for

    inner = _Slow()
    lim = limiter_for("engagement-a", 2)
    assert limiter_for("engagement-a", 2) is lim  # shared by every backend of one engagement
    backends = [LimitedBackend(inner, lim) for _ in range(3)]
    req = CompletionRequest(system="s", messages=[Message(role="user", content="u")])
    threads = [threading.Thread(target=b.complete, args=(req,)) for b in backends for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert inner.peak == 2


def test_tools_run_in_parallel_and_report_in_order(tmp_path, synthetic_repo, fake_llm,
                                                   monkeypatch):
    """The four-tool ESCAPESUITE run spent most of its 25 minutes on one tool at a time."""
    import unvarnish.cli as cli

    eng = _engagement(tmp_path, synthetic_repo, fake_llm, tools=("alpha", "beta", "gamma"))
    fake_llm.autofill = True
    seen: list[str] = []
    active = {"now": 0, "peak": 0}
    lock = threading.Lock()
    real = cli.PhaseRunner.run

    def tracked(self, ctx, **kw):
        with lock:
            active["now"] += 1
            active["peak"] = max(active["peak"], active["now"])
            seen.append(ctx.tool)
        time.sleep(0.2)
        try:
            return real(self, ctx, **kw)
        finally:
            with lock:
                active["now"] -= 1

    monkeypatch.setattr(cli.PhaseRunner, "run", tracked)
    out = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert active["peak"] >= 2 and sorted(seen) == ["alpha", "beta", "gamma"]
    rows = [ln.split("│")[1].strip() for ln in out.output.splitlines()
            if ln.startswith("│") and ln.split("│")[1].strip()]
    assert rows == sorted(rows, key=["alpha", "beta", "gamma"].index)


def test_parallel_tools_one_runs_sequentially(tmp_path, synthetic_repo, fake_llm, monkeypatch):
    import unvarnish.cli as cli
    from unvarnish.config import EngagementConfig

    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    data = eng.config.model_dump()
    data["pipeline"]["parallel_tools"] = 1
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    fake_llm.autofill = True
    active = {"now": 0, "peak": 0}
    real = cli.PhaseRunner.run

    def tracked(self, ctx, **kw):
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
        time.sleep(0.1)
        try:
            return real(self, ctx, **kw)
        finally:
            active["now"] -= 1

    monkeypatch.setattr(cli.PhaseRunner, "run", tracked)
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    assert active["peak"] == 1


def test_interrupt_stops_remaining_model_calls(tmp_path, synthetic_repo, fake_llm, monkeypatch):
    """UNVAR-16: Ctrl-C reached only the main thread, and 46 model calls followed it."""
    import _thread
    import json

    from tests.fake_llm import _request_schema, fill_schema
    from unvarnish.artifacts import read_artifact
    from unvarnish.config import EngagementConfig
    from unvarnish.schemas.analysis import ExtractState

    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    data = eng.config.model_dump()
    data["pipeline"]["concurrency"] = 2
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    lock = threading.Lock()
    calls = {"n": 0}

    def reply(body):
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 3:
            _thread.interrupt_main()
        time.sleep(0.3)  # longer than the CLI's 0.1 s poll, so the stop lands mid-call
        schema = _request_schema(body)
        return json.dumps(fill_schema(schema)) if schema else "Model-written paragraph."

    monkeypatch.setattr(fake_llm, "_next", lambda: reply)
    try:
        out = runner.invoke(app, ["run", "-e", str(eng.root)])
    except KeyboardInterrupt:  # the CLI let the interrupt escape
        raise AssertionError("KeyboardInterrupt escaped the run command") from None
    assert out.exit_code == 130, out.output
    assert "interrupted; rerun" in out.output and "unvarnish run" in out.output
    assert calls["n"] - 3 <= 2  # at most `concurrency` calls after the interrupt
    for name in ("alpha", "beta"):
        state = eng.tool_paths(name).extract_state
        assert not state.exists() or read_artifact(state, ExtractState).meta.inputs_hash == ""

    monkeypatch.setattr(fake_llm, "_next", lambda: None)
    fake_llm.autofill = True
    again = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert again.exit_code == 0, again.output  # the next run resumes and finishes
