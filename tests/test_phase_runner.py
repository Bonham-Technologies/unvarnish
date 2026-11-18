from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import write_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import (
    PhaseResult,
    PhaseRunner,
    PhaseStatus,
    ToolContext,
    build_context,
    is_fresh,
)


class Blob(BaseModel):
    n: int


class CountingPhase:
    name = "counting"

    def __init__(self, hash_value: str = "h1") -> None:
        self.hash_value = hash_value
        self.runs = 0

    def inputs_hash(self, ctx: ToolContext) -> str:
        return self.hash_value

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.inventory / "counting.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        self.runs += 1
        write_artifact(
            self.outputs(ctx)[0], Blob(n=self.runs), produced_by=self.name,
            inputs_hash=self.inputs_hash(ctx),
        )
        return PhaseResult(phase=self.name, status=PhaseStatus.ok)


class ExplodingPhase:
    name = "exploding"

    def inputs_hash(self, ctx: ToolContext) -> str:
        return "x"

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.inventory / "never.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        raise RuntimeError("boom")


def test_build_context(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    assert ctx.tool == name
    assert ctx.source_root == eng.tool_paths(name).source
    assert ctx.meta.origin_kind == "repo"
    assert ctx.config.client == "Acme"


def test_runner_skips_fresh_and_force_reruns(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase()
    runner = PhaseRunner([phase])
    first = runner.run(ctx)
    assert [r.status for r in first] == [PhaseStatus.ok]
    assert is_fresh(phase, ctx)
    second = runner.run(ctx)
    assert [r.status for r in second] == [PhaseStatus.skipped]
    assert phase.runs == 1
    runner.run(ctx, force=True)
    assert phase.runs == 2


def test_runner_reruns_when_inputs_change(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase("h1")
    PhaseRunner([phase]).run(ctx)
    phase.hash_value = "h2"
    assert not is_fresh(phase, ctx)
    PhaseRunner([phase]).run(ctx)
    assert phase.runs == 2


def test_runner_marks_failure_and_skips_downstream(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    after = CountingPhase()
    results = PhaseRunner([ExplodingPhase(), after]).run(ctx)
    assert results[0].status == PhaseStatus.failed
    assert "boom" in (results[0].message or "")
    assert results[1].status == PhaseStatus.skipped
    assert "upstream" in (results[1].message or "")
    assert after.runs == 0


def test_runner_only_runs_named_phase(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    a, b = CountingPhase(), CountingPhase()
    b.name = "other"
    results = PhaseRunner([a, b]).run(ctx, only="other")
    assert [r.phase for r in results] == ["other"]
    assert a.runs == 0 and b.runs == 1


def test_plan_lists_stale_phases(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase()
    runner = PhaseRunner([phase])
    assert runner.plan(ctx) == [phase]
    runner.run(ctx)
    assert runner.plan(ctx) == []
    assert runner.plan(ctx, force=True) == [phase]


class FatalPhase:
    name = "fatal"

    def inputs_hash(self, ctx: ToolContext) -> str:
        return "x"

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.inventory / "never.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        err = RuntimeError("backend is down")
        err.fatal = True  # type: ignore[attr-defined]
        raise err


def test_runner_propagates_fatal_errors(ingested: tuple[Engagement, str]):
    import pytest

    eng, name = ingested
    ctx = build_context(eng, name)
    with pytest.raises(RuntimeError, match="backend is down"):
        PhaseRunner([FatalPhase(), CountingPhase()]).run(ctx)


class InterruptedPhase(ExplodingPhase):
    name = "interrupted"

    def run(self, ctx: ToolContext) -> PhaseResult:
        from unvarnish.model.budget import RunInterrupted

        ctx.budget.interrupt()
        raise RunInterrupted("interrupted")


def test_runner_reports_an_interrupt_escaping_a_phase_as_stopped(
    ingested: tuple[Engagement, str], caplog,
):
    """UNVAR-16: a model call refused after Ctrl-C is a stop, not a crash with a traceback."""
    from unvarnish.model.budget import BudgetTracker

    eng, name = ingested
    ctx = build_context(eng, name, budget=BudgetTracker(None))
    after = CountingPhase()
    results = PhaseRunner([InterruptedPhase(), after]).run(ctx)
    assert [r.status for r in results] == [PhaseStatus.stopped, PhaseStatus.skipped]
    assert after.runs == 0
    assert "Traceback" not in caplog.text


def _named(name: str, out: str, depends_on: tuple[str, ...] | None = None) -> CountingPhase:
    phase = CountingPhase()
    phase.name = name
    phase.outputs = lambda ctx: [ctx.paths.inventory / out]  # type: ignore[method-assign]
    if depends_on is not None:
        phase.depends_on = depends_on  # type: ignore[attr-defined]
    return phase


def test_plan_cascades_to_dependants_but_the_run_still_checks_freshness(
    ingested: tuple[Engagement, str],
):
    """UNVAR-30: a phase downstream of a planned one is planned, even though its own hash
    looks fresh until the upstream rewrites its artifacts. The real run still skips it when
    its inputs came out unchanged."""
    eng, name = ingested
    ctx = build_context(eng, name)
    a = _named("a", "a.json", depends_on=())
    b = _named("b", "b.json", depends_on=("a",))
    c = _named("c", "c.json", depends_on=())  # independent of a
    d = _named("d", "d.json")  # declares nothing: depends on every earlier phase
    runner = PhaseRunner([a, b, c, d])
    runner.run(ctx)
    assert runner.plan(ctx) == []
    a.hash_value = "h2"
    assert [p.name for p in runner.plan(ctx)] == ["a", "b", "d"]
    assert [p.name for p in runner.plan(ctx, only="b")] == []  # nothing upstream runs
    results = runner.run(ctx)
    assert [r.status for r in results] == [PhaseStatus.ok] + [PhaseStatus.skipped] * 3
    assert (a.runs, b.runs, c.runs, d.runs) == (2, 1, 1, 1)
