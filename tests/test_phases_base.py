import logging
from pathlib import Path

import pytest

from tests.conftest import LEAKED_KEY
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseResult, PhaseRunner, PhaseStatus, ToolContext, build_context
from unvarnish.util.logging import setup_run_logging


class CrashingPhase:
    name = "crashing"

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def inputs_hash(self, ctx: ToolContext) -> str:
        return "x"

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.engagement.logs_dir / "never.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        raise self.exc


def _log_text(path: Path) -> str:
    for h in logging.getLogger("unvarnish").handlers:
        h.flush()
    return path.read_text(encoding="utf-8")


def test_crashing_phase_logs_traceback(ingested: tuple[Engagement, str], capsys):
    eng, name = ingested
    log_path = setup_run_logging(eng)
    capsys.readouterr()
    results = PhaseRunner([CrashingPhase(FileNotFoundError("x/y.json"))]).run(
        build_context(eng, name))
    assert results[0].status == PhaseStatus.failed
    text = _log_text(log_path)
    assert "ERROR" in text and name in text and "crashing" in text
    assert "Traceback" in text and "x/y.json" in text
    assert "Traceback" not in "".join(capsys.readouterr())  # the console keeps its one-line summary


def test_crash_traceback_reaches_console_when_verbose(ingested: tuple[Engagement, str], capsys):
    eng, name = ingested
    setup_run_logging(eng, verbose=True)
    capsys.readouterr()
    PhaseRunner([CrashingPhase(FileNotFoundError("x/y.json"))]).run(build_context(eng, name))
    assert "Traceback" in "".join(capsys.readouterr())


def test_crash_log_redacts_secrets(ingested: tuple[Engagement, str]):
    eng, name = ingested
    log_path = setup_run_logging(eng)
    PhaseRunner([CrashingPhase(ValueError(f"bad key {LEAKED_KEY}"))]).run(build_context(eng, name))
    text = _log_text(log_path)
    assert "Traceback" in text and LEAKED_KEY not in text


def test_fatal_error_is_logged_before_reraise(ingested: tuple[Engagement, str]):
    eng, name = ingested
    log_path = setup_run_logging(eng)
    err = RuntimeError("backend is down")
    err.fatal = True  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="backend is down"):
        PhaseRunner([CrashingPhase(err)]).run(build_context(eng, name))
    text = _log_text(log_path)
    assert "ERROR" in text and "crashing" in text and "Traceback" in text
    assert "backend is down" in text


def test_crash_in_engagement_phase_is_recorded_and_logged(ingested: tuple[Engagement, str]):
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.phases.compare import EngagementContext

    eng, _ = ingested
    log_path = setup_run_logging(eng, prefix="compare")
    ctx = EngagementContext(engagement=eng, budget=BudgetTracker(eng.config.budget.max_tokens))
    results = PhaseRunner([CrashingPhase(RuntimeError("compare broke"))]).run(ctx)  # type: ignore[arg-type]
    assert results[0].status == PhaseStatus.failed
    text = _log_text(log_path)
    assert "(engagement)" in text and "Traceback" in text and "compare broke" in text
