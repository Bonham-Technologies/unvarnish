from __future__ import annotations

import json
import logging
import os
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from unvarnish.artifacts import write_artifact
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement, ToolPaths
from unvarnish.model.budget import BudgetTracker, RunInterrupted
from unvarnish.phases.ingest import load_tool_meta, resolve_source_root
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.tool import ToolMeta

log = logging.getLogger(__name__)


@dataclass
class ToolContext:
    engagement: Engagement
    tool: str
    paths: ToolPaths
    meta: ToolMeta
    source_root: Path
    budget: BudgetTracker | None = None  # shared across phases and tools for one run

    @property
    def config(self) -> EngagementConfig:
        return self.engagement.config


class PhaseStatus(StrEnum):
    ok = "ok"
    skipped = "skipped"
    failed = "failed"
    stopped = "stopped"  # budget cap reached; resumable


class PhaseResult(BaseModel):
    phase: str
    status: PhaseStatus
    message: str | None = None
    failures: list[str] = Field(default_factory=list)
    not_ready: bool = False  # an earlier step must run first (the CLI exits 2)


class RunRecord(BaseModel):
    """Outcome of the most recent `run` for a tool; written to analysis/failures.json."""

    tool: str
    ran_at: datetime
    results: list[PhaseResult]
    failures: list[str] = Field(default_factory=list)


def missing_source(ctx: ToolContext) -> str | None:
    """Why the tool's source cannot be read, or None when its directory is there. A linked
    folder can be moved or deleted after `add`, and a copied source removed by hand; analysing
    the empty tree would overwrite the tool's documents with "0 / 0 files" (UNVAR-31)."""
    return source_missing_reason(ctx.source_root, ctx.meta)


def source_missing_reason(root: Path, meta: ToolMeta) -> str | None:
    """`missing_source` for callers without a ToolContext (ask's grep_source)."""
    if root.is_dir():
        return None
    how = ("linked tool; re-add or restore it" if meta.origin_kind == "link"
           else "copied source; re-add the tool")
    what = "is not a directory" if root.exists() else "does not exist"
    return f"source directory {root} {what} ({how})"


def record_run(ctx: ToolContext, results: list[PhaseResult]) -> RunRecord:
    failures = [f"{r.phase}: {x}" for r in results for x in r.failures]
    failures += [f"{r.phase}: {r.message}" for r in results if r.status == PhaseStatus.failed]
    record = RunRecord(tool=ctx.tool, ran_at=datetime.now(UTC), results=results,
                       failures=failures)
    write_artifact(ctx.paths.run_record, record, produced_by="run", inputs_hash="")
    return record


def load_run_record(ctx: ToolContext) -> RunRecord | None:
    if not ctx.paths.run_record.exists():
        return None
    from unvarnish.artifacts import read_artifact

    return read_artifact(ctx.paths.run_record, RunRecord).data


class Phase(Protocol):
    name: str

    def inputs_hash(self, ctx: ToolContext) -> str: ...
    def outputs(self, ctx: ToolContext) -> list[Path]: ...
    def run(self, ctx: ToolContext) -> PhaseResult: ...


META_TAIL_BYTES = 4096


def _recorded_hash(path: Path) -> str | None:
    """The artifact's recorded inputs hash. Artifacts are written with sorted keys, so "meta"
    is the last member: read only the tail, falling back to a full parse."""
    if path.suffix != ".json":
        return "<non-artifact>"
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - META_TAIL_BYTES))
            tail = fh.read().decode("utf-8", errors="replace")
        i = tail.rfind('"meta": {')
        if i != -1:
            body = tail[i + len('"meta": '):].rstrip()
            if body.endswith("}"):
                body = body[:-1].rstrip()  # the artifact's closing brace
            return json.loads(body)["inputs_hash"]
    except (OSError, ValueError, KeyError):
        pass
    try:
        return json.loads(path.read_text(encoding="utf-8"))["meta"]["inputs_hash"]
    except (OSError, ValueError, KeyError):
        return None


def is_fresh(phase: Phase, ctx: ToolContext) -> bool:
    outputs = phase.outputs(ctx)
    if not outputs or not all(p.exists() for p in outputs):
        return False
    pending = getattr(phase, "retry_pending", None)  # failed items to retry (UNVAR-29)
    if pending is not None and pending(ctx):
        return False
    current = phase.inputs_hash(ctx)
    for p in outputs:
        recorded = _recorded_hash(p)
        if recorded is None:
            return False
        if recorded != "<non-artifact>" and recorded != current:
            return False
    return True


def _log_crash(ctx: object, phase: Phase, exc: BaseException) -> None:
    """The run log is the only evidence of an unattended crash, so it gets the full traceback,
    redacted because an exception message can quote a secret. The console shows the
    traceback only with --verbose (`console: False`, see setup_run_logging). The context is a
    ToolContext or compare's EngagementContext, which has no tool. Logging is best-effort: it
    must never replace the phase's own exception."""
    try:
        tool = getattr(ctx, "tool", "(engagement)")
        tb = "".join(traceback.format_exception(exc)).rstrip()
        log.error("%s", redact_text(f"{tool}: phase {phase.name!r} failed\n{tb}"),
                  extra={"console": False})
    except Exception:
        pass


class PhaseRunner:
    def __init__(self, phases: Sequence[Phase]) -> None:
        self.phases = list(phases)

    def _selected(self, only: str | None) -> list[Phase]:
        if only is None:
            return self.phases
        chosen = [p for p in self.phases if p.name == only]
        if not chosen:
            names = ", ".join(p.name for p in self.phases)
            raise ValueError(f"unknown phase {only!r}; known phases: {names}")
        return chosen

    def _missing_upstream(self, ctx: ToolContext, phase: Phase,
                          exc: FileNotFoundError) -> str | None:
        """The first phase to run before `phase`, when the file it could not find is an
        earlier phase's output: the earliest phase up to that producer whose outputs are not
        all there. None when the missing file is not an earlier phase's output."""
        if not exc.filename:
            return None
        missing = os.path.abspath(os.fsdecode(exc.filename))
        earlier = self.phases[:self.phases.index(phase)] if phase in self.phases else []
        for i, producer in enumerate(earlier):
            try:
                outputs = [os.path.abspath(p) for p in producer.outputs(ctx)]
            except Exception:
                continue
            if missing in outputs:
                for candidate in earlier[:i + 1]:
                    try:
                        if not all(p.exists() for p in candidate.outputs(ctx)):
                            return candidate.name
                    except Exception:
                        continue
                return producer.name
        return None

    def plan(
        self, ctx: ToolContext, *, force: bool = False, only: str | None = None
    ) -> list[Phase]:
        """The phases a run would or might run, for the dry run: each stale phase, and each
        phase that reads the output of a planned one (its `depends_on`, the phases whose
        artifacts its inputs hash covers; a phase that declares none depends on every
        earlier one). A downstream phase looks fresh until its upstream rewrites its
        artifacts, so its own hash cannot say. The real run still checks freshness phase by
        phase, so it skips a planned phase whose inputs came out unchanged."""
        planned: list[Phase] = []
        names: set[str] = set()
        earlier: list[str] = []
        for p in self._selected(only):
            deps = getattr(p, "depends_on", None)
            deps = earlier if deps is None else deps
            if force or any(d in names for d in deps) or not is_fresh(p, ctx):
                planned.append(p)
                names.add(p.name)
            earlier.append(p.name)
        return planned

    def run(
        self, ctx: ToolContext, *, force: bool = False, only: str | None = None
    ) -> list[PhaseResult]:
        results: list[PhaseResult] = []
        upstream_failed: str | None = None
        upstream_how = "failed"
        budget = getattr(ctx, "budget", None)
        for phase in self._selected(only):
            if budget is not None and budget.interrupted.is_set():  # Ctrl-C: start nothing
                results.append(PhaseResult(phase=phase.name, status=PhaseStatus.skipped,
                                           message="skipped: interrupted"))
                continue
            # Phases marked runs_after_stop (render) still run after a budget stop: the scanner
            # results they show are complete. A failure upstream still skips them.
            after_stop = upstream_how == "stopped" and getattr(phase, "runs_after_stop", False)
            if upstream_failed and not after_stop:
                results.append(PhaseResult(
                    phase=phase.name, status=PhaseStatus.skipped,
                    message=f"skipped: upstream phase {upstream_failed!r} {upstream_how}",
                ))
                continue
            if not force and is_fresh(phase, ctx):
                results.append(
                    PhaseResult(phase=phase.name, status=PhaseStatus.skipped, message="fresh")
                )
                continue
            # A phase that reads the source never runs on a missing tree: it would rewrite
            # good artifacts from nothing (UNVAR-31). Render and the rollups read only them.
            missing = missing_source(ctx) if getattr(phase, "reads_source", False) else None
            try:
                if missing is not None:
                    result = PhaseResult(phase=phase.name, status=PhaseStatus.failed,
                                         message=missing)
                else:
                    result = phase.run(ctx)
            except RunInterrupted:  # a model call refused after Ctrl-C: a stop, not a crash
                result = PhaseResult(phase=phase.name, status=PhaseStatus.stopped,
                                     message="interrupted")
            except FileNotFoundError as exc:
                needs = self._missing_upstream(ctx, phase, exc)
                if needs is None:
                    _log_crash(ctx, phase, exc)
                    message = repr(exc)
                else:  # run --phase on a tool whose earlier phases have not run yet
                    tool = getattr(ctx, "tool", "")
                    message = (f"needs {needs}; run `unvarnish run {tool}` or "
                               f"`--phase {needs}` first")
                result = PhaseResult(phase=phase.name, status=PhaseStatus.failed,
                                     message=message)
            except Exception as exc:  # one bad phase never kills the process
                _log_crash(ctx, phase, exc)
                if getattr(exc, "fatal", False):  # except configuration/backend outages
                    # The caller records the run so far, so `status` shows the failure
                    # instead of an older run or "never" (UNVAR-78).
                    exc.phase_results = [*results, PhaseResult(  # type: ignore[attr-defined]
                        phase=phase.name, status=PhaseStatus.failed, message=str(exc))]
                    raise
                result = PhaseResult(
                    phase=phase.name, status=PhaseStatus.failed, message=repr(exc)
                )
            results.append(result)
            if result.status in (PhaseStatus.failed, PhaseStatus.stopped):
                upstream_failed = phase.name
                upstream_how = "stopped" if result.status == PhaseStatus.stopped else "failed"
        return results


def build_context(eng: Engagement, tool: str, budget: BudgetTracker | None = None) -> ToolContext:
    paths = eng.tool_paths(tool)
    meta = load_tool_meta(paths)
    return ToolContext(
        engagement=eng, tool=tool, paths=paths, meta=meta,
        source_root=resolve_source_root(eng, meta), budget=budget,
    )
