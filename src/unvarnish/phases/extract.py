from __future__ import annotations

import hashlib
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend, BackendError, BackendUnavailable, ModelRefusal
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.extract import (
    PROMPT_VERSION,
    ROUTE_NOTE,
    build_extract_request,
    build_system_prompt,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.model.structured import StructuredOutputError, complete_structured
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import has_failures, merge_failures
from unvarnish.scanners.client_exposure import route_hints
from unvarnish.scanners.secrets import redact_model_text, redact_text
from unvarnish.schemas.analysis import (
    CandidateFinding,
    ExtractState,
    FailureRecord,
    Unit,
    UnitExtraction,
    UnitResult,
    UnitsIndex,
)
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.inventory import Census

log = logging.getLogger("unvarnish.extract")


def to_findings(
    cands: list[CandidateFinding], unit: Unit, tool: str, model: str
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        if not (unit.line_start <= c.line_start <= c.line_end <= unit.line_end):
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title,
            summary=c.summary, impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=unit.path, line_start=c.line_start, line_end=c.line_end,
                               excerpt=redact_text((c.excerpt or "")[:200]) or None)],
            source=Source.model, model=model, confidence=c.confidence,
            effort=c.effort, effort_note=c.effort_note,
        ))
    return findings, dropped


def unit_inputs_hash(unit: Unit, source: bytes, backend_name: str, model: str,
                     effort: str | None, notes: list[str] | None = None) -> str:
    # Scanner notes join the hash only when present, so units without any keep their cache.
    return hash_inputs([hashlib.sha256(source).hexdigest(), unit.id, backend_name, model,
                        PROMPT_VERSION, effort or "", *(["\n".join(notes)] if notes else [])])


def unit_notes(unit: Unit, hints: dict[str, list[int]]) -> list[str]:
    """Scanner notes for the lines of this unit: route handlers with no auth nearby."""
    return [ROUTE_NOTE.format(line=n) for n in hints.get(unit.path, [])
            if unit.line_start <= n <= unit.line_end]


class ExtractPhase:
    name = "extract"
    reads_source = True  # fails when the source is gone (UNVAR-31)
    # The units index. Route hints from scanner findings join the hash by content, not by
    # file bytes, so a scan rerun that finds the same handlers keeps extract fresh.
    depends_on = ("split",)

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def inputs_hash(self, ctx: ToolContext) -> str:
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        hints = route_hints(ctx.paths.scanner_findings)
        return hash_inputs([hash_files([ctx.paths.units_index]), model_part, PROMPT_VERSION,
                            *([json.dumps(hints, sort_keys=True)] if hints else [])])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.extract_state]

    def retry_pending(self, ctx: ToolContext) -> bool:
        """Failed items wait in failures.json: a plain rerun retries them (UNVAR-29)."""
        return has_failures(ctx, self.name)

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        index = read_artifact(ctx.paths.units_index, UnitsIndex).data
        census = read_artifact(ctx.paths.census, Census).data
        by_id = {u.id: u for u in index.units}
        hints = route_hints(ctx.paths.scanner_findings)
        system = build_system_prompt()
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        ctx.paths.unit_dir.mkdir(parents=True, exist_ok=True)
        stop = threading.Event()  # set on budget cap, fatal error, or interrupt
        budget_hit = threading.Event()

        def process_module(
            module_id: str, unit_ids: list[str]
        ) -> tuple[int, list[FailureRecord], Usage, dict[str, str]]:
            neighbourhood: list[str] = []
            module_done = 0
            module_hashes: dict[str, str] = {}  # done unit id -> its inputs hash
            module_failures: list[FailureRecord] = []
            module_usage = Usage()
            uid: str | None = None  # the unit in hand when an error escapes
            try:
                source_bytes = (ctx.source_root / module_id).read_bytes()
                for uid in unit_ids:
                    unit = by_id[uid]
                    chunk = source_bytes[unit.byte_start:unit.byte_end]
                    notes = unit_notes(unit, hints)
                    h = unit_inputs_hash(unit, chunk, backend.name, backend.model, effort, notes)
                    out_path = ctx.paths.unit_dir / f"{uid}.json"
                    if out_path.exists():
                        try:
                            prior = read_artifact(out_path, UnitResult)
                            if prior.meta.inputs_hash == h:
                                neighbourhood.append(prior.data.extraction.purpose)
                                module_done += 1
                                module_hashes[uid] = h
                                continue
                        except Exception:  # unreadable artifact: redo the unit
                            pass
                    if stop.is_set():
                        break
                    try:
                        budget.check()
                    except BudgetExceeded:
                        budget_hit.set()
                        stop.set()
                        break
                    req = build_extract_request(
                        unit, chunk.decode("utf-8", errors="replace"),
                        frameworks=census.frameworks, neighbourhood=neighbourhood, effort=effort,
                        system=system, scanner_notes=notes,
                    )
                    try:
                        res = complete_structured(backend, req, UnitExtraction)
                    except BudgetExceeded:  # interrupted while waiting for a model slot
                        budget_hit.set()
                        stop.set()
                        break
                    except ModelRefusal as exc:
                        module_failures.append(FailureRecord(
                            phase=self.name, unit_id=uid, path=unit.path,
                            error=f"refused ({exc.category})", attempts=1))
                        continue
                    except StructuredOutputError as exc:
                        module_failures.append(FailureRecord(
                            phase=self.name, unit_id=uid, path=unit.path,
                            error=exc.last_error[:500], attempts=exc.attempts))
                        continue
                    except BackendUnavailable:
                        stop.set()  # nothing else can succeed; let the other workers drain
                        raise
                    except BackendError as exc:
                        module_failures.append(FailureRecord(
                            phase=self.name, unit_id=uid, path=unit.path, error=str(exc)[:500],
                            attempts=1))
                        continue
                    res.parsed = redact_model_text(res.parsed)  # stored extraction: no secrets
                    for c in res.parsed.candidate_findings:  # stored extraction: no raw secrets
                        if c.excerpt:
                            c.excerpt = redact_text(c.excerpt)
                    findings, dropped = to_findings(res.parsed.candidate_findings, unit, ctx.tool,
                                                    backend.model)
                    result = UnitResult(
                        unit=unit, extraction=res.parsed, findings=findings,
                        dropped_findings=dropped, backend=backend.name, model=backend.model,
                        usage=res.usage, prompt_version=PROMPT_VERSION, attempts=res.attempts,
                    )
                    budget.add(res.usage)  # spent even if the write below fails
                    module_usage = module_usage + res.usage
                    write_artifact(out_path, result, produced_by=self.name, inputs_hash=h)
                    neighbourhood.append(res.parsed.purpose)
                    module_done += 1
                    module_hashes[uid] = h
                    log.debug("extracted %s %s (%d tokens, %d attempts)", unit.path, uid,
                              res.usage.total(), res.attempts)
            except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
                if getattr(exc, "fatal", False) or isinstance(exc, BudgetExceeded):
                    raise  # an outage, bad configuration or Ctrl-C stops the phase as before
                # Anything else (the file gone since split, a full disk) fails this module
                # only, as run_parallel does: the phase stays stale and a plain rerun retries
                # the units left undone (UNVAR-32). Done units keep their artifacts.
                error = redact_text(repr(exc))[:500]
                log.error("extract %s: worker failed on %s: %s", ctx.tool, module_id, error)
                module_failures.append(FailureRecord(
                    phase=self.name, unit_id=uid, path=module_id, error=error))
            return module_done, module_failures, module_usage, module_hashes

        done = 0
        failures: list[FailureRecord] = []
        usage = Usage()
        unit_hashes: dict[str, str] = {}
        fatal: BackendUnavailable | None = None
        workers = max(1, ctx.config.pipeline.concurrency)
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {pool.submit(process_module, m, ids): m for m, ids in index.modules.items()}
            for fut in as_completed(futures):
                try:
                    d, f, u, hs = fut.result()
                except BackendUnavailable as exc:
                    fatal = fatal or exc
                    continue
                done += d
                failures.extend(f)
                usage = usage + u
                unit_hashes.update(hs)
        except BaseException:  # interrupt: stop the workers, still record what was done
            stop.set()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
            self._persist(ctx, backend, index, done, failures, usage, unit_hashes,
                          stopped=budget_hit.is_set() or fatal is not None)
        if fatal is not None:
            raise fatal
        stopped = budget_hit.is_set()
        status = PhaseStatus.stopped if stopped else PhaseStatus.ok
        failed = f"{len(failures)} failed; rerun to retry" if failures else "0 failed"
        msg = f"{done}/{len(index.units)} units, {failed}, {usage.total():,} tokens"
        if stopped:
            msg = f"{budget.stop_reason}: " + msg
        log.info("extract %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in failures])

    @staticmethod
    def _units_digest(ctx: ToolContext, index: UnitsIndex, unit_hashes: dict[str, str]) -> str:
        """Digest of the unit artifacts the rollups will read: each done unit's inputs hash,
        and for a unit not done this run (failed, or left by a stop) the inputs hash its
        artifact on disk records, if it has one. That artifact can come from a run the rollups
        never followed (an interrupt, a budget stop, `--phase extract`), so it counts too."""
        parts: list[str] = []
        for uid in sorted(u.id for u in index.units):
            if uid in unit_hashes:
                parts.append(f"{uid}={unit_hashes[uid]}")
                continue
            path = ctx.paths.unit_dir / f"{uid}.json"
            if not path.exists():
                continue
            try:
                parts.append(f"{uid}~{read_artifact(path, UnitResult).meta.inputs_hash}")
            except Exception:  # noqa: BLE001 - unreadable: the rollups skip it too
                continue
        return hash_inputs(parts)

    def _persist(self, ctx: ToolContext, backend: Backend, index: UnitsIndex, done: int,
                 failures: list[FailureRecord], usage: Usage, unit_hashes: dict[str, str], *,
                 stopped: bool) -> None:
        if usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=usage, at=datetime.now(UTC)))
        state = ExtractState(
            tool=ctx.tool, backend=backend.name, model=backend.model,
            prompt_version=PROMPT_VERSION, units_total=len(index.units), units_done=done,
            units_failed=len(failures), usage=usage, stopped_for_budget=stopped,
            units_digest=self._units_digest(ctx, index, unit_hashes),
        )
        merge_failures(ctx, self.name, failures)
        # An empty inputs_hash keeps the phase stale after a stop, a failed unit, or anything
        # else that left units undone (an interrupt), so a later run resumes or retries; done
        # units are kept by their own hashes (UNVAR-29, UNVAR-32).
        complete = not (stopped or failures) and done >= len(index.units)
        write_artifact(ctx.paths.extract_state, state, produced_by=self.name,
                       inputs_hash=self.inputs_hash(ctx) if complete else "")
