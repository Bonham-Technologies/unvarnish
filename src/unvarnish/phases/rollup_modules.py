from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.prompts.rollup import (
    ROLLUP_PROMPT_VERSION,
    build_module_rollup_request,
    build_module_rollup_system,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import (
    ItemOutcome,
    call_structured,
    has_failures,
    merge_failures,
    run_parallel,
)
from unvarnish.scanners.secrets import redact_model_text, redact_text
from unvarnish.schemas.analysis import CandidateFinding, UnitResult, UnitsIndex
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import (
    Module,
    ModuleDigest,
    ModuleRollup,
    ModulesIndex,
    module_file_id,
)
from unvarnish.util.plural import plural

log = logging.getLogger("unvarnish.rollup_modules")
DIGEST_LIST_CAP = 20

WorkItem = tuple[str, list[UnitResult], list[str]]  # path, unit results, unit artifact hashes


def to_module_findings(cands: list[CandidateFinding], path: str, file_lines: int, tool: str,
                       model: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        upper = file_lines if file_lines > 0 else c.line_end
        if not (1 <= c.line_start <= c.line_end <= upper):
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title,
            summary=c.summary, impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=path, line_start=c.line_start, line_end=c.line_end,
                               excerpt=redact_text((c.excerpt or "")[:200]) or None)],
            source=Source.model, model=model, confidence=c.confidence,
            effort=c.effort, effort_note=c.effort_note,
        ))
    return findings, dropped


def _unique(items: Sequence[str]) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it.strip(), None)
    return [s for s in seen if s][:DIGEST_LIST_CAP]


def make_digest(module: Module, units: Sequence[UnitResult], lines: int) -> ModuleDigest:
    return ModuleDigest(
        id=module.id, path=module.path, language=units[0].unit.language if units else None,
        units=len(units), lines=lines, summary=module.rollup.summary,
        responsibilities=module.rollup.responsibilities, interface=module.rollup.interface,
        dependencies_out=module.rollup.dependencies_out,
        external_systems=_unique([c.system for u in units for c in u.extraction.external_calls]),
        data_read=_unique([d for u in units for d in u.extraction.data_read]),
        data_written=_unique([d for u in units for d in u.extraction.data_written]),
        findings=len(module.findings),
    )


MODULE_OUTPUT_ROOM = 6_000
DERIVED_MODEL = "derived"


def derived_module(path: str, tool: str, unit: UnitResult) -> Module:
    """The rollup of a one-unit module, built from that unit's extraction. A model call here
    restates the unit and invents "file-level" findings that cannot exist with one unit."""
    e = unit.extraction
    rollup = ModuleRollup(
        summary=e.purpose, interface=e.interface,
        dependencies_out=_unique([c.system for c in e.external_calls]),
        confidence=e.confidence)
    return Module(id=module_file_id(path), tool=tool, path=path, unit_ids=[unit.unit.id],
                  rollup=rollup, backend=DERIVED_MODEL, model=DERIVED_MODEL, usage=Usage(),
                  prompt_version=ROLLUP_PROMPT_VERSION, attempts=0)


class RollupModulesPhase:
    name = "rollup_modules"
    depends_on = ("split", "extract")  # units index, extract state

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
        return hash_inputs([hash_files([ctx.paths.extract_state, ctx.paths.units_index]),
                            model_part, ROLLUP_PROMPT_VERSION,
                            str(ctx.config.pipeline.rollup_single_unit_modules)])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.modules_index]

    def retry_pending(self, ctx: ToolContext) -> bool:
        """Failed items wait in failures.json: a plain rerun retries them (UNVAR-29)."""
        return has_failures(ctx, self.name)

    def _work(self, ctx: ToolContext, index: UnitsIndex) -> tuple[list[WorkItem], list[str]]:
        work: list[WorkItem] = []
        skipped: list[str] = []
        for path, unit_ids in sorted(index.modules.items()):
            results: list[UnitResult] = []
            hashes: list[str] = []
            for uid in unit_ids:
                p = ctx.paths.unit_dir / f"{uid}.json"
                if not p.exists():
                    continue
                try:
                    art = read_artifact(p, UnitResult)
                except Exception:  # unreadable unit artifact: treat as missing
                    continue
                results.append(art.data)
                hashes.append(art.meta.inputs_hash)
            if results:
                work.append((path, results, hashes))
            else:
                skipped.append(path)
        return work, skipped

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        if not ctx.paths.extract_state.exists():
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="extract has not run for this tool")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        index = read_artifact(ctx.paths.units_index, UnitsIndex).data
        census = read_artifact(ctx.paths.census, Census).data
        lines_by_path = {f.path: f.lines for f in census.files}
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        system = build_module_rollup_system()
        ctx.paths.module_dir.mkdir(parents=True, exist_ok=True)
        work, skipped = self._work(ctx, index)

        derive_single = not ctx.config.pipeline.rollup_single_unit_modules
        # The window minus the system prompt and room for the answer.
        input_room = max(2_000, backend.capabilities.context_window
                         - estimate_tokens(system) - MODULE_OUTPUT_ROOM)

        def worker(item: WorkItem, stop: threading.Event) -> ItemOutcome[ModuleDigest]:
            path, results, hashes = item
            lines = lines_by_path.get(path, 0)
            if derive_single and len(results) == 1:
                module = derived_module(path, ctx.tool, results[0])
                write_artifact(ctx.paths.module_dir / f"{module_file_id(path)}.json", module,
                               produced_by=self.name, inputs_hash=hash_inputs(
                                   [*hashes, DERIVED_MODEL, ROLLUP_PROMPT_VERSION]))
                return ItemOutcome(result=make_digest(module, results, lines))
            h = hash_inputs([*hashes, backend.name, backend.model, effort or "",
                             ROLLUP_PROMPT_VERSION])
            out_path = ctx.paths.module_dir / f"{module_file_id(path)}.json"
            if out_path.exists():
                try:
                    prior = read_artifact(out_path, Module)
                    if prior.meta.inputs_hash == h:
                        return ItemOutcome(result=make_digest(prior.data, results, lines))
                except Exception:  # unreadable artifact: redo the module
                    pass
            req = build_module_rollup_request(path, results[0].unit.language, lines, results,
                                              census.frameworks, effort, system=system,
                                              max_input_tokens=input_room)
            res, failure = call_structured(backend, req, ModuleRollup, phase=self.name,
                                           item_id=module_file_id(path), path=path, stop=stop)
            if res is None:
                return ItemOutcome(failures=[failure] if failure else [])
            res.parsed = redact_model_text(res.parsed)
            for c in res.parsed.candidate_findings:  # the stored rollup must not hold secrets
                if c.excerpt:
                    c.excerpt = redact_text(c.excerpt)
            findings, dropped = to_module_findings(res.parsed.candidate_findings, path, lines,
                                                   ctx.tool, backend.model)
            module = Module(
                id=module_file_id(path), tool=ctx.tool, path=path,
                unit_ids=[r.unit.id for r in results], rollup=res.parsed, findings=findings,
                dropped_findings=dropped, backend=backend.name, model=backend.model,
                usage=res.usage, prompt_version=ROLLUP_PROMPT_VERSION, attempts=res.attempts,
            )
            write_artifact(out_path, module, produced_by=self.name, inputs_hash=h)
            log.debug("rolled up %s (%d units, %d tokens)", path, len(results),
                      res.usage.total())
            return ItemOutcome(result=make_digest(module, results, lines), usage=res.usage)

        outcome = run_parallel(work, worker, workers=ctx.config.pipeline.concurrency,
                               budget=budget, phase=self.name)
        failed = sorted({f.path for f in outcome.failures if f.path})
        idx = ModulesIndex(tool=ctx.tool, modules=sorted(outcome.results, key=lambda d: d.path),
                           failed=failed, skipped=skipped, usage=outcome.usage,
                           stopped_for_budget=outcome.stopped_for_budget)
        # An empty inputs_hash keeps the phase stale after a stop or a failed module, so a
        # later run resumes or retries; done modules are kept by their own hashes (UNVAR-29).
        retry = outcome.stopped or bool(outcome.failures)
        write_artifact(ctx.paths.modules_index, idx, produced_by=self.name,
                       inputs_hash="" if retry else self.inputs_hash(ctx))
        if outcome.usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=outcome.usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, outcome.failures)
        if outcome.fatal is not None:
            raise outcome.fatal
        n_failed = (f"{len(failed) or len(outcome.failures)} failed; rerun to retry"
                    if outcome.failures else "0 failed")
        msg = (f"{len(outcome.results)}/{plural(len(work), 'module')}, {n_failed}, "
               f"{len(skipped)} without units, {outcome.usage.total():,} tokens")
        status = PhaseStatus.stopped if outcome.stopped_for_budget else PhaseStatus.ok
        if outcome.stopped_for_budget:
            msg = f"{budget.stop_reason}: " + msg
        log.info("rollup_modules %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in outcome.failures])
