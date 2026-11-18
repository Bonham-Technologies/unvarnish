from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.comparison import (
    build_matrix,
    integration_items,
    integration_map,
    risk_row,
    tool_summary,
)
from unvarnish.analysis.effort import effort_days_part
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.compare import (
    COMPARE_PROMPT_VERSION,
    build_consolidate_request,
    build_integrate_request,
    build_normalise_request,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseRunner, PhaseStatus
from unvarnish.phases.modelrun import call_structured
from unvarnish.phases.render import override_dirs
from unvarnish.render.comparison import build_comparison_context
from unvarnish.render.markdown import (
    make_env,
    prose_block_names,
    render_document,
    template_source_hash,
)
from unvarnish.render.prose import PROSE_PROMPT_VERSION, generate_prose
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    Comparison,
    Consolidation,
    IntegrationGrouping,
)
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.diagrams import DiagramSet
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.render import RenderState
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.compare")
ENGAGEMENT_TOOL = "(engagement)"


@dataclass
class EngagementContext:
    engagement: Engagement
    budget: BudgetTracker

    @property
    def config(self) -> EngagementConfig:
        return self.engagement.config


@dataclass
class ToolInputs:
    tool: str
    census: Census
    metrics: Metrics
    git: GitStats
    scan: ScannerFindings
    deps: Dependencies
    tool_model: ToolModel | None
    model_findings: ModelFindings | None
    errors: list[str]  # optional artifacts that exist but could not be read


def _optional[T](path: Path, cls: type[T], errors: list[str]) -> T | None:
    if not path.exists():
        return None
    try:
        return read_artifact(path, cls).data  # type: ignore[arg-type]
    except Exception as exc:
        errors.append(f"{path.name} unreadable: {exc!r}"[:300])
        return None


def load_tool_inputs(eng: Engagement, tool: str) -> ToolInputs | None:
    """Everything compare needs for one tool, or None when the tool has not been run."""
    p = eng.tool_paths(tool)
    if not (p.census.exists() and p.metrics.exists() and p.scanner_findings.exists()
            and p.dependencies.exists()):
        return None
    git = (read_artifact(p.git, GitStats).data if p.git.exists()
           else GitStats(tool=tool, available=False, reason="git phase has not run"))
    errors: list[str] = []
    return ToolInputs(
        tool=tool, census=read_artifact(p.census, Census).data,
        metrics=read_artifact(p.metrics, Metrics).data, git=git,
        scan=read_artifact(p.scanner_findings, ScannerFindings).data,
        deps=read_artifact(p.dependencies, Dependencies).data,
        tool_model=_optional(p.tool_model, ToolModel, errors),
        model_findings=_optional(p.model_findings, ModelFindings, errors),
        errors=errors,
    )


def merge_engagement_failures(eng: Engagement, phase: str, items: list[FailureRecord]) -> None:
    existing: list[FailureRecord] = []
    if eng.comparison_failures.exists():
        try:
            existing = read_artifact(eng.comparison_failures, Failures).data.items
        except Exception:
            log.warning("comparison/failures.json unreadable; rewriting it")
    kept = [f for f in existing if f.phase != phase]
    write_artifact(eng.comparison_failures, Failures(tool=ENGAGEMENT_TOOL, items=kept + items),
                   produced_by=phase, inputs_hash="")


class ComparePhase:
    name = "compare"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, eng: Engagement) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(eng, self.name)
        except NoModelConfigured:
            return None

    def _inputs(self, eng: Engagement) -> list[Path]:
        out: list[Path] = []
        for tool in eng.tool_names():
            p = eng.tool_paths(tool)
            out += [p.census, p.metrics, p.git, p.dependencies, p.scanner_findings,
                    p.tool_model, p.model_findings]
        return out

    def inputs_hash(self, ectx: EngagementContext) -> str:
        eng = ectx.engagement
        ref = resolve_model_ref(eng.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files(self._inputs(eng)), ",".join(eng.tool_names()),
                            model_part, COMPARE_PROMPT_VERSION,
                            eng.config.consolidation.model_dump_json(),
                            *effort_days_part(eng.config)])

    def outputs(self, ectx: EngagementContext) -> list[Path]:
        return [ectx.engagement.comparison_file]

    def run(self, ectx: EngagementContext) -> PhaseResult:
        eng = ectx.engagement
        loaded = {t: load_tool_inputs(eng, t) for t in eng.tool_names()}
        inputs = [i for i in loaded.values() if i is not None]
        not_run = [t for t, i in loaded.items() if i is None]
        if not inputs:
            return PhaseResult(phase=self.name, status=PhaseStatus.failed, not_ready=True,
                               message="no tool has been analysed yet; run `unvarnish run` first")
        models = {i.tool: i.tool_model for i in inputs if i.tool_model is not None}
        caps_by_tool = {t: tm.capabilities for t, tm in models.items()}
        backend = self._resolve(eng)
        ref = resolve_model_ref(eng.config, self.name)
        effort = ref.effort if ref else None
        budget = ectx.budget
        usage = Usage()
        failures: list[FailureRecord] = [
            FailureRecord(phase=self.name, unit_id="artifact", path=i.tool, error=err)
            for i in inputs for err in i.errors]
        stopped = False
        stop = threading.Event()
        norm: CapabilityNormalisation | None = None
        consolidation: Consolidation | None = None
        skipped: list[str] = []

        def call[T](req, cls: type[T], item: str) -> T | None:
            nonlocal usage, stopped
            try:
                budget.check()
            except BudgetExceeded:
                stopped = True
                return None
            try:
                res, failure = call_structured(backend, req, cls, phase=self.name,
                                               item_id=item, path=None, stop=stop)
            except BudgetExceeded:  # interrupted while waiting for a model slot
                stopped = True
                return None
            if res is None:
                if failure:
                    failures.append(failure)
                return None
            usage = usage + res.usage
            budget.add(res.usage)
            return res.parsed

        if not_run:
            skipped.append(f"not run, so not compared: {', '.join(not_run)}")
        if len(models) < 2:
            skipped.append("one tool with a tool model: matrix and proposal skipped"
                           if models else "no tool has a tool model: matrix and proposal skipped")
        elif backend is None:
            skipped.append("no model configured: capabilities are listed per tool, "
                           "no grouping or proposal")
        else:
            norm = call(build_normalise_request(caps_by_tool, effort), CapabilityNormalisation,
                        "normalisation")
            if norm is None and not stopped:
                skipped.append("capability normalisation failed: capabilities listed per tool")

        if len(models) >= 2:
            matrix, unmapped, dropped = build_matrix(norm, caps_by_tool)
        else:
            matrix, unmapped, dropped = [], 0, 0
        grouping = None
        if len(models) >= 2 and backend is not None and not stopped:
            grouping = call(build_integrate_request(integration_items(models), effort),
                            IntegrationGrouping, "integration")
            if grouping is None and not stopped:
                skipped.append("integration grouping failed: stores joined by name only")
        integration = integration_map(models, grouping)
        summaries = [tool_summary(i.tool, i.tool_model, i.census) for i in inputs]
        risk = [risk_row(i.tool, i.census, i.metrics, i.git, i.scan, i.model_findings, i.deps,
                         model_analysed=i.tool_model is not None) for i in inputs]

        if len(models) >= 2 and backend is not None and not stopped:
            consolidation = call(
                build_consolidate_request(summaries, matrix, integration, effort,
                                          constraints=eng.config.consolidation, risk=risk,
                                          effort_days=eng.config.report.effort_days),
                Consolidation, "consolidation")
            if consolidation is None and not stopped:
                skipped.append("consolidation proposal failed: see comparison/failures.json")
            elif consolidation is not None:
                for r in consolidation.recommended_approach:
                    if r.recommended_tool not in models:
                        r.recommended_tool = f"{r.recommended_tool} (not a reviewed tool)"

        cmp = Comparison(
            tools=[i.tool for i in inputs], tools_with_model=list(models), tools_not_run=not_run,
            summaries=summaries,
            capability_matrix=matrix, unmapped_capabilities=unmapped,
            dropped_references=dropped, integration_map=integration, risk_table=risk,
            consolidation=consolidation, skipped_reason="; ".join(skipped) or None,
            constraints=(None if eng.config.consolidation.is_empty()
                         else eng.config.consolidation),
            normalised=norm is not None,
            backend=backend.name if backend else None, model=backend.model if backend else None,
            usage=usage, prompt_version=COMPARE_PROMPT_VERSION, stopped_for_budget=stopped,
        )
        eng.comparison_dir.mkdir(parents=True, exist_ok=True)
        # A failed proposal leaves the comparison stale, so the next `compare` retries it.
        proposal_failed = len(models) >= 2 and backend is not None and consolidation is None
        write_artifact(eng.comparison_file, cmp, produced_by=self.name,
                       inputs_hash="" if (stopped or proposal_failed) else self.inputs_hash(ectx))
        if usage.total() and backend is not None:
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase=self.name,
                                       backend=backend.name, model=backend.model, usage=usage,
                                       at=datetime.now(UTC)))
        merge_engagement_failures(eng, self.name, failures)
        msg = (f"{len(inputs)} tools ({len(models)} with a tool model), "
               f"{len(matrix)} matrix rows, {len(integration)} shared systems/stores, "
               f"{'proposal written' if consolidation else 'no proposal'}, "
               f"{usage.total():,} tokens")
        if not_run:
            msg += f"; not run: {', '.join(not_run)}"
        if stopped:
            msg = f"{budget.stop_reason}: " + msg
        log.info("compare: %s", msg)
        return PhaseResult(phase=self.name,
                           status=PhaseStatus.stopped if stopped else PhaseStatus.ok,
                           message=msg,
                           failures=[f"{f.path or f.unit_id}: {f.error}" for f in failures])


class RenderComparisonPhase:
    name = "render_comparison"
    TEMPLATE = "comparison.md.j2"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, eng: Engagement) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(eng, self.name)
        except NoModelConfigured:
            return None

    def _env(self, eng: Engagement):
        return make_env(override_dirs(eng.root, eng.config))

    def inputs_hash(self, ectx: EngagementContext) -> str:
        eng = ectx.engagement
        ref = resolve_model_ref(eng.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        # Each tool's delta feeds the trend column; counted only where one exists, so a
        # baseline re-renders the comparison without rerunning compare's model calls.
        deltas = [p for t in eng.tool_names() if (p := eng.tool_paths(t).delta).exists()]
        return hash_inputs([hash_files([eng.comparison_file]),
                            template_source_hash(self._env(eng), self.TEMPLATE),
                            eng.config.client or "", eng.config.consultant or "",
                            eng.config.report.tone, PROSE_PROMPT_VERSION, model_part,
                            *([hash_files(deltas)] if deltas else []),
                            *effort_days_part(eng.config)])

    def outputs(self, ectx: EngagementContext) -> list[Path]:
        return [ectx.engagement.comparison_render_state, ectx.engagement.comparison_doc]

    def run(self, ectx: EngagementContext) -> PhaseResult:
        eng = ectx.engagement
        cmp = read_artifact(eng.comparison_file, Comparison).data
        env = self._env(eng)
        backend = self._resolve(eng)
        ref = resolve_model_ref(eng.config, self.name)
        effort = ref.effort if ref else None
        context = build_comparison_context(eng, cmp)
        names = prose_block_names(env, self.TEMPLATE)
        if cmp.consolidation is None:
            names = [n for n in names if n != "consolidation_proposal"]  # inside a false branch
        facts = {n: context["prose_facts"].get(n, {}) for n in names}
        prose = generate_prose(backend, facts, tone=eng.config.report.tone, effort=effort,
                               budget=ectx.budget)
        if cmp.consolidation is None:
            prose.text.setdefault("consolidation_proposal", "")
        doc = render_document(env, self.TEMPLATE, {**context, "prose": prose.text})
        eng.comparison_doc.write_text(doc, encoding="utf-8")
        write_artifact(eng.comparison_diagrams, DiagramSet(diagrams=context.get("diagrams", {})),
                       produced_by=self.name, inputs_hash="")
        for f in prose.failures:  # generate_prose stamps "render"; this phase owns them
            f.phase = self.name
        merge_engagement_failures(eng, self.name, prose.failures)
        write_artifact(eng.comparison_render_state,
                       RenderState(tool=ENGAGEMENT_TOOL, documents={
                           eng.comparison_doc.name: hashlib.sha256(doc.encode()).hexdigest()}),
                       produced_by=self.name,
                       inputs_hash="" if prose.stopped_for_budget else self.inputs_hash(ectx))
        if prose.usage.total() and backend is not None:
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase=self.name,
                                       backend=backend.name, model=backend.model,
                                       usage=prose.usage, at=datetime.now(UTC)))
        msg = f"wrote {eng.comparison_doc.name}"
        if prose.usage.total():
            msg += f" ({prose.usage.total():,} tokens of prose)"
        status = PhaseStatus.stopped if prose.stopped_for_budget else PhaseStatus.ok
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.unit_id}: {f.error}" for f in prose.failures])


def comparison_phases(backend: Backend | None = None) -> list:
    return [ComparePhase(backend), RenderComparisonPhase(backend)]


def run_comparison(eng: Engagement, *, force: bool = False, backend: Backend | None = None,
                   budget: BudgetTracker | None = None) -> list[PhaseResult]:
    ectx = EngagementContext(engagement=eng,
                             budget=budget or BudgetTracker(eng.config.budget.max_tokens))
    results = PhaseRunner(comparison_phases(backend)).run(ectx, force=force)  # type: ignore[arg-type]
    for r in results:  # a crash is caught by the runner; record it where the message points
        if r.status == PhaseStatus.failed and not r.not_ready and r.message:
            merge_engagement_failures(eng, r.phase, [FailureRecord(phase=r.phase,
                                                                   error=r.message[:500])])
    return results
