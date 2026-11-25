from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.delta import MATCH_VERSION, compute_delta
from unvarnish.analysis.effort import effort_days_part
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import EngagementConfig, user_config_path
from unvarnish.model.base import Backend, BackendUnavailable
from unvarnish.model.batch import find_batcher
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import batch_first_calls, merge_failures
from unvarnish.render.architecture import build_architecture_context
from unvarnish.render.findings import build_findings_context
from unvarnish.render.inputs import RenderInputs, load_render_inputs
from unvarnish.render.markdown import (
    make_env,
    prose_block_names,
    render_document,
    template_source_hash,
)
from unvarnish.render.prose import PROSE_PROMPT_VERSION, first_prose_requests, generate_prose
from unvarnish.render.requirements import build_requirements_context
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.delta import DELTA_SCHEMA_VERSION, BaselineSnapshot, Delta
from unvarnish.schemas.diagrams import DiagramSet
from unvarnish.schemas.render import RenderState

log = logging.getLogger("unvarnish.render")

Builder = Callable[[ToolContext, RenderInputs], dict]
# (template, ToolPaths attribute, context builder, RenderInputs field that must be present)
DOCUMENTS: list[tuple[str, str, Builder, str | None]] = [
    ("findings.md.j2", "findings_doc", build_findings_context, None),
    ("architecture.md.j2", "architecture_doc", build_architecture_context, "tool_model"),
    ("requirements.md.j2", "requirements_doc", build_requirements_context, "requirements"),
]


def override_dirs(root: Path, config: EngagementConfig) -> list[Path]:
    dirs = [root / "templates"]
    if config.report.templates_dir:
        tdir = Path(config.report.templates_dir).expanduser()
        dirs.append(tdir if tdir.is_absolute() else root / tdir)
    dirs.append(user_config_path().parent / "templates")
    return dirs


def template_override_dirs(ctx: ToolContext) -> list[Path]:
    return override_dirs(ctx.engagement.root, ctx.config)


class RenderPhase:
    runs_after_stop = True
    name = "render"
    depends_on = ("inventory", "git", "scan", "split", "extract", "rollup_modules",
                  "rollup_tool", "verify")  # every artifact (_inputs)

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def _env(self, ctx: ToolContext):
        return make_env(template_override_dirs(ctx))

    def _inputs(self, ctx: ToolContext) -> list[Path]:
        p = ctx.paths
        return [p.census, p.metrics, p.git, p.dependencies, p.scanner_findings, p.units_index,
                p.extract_state, p.modules_index, p.tool_model, p.capabilities,
                p.model_findings, p.failures, p.ai_usage]

    def inputs_hash(self, ctx: ToolContext) -> str:
        env = self._env(ctx)
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        # The baseline only counts when there is one, so a run without it hashes as before.
        # It changes this phase's hash alone: a new baseline re-renders, no model phase reruns.
        b = ctx.config.baseline
        baseline_part = ([hash_files([ctx.paths.baseline]), ",".join(sorted(b.accepted)),
                          str(b.line_drift), str(DELTA_SCHEMA_VERSION), MATCH_VERSION]
                         if ctx.paths.baseline.exists() else [])
        return hash_inputs([
            hash_files(self._inputs(ctx)),
            *(template_source_hash(env, t) for t, _, _, _ in DOCUMENTS),
            ctx.config.client or "", ctx.config.consultant or "", ctx.config.report.tone,
            ctx.config.report.detail_from,  # the findings template compacts below it (UNVAR-51)
            PROSE_PROMPT_VERSION, model_part, *baseline_part,
            *effort_days_part(ctx.config),
        ])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        p = ctx.paths
        out = [p.render_state, p.findings_doc]
        if p.baseline.exists():
            out.append(p.delta)
        if p.tool_model.exists():
            out.append(p.architecture_doc)
        if p.capabilities.exists():
            out.append(p.requirements_doc)
        return out

    def _delta(self, ctx: ToolContext, inp: RenderInputs,
               failures: list[FailureRecord]) -> Delta | None:
        """This run's findings against the baseline snapshot; no model calls (UNVAR-40)."""
        if not ctx.paths.baseline.exists():
            ctx.paths.delta.unlink(missing_ok=True)  # the baseline was removed
            return None
        try:
            snap = read_artifact(ctx.paths.baseline, BaselineSnapshot).data
            if snap.schema_version != DELTA_SCHEMA_VERSION:
                raise ValueError(f"schema version {snap.schema_version}; rerun with --baseline")
        except Exception as exc:  # a broken snapshot costs the section, not the documents
            failures.append(FailureRecord(phase=self.name, unit_id="baseline",
                                          path=ctx.paths.baseline.name, error=repr(exc)[:500]))
            ctx.paths.delta.unlink(missing_ok=True)
            return None
        b = ctx.config.baseline
        return compute_delta(ctx.tool, snap, inp.scan, inp.model_findings,
                             accepted=b.accepted, drift=b.line_drift)

    def run(self, ctx: ToolContext) -> PhaseResult:
        inp = load_render_inputs(ctx)
        env = self._env(ctx)
        backend = self._resolve(ctx)
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        tone = ctx.config.report.tone
        usage = Usage()
        failures: list[FailureRecord] = []
        inp.delta = self._delta(ctx, inp, failures)
        written: list[str] = []
        hashes: dict[str, str] = {}
        diagrams: dict = {}
        stopped = False
        retry_later = False
        ctx.paths.docs.mkdir(parents=True, exist_ok=True)
        # Each document's context and prose facts first, so that in batch mode every prose
        # block of the tool goes in one message batch before any document is written.
        prepared: dict[str, tuple[dict, dict[str, dict]] | Exception] = {}
        for template, _, builder, required in DOCUMENTS:
            if required and getattr(inp, required) is None:
                continue
            try:
                context = builder(ctx, inp)
                names = prose_block_names(env, template)
                prepared[template] = (context, {n: context["prose_facts"].get(n, {})
                                                for n in names})
            except BackendUnavailable:
                raise
            except Exception as exc:  # reported below, where the document is written
                prepared[template] = exc
        batch_usage = Usage()
        if backend is not None and find_batcher(backend) is not None:
            batch_usage = batch_first_calls(ctx, self.name, backend, [
                req for item in prepared.values() if not isinstance(item, Exception)
                for req in first_prose_requests(item[1], tone=tone, effort=effort)], budget)
        try:
            for template, attr, _, required in DOCUMENTS:
                path: Path = getattr(ctx.paths, attr)
                if required and getattr(inp, required) is None:
                    path.unlink(missing_ok=True)  # its inputs are gone; never keep a stale document
                    continue
                try:
                    item = prepared[template]
                    if isinstance(item, Exception):
                        raise item
                    context, facts = item
                    diagrams.update(context.get("diagrams", {}))
                    prose = generate_prose(backend, facts, tone=tone, effort=effort, budget=budget)
                    usage = usage + prose.usage
                    failures.extend(prose.failures)
                    stopped = stopped or prose.stopped_for_budget
                    retry_later = retry_later or bool(prose.failures and backend is not None)
                    doc = render_document(env, template, {**context, "prose": prose.text})
                except BackendUnavailable:
                    raise
                except Exception as exc:  # a broken template override takes down one document
                    log.exception("render %s: %s failed", ctx.tool, template)
                    failures.append(FailureRecord(phase=self.name, unit_id=template,
                                                  error=repr(exc)[:500]))
                    path.unlink(missing_ok=True)  # never leave a stale document behind
                    continue
                path.write_text(doc, encoding="utf-8")
                written.append(path.name)
                hashes[path.name] = hashlib.sha256(doc.encode("utf-8")).hexdigest()
        finally:  # after the prose calls: a paid batch is used whatever the cap
            budget.add(batch_usage)
        # failures.json is one of this phase's inputs: write it before recording the hash,
        # otherwise the phase would be stale the moment it finished.
        merge_failures(ctx, self.name, failures)
        write_artifact(ctx.paths.diagrams, DiagramSet(diagrams=diagrams), produced_by=self.name,
                       inputs_hash="")
        # A failed prose call leaves fallback text: stay stale so the next run retries it
        # instead of keeping the fallback until --force.
        recorded = "" if (stopped or retry_later) else self.inputs_hash(ctx)
        if inp.delta is not None:
            write_artifact(ctx.paths.delta, inp.delta, produced_by=self.name,
                           inputs_hash=recorded, schema_version=DELTA_SCHEMA_VERSION)
        write_artifact(ctx.paths.render_state, RenderState(tool=ctx.tool, documents=hashes),
                       produced_by=self.name, inputs_hash=recorded)
        if usage.total() and backend is not None:
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=usage, at=datetime.now(UTC)))
        msg = f"wrote {', '.join(written)}"
        if (usage + batch_usage).total():
            msg += f" ({(usage + batch_usage).total():,} tokens of prose)"
        if stopped:
            msg = f"{budget.stop_reason}: " + msg
        log.info("render %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name,
                           status=PhaseStatus.stopped if stopped else PhaseStatus.ok,
                           message=msg, failures=[f"{f.unit_id}: {f.error}" for f in failures])
