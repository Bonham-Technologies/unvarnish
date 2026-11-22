from __future__ import annotations

import logging
import re
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.languages import Classification
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend, BackendUnavailable
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.rollup import (
    TOOL_ROLLUP_PROMPT_VERSION,
    ToolFacts,
    build_directory_rollup_request,
    build_tool_rollup_request,
    digest_text,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.scanners.secrets import redact_model_text
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import ModuleDigest, ModulesIndex
from unvarnish.schemas.toolmodel import (
    Capability,
    DataInventoryRow,
    DirectoryRollup,
    EntryPoint,
    ModuleMapEntry,
    RequirementsInventory,
    ToolCandidateFinding,
    ToolModel,
    ToolRollup,
    capability_id,
)
from unvarnish.util.plural import plural

log = logging.getLogger("unvarnish.rollup_tool")
MODULE_MAP_CAP = 60
Chunk = tuple[str, list[ModuleDigest]]
ChunkRollup = tuple[str, int, DirectoryRollup]
IndexedChunkRollup = tuple[int, ChunkRollup]


def common_prefix(paths: Sequence[str]) -> str:
    dirs = [p.rsplit("/", 1)[0] if "/" in p else "" for p in paths]
    parts = [d.split("/") if d else [] for d in dirs]
    if not parts:
        return ""
    out: list[str] = []
    for segs in zip(*parts, strict=False):
        if all(s == segs[0] for s in segs):
            out.append(segs[0])
        else:
            break
    return "/".join(out)


def partition_digests(digests: Sequence[ModuleDigest], budget_tokens: int) -> list[Chunk]:
    """Chunks of path-sorted digests that each fit `budget_tokens`; [] when all fit one call."""
    sized = [(d, estimate_tokens(digest_text(d))) for d in sorted(digests, key=lambda d: d.path)]
    if sum(n for _, n in sized) <= budget_tokens:
        return []
    chunks: list[list[ModuleDigest]] = []
    cur: list[ModuleDigest] = []
    cur_tokens = 0
    for d, n in sized:
        if cur and cur_tokens + n > budget_tokens:
            chunks.append(cur)
            cur, cur_tokens = [], 0
        cur.append(d)
        cur_tokens += n
    if cur:
        chunks.append(cur)
    labelled: list[Chunk] = []
    counts: dict[str, int] = {}
    for c in chunks:
        label = common_prefix([d.path for d in c])
        counts[label] = counts.get(label, 0) + 1
        labelled.append((label if counts[label] == 1 else f"{label} (part {counts[label]})", c))
    if any(n > 1 for n in counts.values()):  # name the first part too, for symmetry
        labelled = [((f"{lbl} (part 1)" if counts.get(lbl, 0) > 1 else lbl), c)
                    for lbl, c in labelled]
    return labelled


def tool_facts(ctx: ToolContext, census: Census, git: GitStats) -> ToolFacts:
    live = [f for f in census.files if not f.excluded]
    return ToolFacts(
        tool=ctx.tool, languages=dict(census.languages), frameworks=list(census.frameworks),
        files_analysed=sum(1 for f in live if f.classification != Classification.binary),
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        commits=git.commit_count if git.available else None,
        authors=len(git.authors) if git.available else None,
        first_commit=git.first_commit.date().isoformat() if git.first_commit else None,
        last_commit=git.last_commit.date().isoformat() if git.last_commit else None,
    )


def to_tool_findings(cands: Sequence[ToolCandidateFinding], known: set[str], tool: str,
                     model: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        paths = [p for p in dict.fromkeys(c.paths) if p in known]
        if not paths:
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title,
            summary=c.summary, impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=p, note="cited by tool-level analysis") for p in paths],
            source=Source.model, model=model, confidence=c.confidence,
            effort=c.effort, effort_note=c.effort_note,
        ))
    return findings, dropped


STOPWORDS = {"a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with", "from", "by",
             "is", "are", "be", "can", "may", "no", "not", "using", "via", "into", "its", "it"}


def _title_words(title: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", title.lower())
    return {w[:-1] if len(w) > 3 and w.endswith("s") else w for w in words} - STOPWORDS


def merge_similar_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Merge tool-level findings that restate one problem: same severity, at least half the
    cited files shared (of the smaller set), and at least 30% of title words in common. The
    hierarchical rollup reports the same issue from different directory chunks."""
    out: list[Finding] = []
    for f in findings:
        paths, words = {e.path for e in f.evidence}, _title_words(f.title)
        for kept in out:
            kp, kw = {e.path for e in kept.evidence}, _title_words(kept.title)
            shared = len(paths & kp) / max(1, min(len(paths), len(kp)))
            similar = len(words & kw) / max(1, len(words | kw))
            if kept.severity == f.severity and shared >= 0.5 and similar >= 0.3:
                kept.evidence.extend(e for e in f.evidence if e.path not in kp)
                break
        else:
            out.append(f)
    return out


def merge_entry_points(base: Sequence[EntryPoint],
                       extra: Sequence[EntryPoint]) -> list[EntryPoint]:
    """One entry point per module and kind, first name kept. HTTP routes are the exception:
    one module serves several, so they are keyed by name. Rollup chunks name the same script
    or screen differently ("Agent release chain scripts" and "release-version-pr.sh")."""
    out: list[EntryPoint] = []
    seen: set[tuple[str, ...]] = set()
    for e in [*base, *extra]:
        key = (("http", e.name.lower()) if e.kind == "http" else (e.module, e.kind))
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def _name_words(name: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z0-9]+", name.lower())) - STOPWORDS


def uses_store(name: str, touched: Sequence[str]) -> bool:
    """Whether a capability's data_touched names this store: the same words, or every word of
    a name of two or more words inside the other. "DB" is not "Orders DB"."""
    words = _name_words(name)
    for t in touched:
        tw = _name_words(t)
        small, large = (words, tw) if len(words) <= len(tw) else (tw, words)
        if words == tw or (len(small) >= 2 and small <= large):
            return True
    return False


def merge_similar_named[T](base: Sequence[T], extra: Sequence[T]) -> list[T]:
    """Union of named items (data stores, external systems), merging an item into an earlier
    one when the shorter name's words (two or more) are all in the longer name. Rollup chunks
    name one store "video-editor-db IndexedDB", "IndexedDB video-editor-db", and so on."""
    out: list[T] = []
    for x in [*base, *extra]:
        words = _name_words(x.name)  # type: ignore[attr-defined]
        for kept in out:
            kw = _name_words(kept.name)  # type: ignore[attr-defined]
            small, large = (words, kw) if len(words) <= len(kw) else (kw, words)
            if words == kw or (len(small) >= 2 and small <= large):
                extra_modules = [m for m in getattr(x, "modules", [])
                                 if m not in getattr(kept, "modules", [])]
                if extra_modules:
                    kept.modules.extend(extra_modules)  # type: ignore[attr-defined]
                break
        else:
            out.append(x)
    return out


def build_tool_model(tool: str, rollup: ToolRollup, known: set[str], *,
                     chunk_rollups: Sequence[ChunkRollup], backend_name: str, model: str,
                     usage: Usage, attempts: int, modules_covered: int,
                     chunks_attempted: int = 0,
                     chunks_failed: Sequence[str] = ()) -> ToolModel:
    entry_points = merge_entry_points([], rollup.entry_points)
    data_stores = merge_similar_named([], rollup.data_stores)
    external = merge_similar_named([], rollup.external_systems)
    cands = list(rollup.candidate_findings)
    extra_modules: list[ModuleMapEntry] = []
    for _, _, dr in chunk_rollups:
        entry_points = merge_entry_points(entry_points, dr.entry_points)
        data_stores = merge_similar_named(data_stores, dr.data_stores)
        external = merge_similar_named(external, dr.external_systems)
        cands.extend(dr.candidate_findings)
        extra_modules.extend(dr.notable_modules)
    module_map: list[ModuleMapEntry] = []
    seen_paths: set[str] = set()
    for m in [*rollup.module_map, *extra_modules]:
        if m.path in known and m.path not in seen_paths and len(module_map) < MODULE_MAP_CAP:
            seen_paths.add(m.path)
            module_map.append(ModuleMapEntry(path=m.path, role=m.role,
                                             depends_on=[d for d in m.depends_on if d in known]))
    findings, dropped = to_tool_findings(cands, known, tool, model)
    findings = merge_similar_findings(findings)
    caps: dict[str, Capability] = {}
    for c in rollup.capabilities:
        cid = capability_id(tool, c.actor, c.action, c.object)
        if cid in caps:
            continue
        caps[cid] = Capability(
            **c.model_dump(), id=cid, tool=tool,
            evidence=[Evidence(path=p) for p in dict.fromkeys(c.implementing_modules)
                      if p in known],
        )
    return ToolModel(
        tool=tool, purpose=rollup.purpose, actors=rollup.actors,
        entry_points=[e for e in entry_points if e.module in known],
        data_stores=[s.model_copy(update={"modules": [m for m in s.modules if m in known]})
                     for s in data_stores],
        external_systems=[x.model_copy(update={"modules": [m for m in x.modules if m in known]})
                          for x in external],
        internal_stack=rollup.internal_stack, module_map=module_map,
        data_flows=rollup.data_flows, deployment_assumptions=rollup.deployment_assumptions,
        capabilities=list(caps.values()),
        business_rules=[r for r in rollup.business_rules if r.module in known],
        open_questions=rollup.open_questions, findings=findings, dropped_findings=dropped,
        hierarchical=chunks_attempted > 0, chunks=len(chunk_rollups),
        chunks_attempted=chunks_attempted, chunks_failed=list(chunks_failed),
        modules_covered=modules_covered, confidence=rollup.confidence, backend=backend_name,
        model=model, usage=usage, prompt_version=TOOL_ROLLUP_PROMPT_VERSION, attempts=attempts,
    )


def requirements_inventory(tm: ToolModel) -> RequirementsInventory:
    def users_of(name: str) -> list[str]:
        return [c.id for c in tm.capabilities if uses_store(name, c.data_touched)]

    rows = [DataInventoryRow(name=s.name, kind=s.kind, description=s.description,
                             used_by=users_of(s.name)) for s in tm.data_stores]
    rows += [DataInventoryRow(name=s.name, kind=f"external:{s.kind}", description=s.description,
                              used_by=users_of(s.name)) for s in tm.external_systems]
    return RequirementsInventory(tool=tm.tool, actors=tm.actors, capabilities=tm.capabilities,
                                 data_inventory=rows, business_rules=tm.business_rules,
                                 open_questions=tm.open_questions)


class RollupToolPhase:
    name = "rollup_tool"
    depends_on = ("inventory", "git", "rollup_modules")  # census, git, modules

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
        return hash_inputs([hash_files([ctx.paths.modules_index, ctx.paths.census,
                                        ctx.paths.git]),
                            model_part, TOOL_ROLLUP_PROMPT_VERSION,
                            str(ctx.config.pipeline.rollup_input_tokens)])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.tool_model, ctx.paths.capabilities]

    def _finish(self, ctx: ToolContext, backend: Backend, usage: Usage,
                failures: list[FailureRecord]) -> None:
        if usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, failures)

    def _failed(self, ctx: ToolContext, backend: Backend, usage: Usage,
                failures: list[FailureRecord], message: str) -> PhaseResult:
        """The tool model could not be produced. One failed call never kills the run: record
        it, remove any stale tool model so render does not use an outdated one, and let the
        downstream phases produce the documents that do not need it."""
        self._finish(ctx, backend, usage, failures)
        for stale in (ctx.paths.tool_model, ctx.paths.capabilities):
            stale.unlink(missing_ok=True)
        log.warning("rollup_tool %s: %s", ctx.tool, message)
        return PhaseResult(phase=self.name, status=PhaseStatus.ok,
                           message=f"no tool model: {message}",
                           failures=[f"{f.unit_id or 'tool'}: {f.error}" for f in failures]
                           or [message])

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        if not ctx.paths.modules_index.exists():
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="rollup_modules has not run for this tool")
        index = read_artifact(ctx.paths.modules_index, ModulesIndex).data
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        census = read_artifact(ctx.paths.census, Census).data
        git = (read_artifact(ctx.paths.git, GitStats).data if ctx.paths.git.exists()
               else GitStats(tool=ctx.tool, available=False, reason="git phase has not run"))
        known = {d.path for d in index.modules}
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        usage = Usage()
        failures: list[FailureRecord] = []
        if not index.modules:
            return self._failed(ctx, backend, usage, failures, "no module rollups available")
        chunks = partition_digests(index.modules, ctx.config.pipeline.rollup_input_tokens)
        chunk_rollups: list[ChunkRollup] = []
        chunks_failed: list[str] = []
        modules_covered = len(index.modules)

        if chunks:
            indexed = list(enumerate(chunks))

            def worker(item: tuple[int, Chunk],
                       stop: threading.Event) -> ItemOutcome[IndexedChunkRollup]:
                i, (prefix, digests) = item
                req = build_directory_rollup_request(prefix, digests, effort)
                res, failure = call_structured(backend, req, DirectoryRollup, phase=self.name,
                                               item_id=f"chunk{i}:{prefix or '(root)'}",
                                               path=None, stop=stop)
                if res is None:
                    return ItemOutcome(failures=[failure] if failure else [])
                return ItemOutcome(result=(i, (prefix, len(digests),
                                               redact_model_text(res.parsed))),
                                   usage=res.usage)

            outcome = run_parallel(indexed, worker, workers=ctx.config.pipeline.concurrency,
                                   budget=budget, phase=self.name)
            usage = usage + outcome.usage
            failures.extend(outcome.failures)
            if outcome.fatal is not None:
                self._finish(ctx, backend, usage, failures)
                raise outcome.fatal
            if outcome.stopped_for_budget:
                self._finish(ctx, backend, usage, failures)
                return PhaseResult(phase=self.name, status=PhaseStatus.stopped,
                                   message=f"{budget.stop_reason} during directory rollups")
            if not outcome.results:
                return self._failed(ctx, backend, usage, failures,
                                    "every directory rollup failed")
            succeeded = {i for i, _ in outcome.results}
            chunk_rollups = [cr for _, cr in sorted(outcome.results, key=lambda r: r[0])]
            chunks_failed = [prefix or "(root)" for i, (prefix, _) in indexed
                             if i not in succeeded]
            modules_covered = sum(n for _, n, _ in chunk_rollups)

        try:
            budget.check()
        except BudgetExceeded:
            self._finish(ctx, backend, usage, failures)
            return PhaseResult(phase=self.name, status=PhaseStatus.stopped,
                               message=f"{budget.stop_reason} before the tool rollup")
        req = build_tool_rollup_request(tool_facts(ctx, census, git),
                                        [] if chunks else index.modules, chunk_rollups, effort)
        try:
            res, failure = call_structured(backend, req, ToolRollup, phase=self.name,
                                           item_id="tool", path=None, stop=threading.Event())
        except BudgetExceeded:  # interrupted while waiting for a model slot
            self._finish(ctx, backend, usage, failures)
            return PhaseResult(phase=self.name, status=PhaseStatus.stopped,
                               message=f"{budget.stop_reason} before the tool rollup")
        except BackendUnavailable:
            self._finish(ctx, backend, usage, failures)  # keep the chunk calls' cost
            raise
        if res is None:
            if failure:
                failures.append(failure)
            return self._failed(ctx, backend, usage, failures,
                                f"tool rollup failed: {failure.error if failure else '?'}")
        usage = usage + res.usage
        budget.add(res.usage)
        tm = build_tool_model(ctx.tool, redact_model_text(res.parsed), known,
                              chunk_rollups=chunk_rollups,
                              backend_name=backend.name, model=backend.model, usage=usage,
                              attempts=res.attempts, modules_covered=modules_covered,
                              chunks_attempted=len(chunks), chunks_failed=chunks_failed)
        h = self.inputs_hash(ctx)
        write_artifact(ctx.paths.tool_model, tm, produced_by=self.name, inputs_hash=h)
        write_artifact(ctx.paths.capabilities, requirements_inventory(tm), produced_by=self.name,
                       inputs_hash=h)
        self._finish(ctx, backend, usage, failures)
        chunks = plural(tm.chunks_attempted, "chunk")
        how = (f"hierarchical, {tm.chunks}/{chunks}" if tm.hierarchical
               else "single pass")
        msg = (f"{plural(len(tm.capabilities), 'capability')}, "
               f"{plural(len(tm.findings), 'finding')}, {how}, "
               f"{usage.total():,} tokens")
        log.info("rollup_tool %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, message=msg,
                           failures=[f"{f.unit_id or 'tool'}: {f.error}" for f in failures])
