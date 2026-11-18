from __future__ import annotations

import math
from collections.abc import Collection, Sequence

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.artifacts import read_artifact
from unvarnish.model.prompts.extract import build_system_prompt
from unvarnish.model.prompts.rollup import build_module_rollup_system, build_tool_rollup_system
from unvarnish.model.prompts.verify import build_verify_system
from unvarnish.phases.base import ToolContext
from unvarnish.phases.render import DOCUMENTS, template_override_dirs
from unvarnish.render.markdown import make_env, prose_block_names
from unvarnish.schemas.analysis import UnitResult, UnitsIndex
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.rollup import Module

MODEL_PHASES = ("extract", "rollup_modules", "rollup_tool", "verify", "render")

SYSTEM_PROMPT_TOKENS: int = estimate_tokens(build_system_prompt())
NEIGHBOURHOOD_TOKENS = 300
OUTPUT_TOKENS_PER_UNIT = 700

MODULE_SYSTEM_TOKENS: int = estimate_tokens(build_module_rollup_system())
UNIT_SUMMARY_TOKENS = 300
MODULE_OUTPUT_TOKENS = 600
TOOL_SYSTEM_TOKENS: int = estimate_tokens(build_tool_rollup_system())
DIGEST_TOKENS = 150
CHUNK_OUTPUT_TOKENS = 1500
TOOL_OUTPUT_TOKENS = 6000
VERIFY_SYSTEM_TOKENS: int = estimate_tokens(build_verify_system())
VERIFY_INPUT_TOKENS = 1500
VERIFY_OUTPUT_TOKENS = 150
PROSE_INPUT_TOKENS = 3000
PROSE_OUTPUT_TOKENS = 500


def estimate_extract(index: UnitsIndex, done_ids: Collection[str] = frozenset(), *,
                     cached_system: bool = False) -> Usage:
    """With prompt caching, every call after the first reads the system prompt from cache."""
    remaining = [u for u in index.units if u.id not in done_ids]
    body = sum(u.token_estimate + NEIGHBOURHOOD_TOKENS for u in remaining)
    if cached_system and remaining:
        return Usage(input_tokens=body + SYSTEM_PROMPT_TOKENS,
                     cache_read_tokens=SYSTEM_PROMPT_TOKENS * (len(remaining) - 1),
                     output_tokens=OUTPUT_TOKENS_PER_UNIT * len(remaining))
    return Usage(input_tokens=body + SYSTEM_PROMPT_TOKENS * len(remaining),
                 output_tokens=OUTPUT_TOKENS_PER_UNIT * len(remaining))


def estimate_rollup_modules(index: UnitsIndex, *, single_unit_calls: bool = False) -> Usage:
    """One call per module with several units; one-unit modules are derived without a call
    unless the engagement asks for them."""
    called = [ids for ids in index.modules.values() if single_unit_calls or len(ids) > 1]
    return Usage(
        input_tokens=(len(called) * MODULE_SYSTEM_TOKENS
                      + sum(len(ids) for ids in called) * UNIT_SUMMARY_TOKENS),
        output_tokens=len(called) * MODULE_OUTPUT_TOKENS,
    )


def estimate_rollup_tool(n_modules: int, rollup_input_tokens: int) -> Usage:
    digests = n_modules * DIGEST_TOKENS
    chunks = 0 if digests <= rollup_input_tokens else math.ceil(digests / rollup_input_tokens)
    chunk_input = chunks * (TOOL_SYSTEM_TOKENS + rollup_input_tokens)
    final_input = TOOL_SYSTEM_TOKENS + (chunks * CHUNK_OUTPUT_TOKENS if chunks else digests)
    return Usage(input_tokens=chunk_input + final_input,
                 output_tokens=TOOL_OUTPUT_TOKENS + chunks * CHUNK_OUTPUT_TOKENS)


def estimate_verify(n_high: int) -> Usage:
    return Usage(input_tokens=n_high * (VERIFY_SYSTEM_TOKENS + VERIFY_INPUT_TOKENS),
                 output_tokens=n_high * VERIFY_OUTPUT_TOKENS)


def tool_prose_block_count(env) -> int:
    """Prose calls a tool's render makes: the blocks its own document templates reference
    (the same `DOCUMENTS` and `prose_block_names` the render phase uses), not the comparison's."""
    return sum(len(prose_block_names(env, template)) for template, *_ in DOCUMENTS)


def estimate_render(n_blocks: int) -> Usage:
    return Usage(input_tokens=n_blocks * PROSE_INPUT_TOKENS,
                 output_tokens=n_blocks * PROSE_OUTPUT_TOKENS)


def count_high_findings(ctx: ToolContext) -> int:
    """High/critical model findings recorded so far in unit and module artifacts."""
    from unvarnish.phases.verify import current_artifacts

    n = 0
    high = (Severity.critical, Severity.high)
    units, modules = current_artifacts(ctx)
    for paths, cls in ((units, UnitResult), (modules, Module)):
        for p in paths:
            try:
                n += sum(1 for f in read_artifact(p, cls).data.findings if f.severity in high)
            except Exception:
                continue
    return n


def _caches(ctx: ToolContext, phase: str) -> bool:
    """Whether the phase's backend caches the system prompt (Anthropic does)."""
    from unvarnish.model.registry import resolve_model_ref

    ref = resolve_model_ref(ctx.config, phase)
    backend = ctx.config.backends.get(ref.backend) if ref else None
    return backend is not None and backend.type == "anthropic"


def planned_units(ctx: ToolContext, planned: Collection[str]) -> UnitsIndex | None:
    """The units the planned run would extract from. When split is not planned, its recorded
    index (None before split has run). When it is, a split of the source as it is now,
    computed in memory and written nowhere: from a census computed the same way when
    inventory is planned too, else from the recorded census. None if that fails."""
    if "split" not in planned:
        if not ctx.paths.units_index.exists():
            return None
        return read_artifact(ctx.paths.units_index, UnitsIndex).data
    from unvarnish.phases.inventory import census_files, tracked_files
    from unvarnish.phases.split import split_records
    from unvarnish.schemas.inventory import Census

    try:
        if "inventory" in planned or not ctx.paths.census.exists():
            records = census_files(ctx.source_root, tracked_files(ctx))
        else:
            records = read_artifact(ctx.paths.census, Census).data.files
        return split_records(ctx, records)[0]
    except Exception:  # an estimate never fails the dry run
        return None


def extracted_units(ctx: ToolContext, index: UnitsIndex) -> set[str]:
    """The units whose recorded extraction the next extract would keep: the artifact's
    inputs hash matches the unit's current source bytes, model and prompt. Every other unit
    is new or changed and costs a model call."""
    from unvarnish.model.registry import resolve_model_ref
    from unvarnish.phases.base import _recorded_hash
    from unvarnish.phases.extract import unit_inputs_hash, unit_notes
    from unvarnish.scanners.client_exposure import route_hints

    if not ctx.paths.unit_dir.exists():
        return set()
    ref = resolve_model_ref(ctx.config, "extract")
    by_id = {u.id: u for u in index.units}
    hints = route_hints(ctx.paths.scanner_findings)
    done: set[str] = set()
    for path, ids in index.modules.items():
        try:
            source = (ctx.source_root / path).read_bytes()
        except OSError:
            continue
        for uid in ids:
            art = ctx.paths.unit_dir / f"{uid}.json"
            if not art.exists() or uid not in by_id:
                continue
            if ref is None:  # no model: extract skips, so nothing is priced as changed
                done.add(uid)
                continue
            unit = by_id[uid]
            h = unit_inputs_hash(unit, source[unit.byte_start:unit.byte_end], ref.backend,
                                 ref.model, ref.effort, unit_notes(unit, hints))
            if _recorded_hash(art) == h:
                done.add(uid)
    return done


def estimate_plan(ctx: ToolContext, planned: Sequence[str]) -> dict[str, tuple[Usage, str] | None]:
    """Token estimate and a short note for each planned model phase, or None when one is not
    estimable yet. The units come from `planned_units`, computed once."""
    model_phases = [p for p in planned if p in MODEL_PHASES]
    index = None
    if any(p in ("extract", "rollup_modules", "rollup_tool") for p in model_phases):
        index = planned_units(ctx, planned)
    return {p: estimate_phase(ctx, p, index) for p in model_phases}


def estimate_phase(ctx: ToolContext, phase: str,
                   index: UnitsIndex | None = None) -> tuple[Usage, str] | None:
    """Token estimate and a short note for one model phase, or None when not estimable yet."""
    if phase == "render":
        n = tool_prose_block_count(make_env(template_override_dirs(ctx)))
        return estimate_render(n), f"{n} prose blocks"
    if phase == "verify":
        n = count_high_findings(ctx)
        return estimate_verify(n), f"{n} high/critical model findings recorded so far"
    if index is None:
        return None
    if phase == "extract":
        done = extracted_units(ctx, index)
        remaining = sum(1 for u in index.units if u.id not in done)
        return (estimate_extract(index, done, cached_system=_caches(ctx, phase)),
                f"{remaining} of {len(index.units)} units new or changed")
    if phase == "rollup_modules":
        single = ctx.config.pipeline.rollup_single_unit_modules
        called = sum(1 for ids in index.modules.values() if single or len(ids) > 1)
        return (estimate_rollup_modules(index, single_unit_calls=single),
                f"{called} of {len(index.modules)} modules need a model call")
    if phase == "rollup_tool":
        return (estimate_rollup_tool(len(index.modules), ctx.config.pipeline.rollup_input_tokens),
                f"{len(index.modules)} module digests")
    return None
