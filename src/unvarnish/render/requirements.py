from __future__ import annotations

from unvarnish.phases.base import ToolContext
from unvarnish.render.findings import analysis_mode, generated_at, model_gaps
from unvarnish.render.inputs import RenderInputs


def capability_label(actor: str, action: str, obj: str) -> str:
    return f"{actor} can {action} {obj}"


def build_requirements_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    req = inp.requirements
    assert req is not None, "requirements.md needs capabilities.json"
    caps = sorted(req.capabilities,
                  key=lambda c: (c.actor.lower(), c.action.lower(), c.object.lower()))
    labels = {c.id: capability_label(c.actor, c.action, c.object) for c in caps}
    data_rows = [{"name": r.name, "kind": r.kind, "description": r.description,
                  "used_by": [labels[i] for i in r.used_by if i in labels]}
                 for r in req.data_inventory]
    gaps = model_gaps(inp)
    prose_facts = {"open_questions": {
        "tool": ctx.meta.name,
        "open_questions_from_analysis": req.open_questions,
        "actors": [a.name for a in req.actors],
        "implicit_capabilities": [f"{labels[c.id]}: {c.description}" for c in caps
                                  if c.implicit],
        "capabilities_without_known_module": [labels[c.id] for c in caps if not c.evidence],
        "business_rules": [r.model_dump() for r in req.business_rules],
        "not_analysed": {"failed_units": gaps["failed_units_count"],
                         "windowed_units": gaps["windowed"]["count"],
                         "failed_modules": len(gaps["failed_modules"]),
                         "files_not_split": len(gaps["skipped_split"])},
    }}
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "req": req, "capabilities": caps,
        "implicit_count": sum(1 for c in caps if c.implicit), "data_rows": data_rows,
        "analysis_mode": analysis_mode(inp), "prose_facts": prose_facts, "diagrams": {},
    }
