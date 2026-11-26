from __future__ import annotations

from unvarnish.phases.base import ToolContext
from unvarnish.render.findings import analysis_mode, generated_at, model_gaps
from unvarnish.render.inputs import RenderInputs

FIELDS_SHOWN = 8  # field names per data class row
STORES_SHOWN = 6  # stores per data class row
EVIDENCE_SHOWN = 3  # locations per data class row
DESTINATION_ROWS = 40
PATHS_SHOWN = 3


def capability_label(actor: str, action: str, obj: str) -> str:
    return f"{actor} can {action} {obj}"


def _and_more(items: list[str], shown: int) -> str:
    text = ", ".join(items[:shown])
    return text + (f", and {len(items) - shown} more" if len(items) > shown else "")


def _code(items: list[str], shown: int) -> str:
    return _and_more([f"`{i}`" for i in items], shown)


def sensitive_context(inp: RenderInputs) -> dict | None:
    """The "Sensitive data" section (UNVAR-100): the classes field names suggest, where they
    are declared, and a join of their stores to the destinations already in the analysis.
    Built from sensitive-data.json, tool.json and ai-usage.json alone; None when the
    sensitive_data scanner did not run."""
    sd = inp.sensitive_data
    if sd is None:
        return None
    rows = []
    for key in sd.classes_found():
        hits = [f for f in sd.fields if f.data_class == key]
        fields = list(dict.fromkeys(f.field for f in hits))
        stores = list(dict.fromkeys(f"`{f.store}` ({f.store_kind})" for f in hits))
        where = list(dict.fromkeys(f"{f.path}:{f.line}" for f in hits))
        rows.append({"label": sd.classes[key], "fields": _code(fields, FIELDS_SHOWN),
                     "stores": _and_more(stores, STORES_SHOWN),
                     "evidence": _code(where, EVIDENCE_SHOWN)})
    # Stores by the file that declares them, with their classes in the pattern set's order.
    by_file: dict[str, dict[str, set[str]]] = {}
    for f in sd.fields:
        by_file.setdefault(f.path, {}).setdefault(f.store, set()).add(f.data_class)
    order = list(sd.classes)

    def stores_in(paths: list[str]) -> str:
        found: dict[str, set[str]] = {}
        for p in paths:
            for store, classes in by_file.get(p, {}).items():
                found.setdefault(store, set()).update(classes)
        items = []
        for store, classes in found.items():
            labels = ", ".join(sd.classes[c] for c in sorted(classes, key=order.index))
            items.append(f"`{store}` ({labels})")
        return _and_more(items, STORES_SHOWN) or "—"

    destinations = []
    tm = inp.tool_model
    if tm is not None:
        for x in tm.external_systems:
            if x.direction == "inbound":
                continue
            flows = [fl.data for fl in tm.data_flows if fl.target.strip().lower()
                     == x.name.strip().lower()]
            destinations.append({"name": x.name, "kind": x.kind, "found_by": "tool model",
                                 "code": _code(x.modules, PATHS_SHOWN) or "—",
                                 "stores": stores_in(x.modules),
                                 "flows": "; ".join(flows) or "—"})
    usage = inp.ai_usage
    if usage is not None:
        providers: dict[str, dict] = {}
        for s in usage.services:
            p = providers.setdefault(s.provider, {"hosting": s.hosting, "paths": []})
            if s.path not in p["paths"]:
                p["paths"].append(s.path)
        for name, p in sorted(providers.items()):
            destinations.append({"name": name, "kind": f"AI model provider ({p['hosting']})",
                                 "found_by": "ai_usage scanner",
                                 "code": _code(p["paths"], PATHS_SHOWN),
                                 "stores": stores_in(p["paths"]), "flows": "—"})
    more = len(destinations) - DESTINATION_ROWS
    return {"rows": rows, "classes": len(rows), "fields": len(sd.fields),
            "structures": sd.structures_read, "files": sd.files_read,
            "overridden": sd.patterns_overridden,
            "destinations": destinations[:DESTINATION_ROWS], "more_destinations": max(0, more),
            "tool_model": tm is not None, "ai_usage": usage is not None,
            "unparsed": sd.unparsed, "not_read": sd.not_read}


def build_requirements_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    req = inp.requirements
    base = {"tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
            "generated_at": generated_at(), "req": req, "analysis_mode": analysis_mode(inp),
            "sensitive": sensitive_context(inp), "diagrams": {}}
    if req is None:  # no model analysis: the sensitive data section alone (UNVAR-100)
        assert inp.sensitive_data is not None, "requirements.md needs capabilities.json"
        # That page shows none of the template's prose blocks: never ask a model for them.
        return {**base, "prose_facts": {}, "no_prose": True}
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
    return {**base, "capabilities": caps,
            "implicit_count": sum(1 for c in caps if c.implicit), "data_rows": data_rows,
            "prose_facts": prose_facts}
