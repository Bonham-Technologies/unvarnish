from __future__ import annotations

from unvarnish.phases.base import ToolContext
from unvarnish.render.diagram import context_diagram, module_diagram, to_mermaid
from unvarnish.render.findings import ai_indicators, analysis_mode, generated_at
from unvarnish.render.inputs import RenderInputs

TOP_AUTHORS = 5
HARDCODED_ROWS = 30
AI_ROWS = 40


def module_mermaid_or_none(tm, diagram=None) -> str | None:
    """The module diagram, or None when the tool model has no module map to draw."""
    if not tm.module_map:
        return None
    return to_mermaid(diagram if diagram is not None else module_diagram(tm))


def build_architecture_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    tm = inp.tool_model
    assert tm is not None, "architecture.md needs tool.json"
    digests = {d.path: d for d in inp.modules.modules} if inp.modules else {}
    module_rows = []
    for m in tm.module_map:
        d = digests.get(m.path)
        module_rows.append({"path": m.path, "role": m.role, "depends_on": m.depends_on,
                            "units": d.units if d else None, "lines": d.lines if d else None,
                            "findings": d.findings if d else None})
    ctx_diagram = context_diagram(tm)
    mod_diagram = module_diagram(tm)
    units = inp.units
    st = inp.extract_state
    coverage = {
        "units_total": len(units.units) if units else 0,
        "units_done": st.units_done if st else 0,
        "units_failed": st.units_failed if st else 0,
        "windowed": sum(1 for u in units.units if u.split_method == "windowed") if units else 0,
        "modules_rolled": len(inp.modules.modules) if inp.modules else 0,
        "modules_failed": len(inp.modules.failed) if inp.modules else 0,
        "modules_without_units": len(inp.modules.skipped) if inp.modules else 0,
        "skipped_split": len(units.skipped) if units else 0,
    }
    hardcoded = []
    for f in inp.scan.findings:
        kind = next((t.split(":", 1)[1] for t in f.tags if t.startswith("hardcoded:")), None)
        if kind is None:
            continue
        for e in f.evidence:
            if len(hardcoded) >= HARDCODED_ROWS:
                break
            hardcoded.append({"kind": kind, "value": (e.note or "").removeprefix("value: "),
                              "location": f"{e.path}:{e.line_start}"})
    ai_services = _ai_services(inp)
    git = inp.git
    languages = sorted(inp.census.languages.items(), key=lambda kv: -kv[1])[:8]
    indicators = ai_indicators(git)
    prose_facts = {
        "purpose_and_users": {
            "tool": ctx.meta.name, "purpose": tm.purpose,
            "actors": [a.model_dump() for a in tm.actors],
            "entry_points": [e.model_dump() for e in tm.entry_points],
            "capabilities_count": len(tm.capabilities),
        },
        "deployment": {
            "deployment_assumptions": tm.deployment_assumptions,
            "internal_stack": tm.internal_stack,
            "frameworks_detected": inp.census.frameworks, "languages": dict(languages),
            "external_systems": [s.model_dump(exclude={"modules"})
                                 for s in tm.external_systems],
            "data_stores": [s.model_dump(exclude={"modules"}) for s in tm.data_stores],
        },
        "build_history": {
            "available": git.available, "reason": git.reason,
            "commit_count": git.commit_count,
            "first_commit": git.first_commit.date().isoformat() if git.first_commit else None,
            "last_commit": git.last_commit.date().isoformat() if git.last_commit else None,
            "active_days": git.active_days,
            "authors": [{"name": a.name, "commits": a.commits, "share": round(a.share, 2)}
                        for a in git.authors[:TOP_AUTHORS]],
            "author_count": len(git.authors), "bot_count": len(git.bots),
            "bus_factor": git.bus_factor, "top_author_share": git.top_author_share,
            "large_commits": len(git.large_commits),
            "large_commit_threshold": git.large_commit_threshold,
            "ai_tooling_indicators": indicators,
        },
    }
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "tm": tm, "census": inp.census, "deps": inp.deps,
        "git": git, "languages": languages, "module_rows": module_rows,
        "context_mermaid": to_mermaid(ctx_diagram),
        "module_mermaid": module_mermaid_or_none(tm, mod_diagram),
        "module_diagram_note": mod_diagram.note,
        "diagrams": {"context": ctx_diagram, "modules": mod_diagram},
        "coverage": coverage, "ai_indicators": indicators, "hardcoded": hardcoded,
        "ai_services": ai_services,
        "analysis_mode": analysis_mode(inp), "prose_facts": prose_facts,
    }


def _ai_services(inp: RenderInputs) -> dict | None:
    """The AI services table (UNVAR-91), from ai-usage.json alone; None when not checked."""
    usage = inp.ai_usage
    if usage is None:
        return None
    rows = [{"provider": s.provider + (f" (via {s.via})" if s.via else ""),
             "model": s.model, "location": f"{s.path}:{s.line}", "hosting": s.hosting}
            for s in sorted(usage.services, key=lambda s: (s.provider, s.path, s.line))]
    tools = [f"`{t.path}:{t.line}` ({t.kind}{f' `{t.name}`' if t.name else ''})"
             for t in usage.tool_definitions]
    more = len(rows) - AI_ROWS
    return {"rows": rows[:AI_ROWS], "more": more if more > 0 else 0,
            "tools": tools[:AI_ROWS], "more_tools": max(0, len(tools) - AI_ROWS)}
