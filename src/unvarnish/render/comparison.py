from __future__ import annotations

import logging

from unvarnish.analysis.effort import days_text, effort_text
from unvarnish.artifacts import read_artifact
from unvarnish.config import EffortDays
from unvarnish.engagement import Engagement
from unvarnish.render.diagram import Diagram, Edge, Node, to_mermaid
from unvarnish.render.findings import generated_at
from unvarnish.schemas.comparison import Comparison
from unvarnish.schemas.delta import Delta

log = logging.getLogger("unvarnish.compare")


def integration_diagram(cmp: Comparison, max_rows: int = 40) -> Diagram:
    rows = cmp.integration_map[:max_rows]
    nodes = [Node(id=f"tool:{t}", label=t, kind="tool") for t in cmp.tools_with_model]
    edges: list[Edge] = []
    for i, r in enumerate(rows):
        nid = f"sys{i}"
        nodes.append(Node(id=nid, label=r.name,
                          kind="store" if r.category == "data_store" else "external"))
        for e in r.entries:
            edges.append(Edge(source=f"tool:{e.tool}", target=nid, label=e.kind))
    note = (f"Showing the {len(rows)} most shared of {len(cmp.integration_map)} systems."
            if len(cmp.integration_map) > max_rows else None)
    return Diagram(title="integration map", nodes=nodes, edges=edges, note=note)


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


def _cost_measures(cmp: Comparison, days: EffortDays | None) -> list[tuple[str, list[str]]]:
    """The cost-to-fix rows (UNVAR-42): bands always, engineer-days only once configured."""
    rows = cmp.risk_table
    out = [("Cost to fix (effort bands)",
            [effort_text(r.findings_by_effort) if r.findings_by_effort else "—" for r in rows])]
    if days is not None:
        out.append(("Cost to fix (engineer-days, estimate)",
                    [days_text(r.findings_by_effort, days) if r.findings_by_effort else "—"
                     for r in rows]))
    return out


def _risk_measures(cmp: Comparison, days: EffortDays | None = None) -> list[dict]:
    rows = cmp.risk_table
    severities = ("critical", "high", "medium", "low", "info")
    measures: list[tuple[str, list[str]]] = [
        ("Model analysis", ["yes" if r.model_analysed else "**no**" for r in rows]),
        ("Files analysed", [f"{r.files_analysed:,}" for r in rows]),
        ("Source lines", [f"{r.source_lines:,}" for r in rows]),
        ("Largest file (lines)", [f"{r.largest_file_lines:,}" for r in rows]),
        ("Automated tests", ["present" if r.tests_present else "**none**" for r in rows]),
        ("Secrets in working tree", [str(r.secrets_current) for r in rows]),
        ("Secrets in history", [str(r.secrets_history) for r in rows]),
        ("Client-exposed credentials / open tables",
         ["not checked" if r.client_exposed_credentials is None
          else f"{r.client_exposed_credentials} / {r.open_tables}" for r in rows]),
        ("Bus factor", ["—" if r.bus_factor is None else str(r.bus_factor) for r in rows]),
        ("Top author share", [_pct(r.top_author_share) for r in rows]),
        ("Critical or high findings", [str(r.critical_or_high) for r in rows]),
    ]
    measures += [(f"Findings: {sev}", [str(r.findings_by_severity.get(sev, 0)) for r in rows])
                 for sev in severities if any(r.findings_by_severity.get(sev) for r in rows)]
    measures += _cost_measures(cmp, days)
    measures += [
        ("AI tooling indicators", [str(r.ai_indicators) for r in rows]),
        ("Dependency vulnerabilities", ["not checked" if r.dependency_vulnerabilities is None
                                        else str(r.dependency_vulnerabilities) for r in rows]),
    ]
    return [{"label": label, "cells": values} for label, values in measures]


def trend_text(delta: Delta) -> str:
    """One tool's trend since the previous review, for the comparison's tools table."""
    c = delta.counts()
    net = c["new"] - c["resolved"]
    word = ("no change" if not (c["new"] or c["resolved"]) else
            "improved" if net < 0 else "worsened" if net > 0 else "level")
    detail = f"{c['resolved']} resolved, {c['new']} new"
    if c["accepted"]:
        detail += f", {c['accepted']} risk accepted"
    return f"{word} ({detail})"


def tool_trends(eng: Engagement, tools: list[str]) -> dict[str, str]:
    """Trend text per tool that has a delta (`run --baseline`, UNVAR-40); empty without one,
    so the document is unchanged."""
    out: dict[str, str] = {}
    for tool in tools:
        path = eng.tool_paths(tool).delta
        if not path.exists():
            continue
        try:
            out[tool] = trend_text(read_artifact(path, Delta).data)
        except Exception as exc:  # an unreadable delta costs its cell, not the document
            log.warning("ignoring unreadable %s for %s: %r", path.name, tool, exc)
    return out


def build_comparison_context(eng: Engagement, cmp: Comparison) -> dict:
    integration = integration_diagram(cmp)
    matrix_rows = [{
        "name": r.name, "actor": r.actor, "unmapped": r.unmapped, "covered": r.tools_covering,
        "cells": ["; ".join(c.labels) if c.labels else "—" for c in r.cells],
    } for r in cmp.capability_matrix]
    analysis_mode = f"{cmp.backend}/{cmp.model}" if cmp.backend else "scanners only"
    prose_facts = {
        "tools_reviewed": {
            "client": eng.config.client,
            "tools": [s.model_dump() for s in cmp.summaries],
            "risk": [r.model_dump() for r in cmp.risk_table],
        },
        "consolidation_proposal": {
            "tools": [s.tool for s in cmp.summaries],
            "consolidation": cmp.consolidation.model_dump() if cmp.consolidation else None,
            "constraints": cmp.constraints.model_dump() if cmp.constraints else None,
            "shared_capabilities": [r.name for r in cmp.capability_matrix
                                    if r.tools_covering > 1],
            "single_tool_capabilities": [r.name for r in cmp.capability_matrix
                                         if r.tools_covering == 1],
            "shared_systems": [r.name for r in cmp.integration_map if len(r.tools) > 1],
        },
    }
    return {
        "client": eng.config.client, "consultant": eng.config.consultant,
        "generated_at": generated_at(), "cmp": cmp, "tools": cmp.tools,
        "matrix_tools": cmp.tools_with_model, "matrix_rows": matrix_rows,
        "risk_measures": _risk_measures(cmp, eng.config.report.effort_days),
        "integration_mermaid": to_mermaid(integration), "diagrams": {"integration": integration},
        "analysis_mode": analysis_mode, "prose_facts": prose_facts,
        "trends": tool_trends(eng, cmp.tools),
    }
