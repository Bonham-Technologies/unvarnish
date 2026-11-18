from __future__ import annotations

import re

from unvarnish.analysis.effort import effort_counts
from unvarnish.analysis.languages import Classification
from unvarnish.render.findings import ai_indicators, is_history, merged_findings
from unvarnish.scanners.client_exposure import exposure_counts
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    IntegrationEntry,
    IntegrationGrouping,
    IntegrationItem,
    IntegrationRow,
    MatrixCell,
    MatrixRow,
    RiskRow,
    ToolSummary,
)
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import Capability, ToolModel
from unvarnish.schemas.verify import ModelFindings

_EDGE_PUNCT = re.compile(r"^[\W_]+|[\W_]+$")


def normalise_name(s: str) -> str:
    return _EDGE_PUNCT.sub("", " ".join(s.lower().split()))


def capability_label(c: Capability) -> str:
    return f"{c.actor} can {c.action} {c.object}"


def build_matrix(norm: CapabilityNormalisation | None,
                 caps_by_tool: dict[str, list[Capability]]) -> tuple[list[MatrixRow], int, int]:
    """Matrix rows from the model's grouping; unplaced capabilities become their own rows.

    Returns (rows, unmapped capability count, dropped unknown-reference count). Every row has
    exactly one cell per tool, in `caps_by_tool` order, so the table renders rectangular.
    """
    tools = list(caps_by_tool)
    by_id = {(t, c.id): c for t, caps in caps_by_tool.items() for c in caps}
    placed: set[tuple[str, str]] = set()
    rows: list[MatrixRow] = []
    dropped = 0
    for group in (norm.capabilities if norm else []):
        members: dict[str, list[str]] = {t: [] for t in tools}
        for ref in group.members:
            cap = by_id.get((ref.tool, ref.capability_id))
            if cap is None or (ref.tool, ref.capability_id) in placed:
                dropped += 1
                continue
            placed.add((ref.tool, ref.capability_id))
            members[ref.tool].append(capability_label(cap))
        if not any(members.values()):
            continue
        rows.append(MatrixRow(
            name=group.name, description=group.description, actor=group.actor,
            cells=[MatrixCell(tool=t, labels=members[t]) for t in tools],
            tools_covering=sum(1 for t in tools if members[t])))
    unmapped = 0
    for t in tools:
        for cap in caps_by_tool[t]:
            if (t, cap.id) in placed:
                continue
            unmapped += 1
            rows.append(MatrixRow(
                name=capability_label(cap), description=cap.description, actor=cap.actor,
                cells=[MatrixCell(tool=u, labels=[capability_label(cap)] if u == t else [])
                       for u in tools],
                tools_covering=1, unmapped=True))
    return rows, unmapped, dropped


def integration_items(models: dict[str, ToolModel]) -> list[IntegrationItem]:
    out: list[IntegrationItem] = []
    for tool, tm in models.items():
        n = 0
        for s in tm.data_stores:
            n += 1
            out.append(IntegrationItem(id=f"{tool}#{n}", tool=tool, category="data_store",
                                       name=s.name.strip(), kind=s.kind,
                                       description=s.description))
        for x in tm.external_systems:
            n += 1
            out.append(IntegrationItem(id=f"{tool}#{n}", tool=tool, category="external_system",
                                       name=x.name.strip(), kind=x.kind, direction=x.direction,
                                       description=x.description))
    return out


def integration_map(models: dict[str, ToolModel],
                    grouping: IntegrationGrouping | None = None) -> list[IntegrationRow]:
    """Stores and external systems joined across tools; shared first. With a model grouping,
    entries join by group (tools name one store differently) and internal state is left out;
    otherwise, and for entries no group claims, they join by normalised name."""
    items = integration_items(models)
    by_id = {i.id: i for i in items}
    rows: dict[tuple[str, str], IntegrationRow] = {}
    claimed: set[str] = set()

    def add(key: tuple[str, str], name: str, category: str, item: IntegrationItem) -> None:
        row = rows.get(key)
        if row is None:
            row = rows[key] = IntegrationRow(name=name, category=category,  # type: ignore[arg-type]
                                             entries=[], tools=[])
        row.entries.append(IntegrationEntry(tool=item.tool, kind=item.kind,
                                            direction=item.direction,
                                            description=item.description))
        if item.tool not in row.tools:
            row.tools.append(item.tool)

    for g in (grouping.groups if grouping else []):
        members = [by_id[m] for m in g.members if m in by_id and m not in claimed]
        if not members:
            continue
        claimed.update(m.id for m in members)
        if g.internal:
            continue
        cats = [m.category for m in members]
        category = max(set(cats), key=cats.count)
        for m in members:
            add(("group", g.name.lower()), g.name.strip(), category, m)
    for item in items:
        if item.id not in claimed:
            add((item.category, normalise_name(item.name)), item.name, item.category, item)
    return sorted(rows.values(), key=lambda r: (-len(r.tools), r.category, r.name.lower()))


def risk_row(tool: str, census: Census, metrics: Metrics, git: GitStats, scan: ScannerFindings,
             model_findings: ModelFindings | None, deps: Dependencies, *,
             model_analysed: bool | None = None) -> RiskRow:
    """One tool's "by the numbers" row. `model_analysed` means a tool model exists (the same
    gate the matrix and proposal use); it defaults to whether model findings exist."""
    live = [f for f in census.files if not f.excluded]
    findings = merged_findings(scan.findings, model_findings.findings if model_findings else [])
    by_sev = {sev.value: n for sev in Severity
              if (n := sum(1 for f in findings if f.severity == sev))}
    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    history = [f for f in secrets if is_history(f)]
    exposure = (exposure_counts(scan.findings) if "client_exposure" in scan.scanners_run
                else {"credentials": None, "open_tables": None})
    return RiskRow(
        tool=tool,
        model_analysed=(model_findings is not None if model_analysed is None
                        else model_analysed),
        files_analysed=sum(1 for f in live if f.classification != Classification.binary),
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        largest_file_lines=max((m.lines for m in metrics.files), default=0),
        tests_present=any(f.classification == Classification.test for f in live),
        secrets_current=len(secrets) - len(history), secrets_history=len(history),
        bus_factor=git.bus_factor, top_author_share=git.top_author_share,
        findings_by_severity=by_sev,
        critical_or_high=by_sev.get("critical", 0) + by_sev.get("high", 0),
        ai_indicators=len(ai_indicators(git)),
        dependency_vulnerabilities=len(deps.advisories) if deps.advisories_checked else None,
        client_exposed_credentials=exposure["credentials"], open_tables=exposure["open_tables"],
        findings_by_effort=effort_counts(findings),
    )


def tool_summary(tool: str, tm: ToolModel | None, census: Census) -> ToolSummary:
    live = [f for f in census.files if not f.excluded]
    return ToolSummary(
        tool=tool, purpose=tm.purpose if tm else None,
        actors=[a.name for a in tm.actors] if tm else [],
        capabilities=len(tm.capabilities) if tm else 0,
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        model_analysed=tm is not None,
    )
