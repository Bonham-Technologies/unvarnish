from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from pydantic import BaseModel

from unvarnish.analysis.comparison import capability_label
from unvarnish.analysis.effort import days_text, effort_text
from unvarnish.config import ConsolidationConstraints, EffortDays
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    Consolidation,
    IntegrationGrouping,
    IntegrationItem,
    IntegrationRow,
    MatrixRow,
    RiskRow,
    ToolSummary,
)
from unvarnish.schemas.toolmodel import Capability

COMPARE_PROMPT_VERSION = "2026-11-10.1"  # bump whenever either compare prompt changes
NORMALISE_MAX_TOKENS = 16_000
CONSOLIDATE_MAX_TOKENS = 16_000
INTEGRATE_MAX_TOKENS = 8_000
MAX_CAPABILITIES_PER_TOOL = 150  # normalisation input per tool
DESCRIPTION_CHARS = 300


@cache
def _system(template_name: str, schema_cls: type[BaseModel]) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath(template_name)
                .read_text(encoding="utf-8"))
    return template.replace("{{SCHEMA}}", json.dumps(strict_schema(schema_cls), indent=1,
                                                     sort_keys=True))


def build_normalise_system() -> str:
    return _system("compare_normalise_system.md", CapabilityNormalisation)


def build_consolidate_system() -> str:
    return _system("compare_consolidate_system.md", Consolidation)


def build_integrate_system() -> str:
    return _system("compare_integrate_system.md", IntegrationGrouping)


def build_integrate_request(items: Sequence[IntegrationItem], effort: str | None,
                            system: str | None = None) -> CompletionRequest:
    lines = ["id | tool | category | kind | name | description"]
    for i in items:
        desc = " ".join(i.description.split())[:DESCRIPTION_CHARS]
        lines.append(f"{i.id} | {i.tool} | {i.category} | {i.kind} | {i.name} | {desc}")
    return CompletionRequest(system=system or build_integrate_system(),
                             messages=[Message(role="user", content="\n".join(lines))],
                             schema_name="IntegrationGrouping", effort=effort,
                             cache_system=True, max_tokens=INTEGRATE_MAX_TOKENS)


def capability_line(tool: str, c: Capability) -> str:
    desc = " ".join(c.description.split())[:DESCRIPTION_CHARS]
    flag = "implicit" if c.implicit else "designed"
    return f"{tool} | {c.id} | {capability_label(c)} | {desc} | {flag}"


def build_normalise_request(caps_by_tool: dict[str, list[Capability]], effort: str | None,
                            system: str | None = None) -> CompletionRequest:
    parts: list[str] = []
    for tool, caps in caps_by_tool.items():
        parts.append(f"## {tool} ({len(caps)} capabilities)")
        parts.extend(capability_line(tool, c) for c in caps[:MAX_CAPABILITIES_PER_TOOL])
        if len(caps) > MAX_CAPABILITIES_PER_TOOL:
            parts.append(f"(+{len(caps) - MAX_CAPABILITIES_PER_TOOL} more not sent)")
        parts.append("")
    return CompletionRequest(system=system or build_normalise_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="CapabilityNormalisation", effort=effort,
                             cache_system=True, max_tokens=NORMALISE_MAX_TOKENS)


def constraints_text(c: ConsolidationConstraints) -> str:
    lines = ["## Consultant constraints",
             "(Set by the consultant. Work within them; they are not material under review.)"]
    if c.target_platform:
        lines.append(f"- Target platform: {c.target_platform}")
    if c.approved_stack:
        lines.append(f"- Approved stack: {', '.join(c.approved_stack)}")
    if c.must_keep:
        lines.append(f"- Must keep: {'; '.join(c.must_keep)}")
    if c.retire:
        lines.append(f"- Retire: {'; '.join(c.retire)}")
    if c.notes:
        lines.append(f"- Notes: {c.notes}")
    return "\n".join(lines)


def cost_text(risk: Sequence[RiskRow], days: EffortDays | None) -> str:
    """Each tool's findings by remediation-effort band, counted from the analysis (UNVAR-42)."""
    lines = ["## Cost to fix",
             "(Counted from each tool's findings, not estimated by you. Bands: S up to half a "
             "day, M up to two days, L up to a week, XL weeks.)"]
    for r in risk:
        if not r.findings_by_effort:
            continue
        line = f"- {r.tool}: {effort_text(r.findings_by_effort)}"
        if days is not None:
            line += f"; {days_text(r.findings_by_effort, days)} engineer-days (estimate)"
        lines.append(line)
    return "\n".join(lines)


def build_consolidate_request(summaries: Sequence[ToolSummary], matrix: Sequence[MatrixRow],
                              integration: Sequence[IntegrationRow], effort: str | None,
                              system: str | None = None, *,
                              constraints: ConsolidationConstraints | None = None,
                              risk: Sequence[RiskRow] = (),
                              effort_days: EffortDays | None = None,
                              ) -> CompletionRequest:
    parts = ["## Tools"]
    for s in summaries:
        actors = ", ".join(s.actors) or "unknown actors"
        parts.append(f"- {s.tool}: {s.purpose or 'purpose not analysed'} (actors: {actors}; "
                     f"{s.capabilities} capabilities; {s.source_lines:,} source lines)")
    parts += ["", "## Capability matrix"]
    for row in matrix:
        cells = "; ".join(f"{c.tool}: {', '.join(c.labels) if c.labels else '-'}"
                          for c in row.cells)
        flag = " (unmapped: one tool only)" if row.unmapped else ""
        parts.append(f"- {row.name} [{row.actor}]{flag}: {row.description} | {cells}")
    parts += ["", "## Integration and data map"]
    for r in integration:
        parts.append(f"- {r.name} [{r.category}]: {', '.join(r.tools)}")
        parts.extend(f"  - {e.tool}: {e.kind}{' ' + e.direction if e.direction else ''}; "
                     f"{' '.join(e.description.split())[:DESCRIPTION_CHARS]}"
                     for e in r.entries)
    if any(r.findings_by_effort for r in risk):
        parts += ["", cost_text(risk, effort_days)]
    if constraints is not None and not constraints.is_empty():
        parts += ["", constraints_text(constraints)]
    return CompletionRequest(system=system or build_consolidate_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="Consolidation", effort=effort, cache_system=True,
                             max_tokens=CONSOLIDATE_MAX_TOKENS)
