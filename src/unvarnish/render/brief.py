"""The leadership brief across every tool (UNVAR-99): comparison/brief.md.

Every number is counted here from each tool's own artifacts (census, scanner findings, model
findings, dependencies, delta), with the same helpers the per-tool findings documents and the
comparison's risk table use, so a total in the brief is the sum of what each tool's documents
show. The only model call is the optional prose block."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from unvarnish.analysis.comparison import risk_row
from unvarnish.analysis.effort import (
    NOT_ESTIMATED,
    day_range,
    effort_counts,
    effort_text,
    fmt_days,
)
from unvarnish.config import EffortDays
from unvarnish.engagement import Engagement
from unvarnish.render.comparison import tool_trends
from unvarnish.render.findings import exploit_rank, generated_at, merged_findings
from unvarnish.scanners.end_of_life import eol_counts
from unvarnish.schemas.finding import SEVERITY_ORDER, Effort, Finding, Severity, Source

if TYPE_CHECKING:
    from unvarnish.phases.compare import ToolInputs

TOP_FINDINGS = 10
SEVERITIES = [s.value for s in Severity]


@dataclass(frozen=True)
class ActionBucket:
    key: str
    label: str
    rule: str


ACTION_BUCKETS = (
    ActionBucket("fix_now", "Fix now",
                 "Critical findings, whatever the effort; high findings with effort S or M, "
                 "or not estimated"),
    ActionBucket("before_scaling", "Fix before scaling",
                 "High findings with effort L or XL; medium findings, whatever the effort"),
    ActionBucket("accept", "Accept",
                 "Low and info findings: accept the risk on record, or fix them when the code "
                 "is next changed"),
)
LARGE_BANDS = (Effort.L, Effort.XL)


def action_bucket(severity: Severity, effort: Effort | None) -> str:
    """The action-plan bucket for one finding, from its severity and effort band alone
    (documented in docs/operations.md, ruling in docs/decisions.md)."""
    if severity == Severity.critical:
        return "fix_now"
    if severity == Severity.high:
        return "before_scaling" if effort in LARGE_BANDS else "fix_now"
    if severity == Severity.medium:
        return "before_scaling"
    return "accept"


def days_cell(counts: dict[str, int], days: EffortDays | None) -> str | None:
    """"2.5–9 engineer-days; 3 not estimated" for a table cell; None without a day mapping or
    without findings, so the cell falls back to effort_text's "no findings", not "0–0"."""
    if days is None or not sum(counts.values()):
        return None
    low, high = day_range(counts, days)
    text = f"{fmt_days(low)}–{fmt_days(high)} engineer-days"
    if counts.get(NOT_ESTIMATED):
        text += f"; {counts[NOT_ESTIMATED]} not estimated"
    return text


def _sum(counts: Sequence[dict[str, int]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in counts:
        for k, v in c.items():
            out[k] = out.get(k, 0) + v
    return out


def _checked_total(values: list[int | None], tools: int) -> dict | None:
    """The sum over the tools that were checked, and how many were; None when none was."""
    checked = [v for v in values if v is not None]
    if not checked:
        return None
    return {"count": sum(checked), "checked": len(checked), "tools": tools}


def _tool_row(i: ToolInputs, days: EffortDays | None) -> tuple[dict, list[Finding]]:
    findings = merged_findings(i.scan.findings,
                               i.model_findings.findings if i.model_findings else [])
    risk = risk_row(i.tool, i.census, i.metrics, i.git, i.scan, i.model_findings, i.deps,
                    model_analysed=i.model_findings is not None)
    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    effort = effort_counts(findings)
    eol = (eol_counts(i.scan.findings)
           if "end_of_life" in i.scan.scanners_run and i.deps.eol_data_date else None)
    kev = (sum(1 for a in i.deps.advisories if a.get("kev"))
           if i.deps.exploit_data_date and i.deps.advisories_checked else None)
    buckets = {b.key: 0 for b in ACTION_BUCKETS}
    bucket_effort: dict[str, list[Finding]] = {b.key: [] for b in ACTION_BUCKETS}
    for f in findings:
        key = action_bucket(f.severity, f.effort)
        buckets[key] += 1
        bucket_effort[key].append(f)
    row = {
        "tool": i.tool, "model_analysed": i.model_findings is not None,
        "files": risk.files_analysed, "by_severity": by_sev, "total": len(findings),
        "secrets_current": risk.secrets_current, "secrets_history": risk.secrets_history,
        "exposed": risk.client_exposed_credentials, "eol": eol, "kev": kev,
        "effort": effort, "effort_text": days_cell(effort, days) or effort_text(effort),
        "buckets": buckets,
        "bucket_effort": {k: effort_counts(v) for k, v in bucket_effort.items()},
    }
    return row, findings


def _location(f: Finding) -> str | None:
    ev = f.evidence[0]
    if ev.path in (".", ""):
        return None  # a finding about the whole tool, such as its authorship
    return f"{ev.path}:{ev.line_start}" if ev.line_start else ev.path


def build_brief_context(eng: Engagement, inputs: list[ToolInputs], not_run: list[str]) -> dict:
    days = eng.config.report.effort_days
    rows: list[dict] = []
    pooled: list[tuple[int, str, Finding]] = []
    for n, i in enumerate(inputs):
        row, findings = _tool_row(i, days)
        rows.append(row)
        pooled += [(n, i.tool, f) for f in findings]
    tools = [r["tool"] for r in rows]
    trends = tool_trends(eng, tools)
    for r in rows:
        r["trend"] = trends.get(r["tool"])

    by_sev = _sum([r["by_severity"] for r in rows])
    effort = _sum([r["effort"] for r in rows])
    totals = {
        "tools": len(rows), "files": sum(r["files"] for r in rows),
        "findings": sum(r["total"] for r in rows), "by_severity": by_sev,
        "secrets_current": sum(r["secrets_current"] for r in rows),
        "secrets_history": sum(r["secrets_history"] for r in rows),
        "exposed": _checked_total([r["exposed"] for r in rows], len(rows)),
        "eol_past": _checked_total([r["eol"]["past"] if r["eol"] else None for r in rows],
                                   len(rows)),
        "eol_near": _checked_total([r["eol"]["near"] if r["eol"] else None for r in rows],
                                   len(rows)),
        "kev": _checked_total([r["kev"] for r in rows], len(rows)),
        "effort_bands": effort_text(effort),
        "effort_days": days_cell(effort, days),
    }

    pooled.sort(key=lambda t: (SEVERITY_ORDER[t[2].severity], exploit_rank(t[2]),
                               0 if t[2].source == Source.scanner else 1, t[0],
                               t[2].evidence[0].path, t[2].evidence[0].line_start or 0,
                               t[2].title))
    top = [{"severity": f.severity.value, "title": f.title, "tool": tool,
            "location": _location(f),
            "effort": f.effort.value if f.effort else "not estimated",
            "known_exploited": any(e.kev for e in (f.exploits or []))}
           for _, tool, f in pooled[:TOP_FINDINGS]]

    plan = []
    for b in ACTION_BUCKETS:
        counts = _sum([r["bucket_effort"][b.key] for r in rows])
        plan.append({
            "label": b.label, "rule": b.rule, "count": sum(r["buckets"][b.key] for r in rows),
            "by_tool": [(r["tool"], r["buckets"][b.key]) for r in rows if r["buckets"][b.key]],
            "effort": days_cell(counts, days) or effort_text(counts)})

    scanner_only = [r["tool"] for r in rows if not r["model_analysed"]]
    prose_facts = {"portfolio_summary": {
        "client": eng.config.client,
        "tools_reviewed": tools, "tools_not_reviewed": not_run,
        "findings": {"total": totals["findings"], "by_severity": by_sev},
        "tools": [{"tool": r["tool"], "critical_or_high":
                   r["by_severity"]["critical"] + r["by_severity"]["high"],
                   "model_analysed": r["model_analysed"], "effort_to_fix": r["effort_text"],
                   "trend": r["trend"]} for r in rows],
        "credential_like_values": {"working_tree": totals["secrets_current"],
                                   "git_history_only": totals["secrets_history"]},
        "end_of_life_runtimes": (totals["eol_past"] or {}).get("count"),
        "known_exploited_advisories": (totals["kev"] or {}).get("count"),
        "action_plan": {p["label"]: p["count"] for p in plan},
        "highest_findings": [{k: t[k] for k in ("severity", "title", "tool")} for t in top],
    }}
    return {
        "client": eng.config.client, "consultant": eng.config.consultant,
        "generated_at": generated_at(), "tools": tools, "not_run": not_run,
        "scanner_only": scanner_only, "severities": SEVERITIES, "totals": totals,
        "rows": rows, "trends": bool(trends), "top": top, "plan": plan,
        "days": days is not None, "prose_facts": prose_facts,
    }
