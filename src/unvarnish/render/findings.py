from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from unvarnish.analysis.effort import (
    BANDS,
    NOT_ESTIMATED,
    day_range,
    effort_counts,
    fmt_days,
)
from unvarnish.analysis.languages import Classification
from unvarnish.config import EffortDays
from unvarnish.phases.base import ToolContext
from unvarnish.render.inputs import RenderInputs
from unvarnish.scanners.client_exposure import exposure_counts
from unvarnish.scanners.end_of_life import data_age_warning, eol_counts
from unvarnish.schemas.delta import Delta, DeltaEntry, DeltaStatus
from unvarnish.schemas.finding import SEVERITY_ORDER, Finding, Severity, Source, Verification
from unvarnish.schemas.git import GitStats
from unvarnish.util.plural import plural

EXAMPLES_PER_REASON = 5
HEADLINE_FINDINGS = 12
FAILED_UNITS_SHOWN = 10
TOO_LARGE_BYTES = 5_000_000


def _severity_groups(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    groups: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.severity].append(f)
    return [(sev.value, groups[sev]) for sev in sorted(groups, key=SEVERITY_ORDER.__getitem__)]


def _compact(detail_from: str) -> list[str]:
    """Severities rendered one row each: everything below `detail_from`."""
    floor = SEVERITY_ORDER[Severity(detail_from)]
    return [s.value for s in Severity if SEVERITY_ORDER[s] > floor]


def merged_findings(scan: list[Finding], model: list[Finding]) -> list[Finding]:
    """Scanner and live model findings, by severity; scanner first at equal severity."""
    live = [f for f in model if f.verification != Verification.rejected]
    return sorted([*scan, *live], key=lambda f: (
        SEVERITY_ORDER[f.severity], 0 if f.source == Source.scanner else 1,
        f.evidence[0].path, f.evidence[0].line_start or 0))


def ai_indicators(git: GitStats) -> list[str]:
    ai = git.ai_fingerprints
    out = list(ai.files) + [f"Co-Authored-By {name} ×{n}" for name, n in
                            ai.coauthor_trailers.items()]
    if ai.message_patterns:
        verb = "mentions" if ai.message_patterns == 1 else "mention"
        out.append(f"{plural(ai.message_patterns, 'commit message')} {verb} AI generation")
    return out


UNKNOWN_PURPOSE = ("not known: the tool-level analysis did not complete, so do not describe "
                   "what the tool does or who uses it beyond what the other facts show")


def is_history(f: Finding) -> bool:
    """A secret found only in git history (tagged by the secrets scanner)."""
    return "history" in f.tags or f.title.endswith("in git history")  # older artifacts


SEVERITY_WORDS = ("critical", "high", "medium", "low")


def vulnerability_text(advisories: list[dict]) -> str:
    """"9 (2 high, 7 medium)": the count with its severity breakdown (spec 8.4)."""
    if not advisories:
        return "0"
    counts = {s: sum(1 for a in advisories if (a.get("severity") or "medium") == s)
              for s in SEVERITY_WORDS}
    parts = [f"{n} {s}" for s, n in counts.items() if n]
    return f"{len(advisories)} ({', '.join(parts)})"


def hardcoded_counts(findings: list[Finding]) -> dict[str, int]:
    """Distinct hardcoded values per kind, from the hardcoded_infra findings' tags."""
    counts: dict[str, int] = {}
    for f in findings:
        kind = next((t.split(":", 1)[1] for t in f.tags if t.startswith("hardcoded:")), None)
        distinct = next((t.split(":", 1)[1] for t in f.tags if t.startswith("distinct:")), "0")
        if kind:
            counts[kind] = int(distinct)
    return counts


def analysis_mode(inp: RenderInputs) -> str:
    if inp.extract_state is None:
        return "scanners only"
    return f"{inp.extract_state.backend}/{inp.extract_state.model}"


def generated_at() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def model_gaps(inp: RenderInputs) -> dict:
    units = inp.units
    windowed = [u.path for u in units.units if u.split_method == "windowed"] if units else []
    failed_units = [f for f in (inp.failures.items if inp.failures else [])
                    if f.phase == "extract"]
    failed_chunks = list(inp.tool_model.chunks_failed) if inp.tool_model else []
    for f in (inp.failures.items if inp.failures else []):
        if f.phase == "rollup_tool" and f.unit_id and f.unit_id.startswith("chunk"):
            label = f.unit_id.split(":", 1)[-1]
            if label not in failed_chunks:
                failed_chunks.append(label)
    tool_rollup_failed = any(
        f.phase == "rollup_tool" and f.unit_id == "tool"
        for f in (inp.failures.items if inp.failures else []))
    return {
        "failed_chunks": failed_chunks,
        "tool_rollup_failed": tool_rollup_failed,
        "windowed": {"count": len(windowed),
                     "examples": list(dict.fromkeys(windowed))[:EXAMPLES_PER_REASON]},
        "failed_units": [{"path": f.path, "error": f.error} for f in
                         failed_units[:FAILED_UNITS_SHOWN]],
        "failed_units_count": len(failed_units),
        "failed_modules": list(inp.modules.failed) if inp.modules else [],
        "modules_without_units": list(inp.modules.skipped) if inp.modules else [],
        # Files over 5 MB are listed once, under "Files too large to scan".
        "skipped_split": [s.model_dump() for s in units.skipped
                          if not s.reason.startswith("larger than")] if units else [],
        "too_large": [{"path": f.path, "size": f"{f.bytes / 1_000_000:.1f} MB"}
                      for f in inp.census.files
                      if not f.excluded and f.classification != Classification.binary
                      and f.bytes > TOO_LARGE_BYTES],
        "rejected": inp.model_findings.rejected if inp.model_findings else 0,
    }


def remediation_outlook(findings: list[Finding], days: EffortDays | None) -> dict:
    """The "Remediation outlook" table: findings by effort band and severity, counted from the
    findings themselves; engineer-days only when `report.effort_days` is set (UNVAR-42)."""
    rows = []
    for sev in Severity:
        group = [f for f in findings if f.severity == sev]
        if group:
            rows.append({"severity": sev.value, "counts": effort_counts(group),
                         "total": len(group)})
    totals = effort_counts(findings)
    out: dict = {"bands": BANDS, "rows": rows, "totals": totals, "total": len(findings),
                 "days": None}
    if days is not None:
        low, high = day_range(totals, days)
        out["days"] = {"low": fmt_days(low), "high": fmt_days(high),
                       "not_estimated": totals[NOT_ESTIMATED],
                       "mapping": ", ".join(f"{b} {fmt_days(getattr(days, b))}"
                                            for b in BANDS)}
    return out


def _location(path: str | None, line: int | None) -> str:
    return f"{path}:{line}" if line else (path or "")


def _delta_row(e: DeltaEntry) -> dict:
    f, ev = e.finding, e.finding.evidence[0]
    change = []
    if e.status == DeltaStatus.changed:
        if e.group is not None:  # a group's first member is no location (UNVAR-49)
            if None not in (e.previous_count, e.count) and e.previous_count != e.count:
                change.append(f"count {e.previous_count} → {e.count}")
        elif (e.previous_path, e.previous_line) != (ev.path, ev.line_start):
            change.append(f"moved from `{_location(e.previous_path, e.previous_line)}`")
        if e.previous_severity and e.previous_severity != f.severity:
            change.append(f"re-rated from {e.previous_severity.value}")
    elif e.status == DeltaStatus.accepted:
        change.append("not found in this review" if e.matched_by is None and
                      e.previous_id == f.id else "still present")
    return {"title": f.title, "severity": f.severity.value, "source": f.source.value,
            "location": _location(ev.path, ev.line_start), "id": f.id,
            "change": "; ".join(change)}


def delta_context(delta: Delta | None) -> dict | None:
    """The "Since the previous review" section of findings.md (UNVAR-40); None without a
    baseline, so the document is unchanged."""
    if delta is None:
        return None
    info = delta.baseline
    when = [f"{info.reviewed_at:%Y-%m-%d}"] if info.reviewed_at else []
    if info.commit:
        when.append(f"commit {info.commit[:12]}")

    def rows(status: DeltaStatus) -> list[dict]:
        entries = sorted(delta.of(status), key=lambda e: (
            SEVERITY_ORDER[e.finding.severity], e.finding.evidence[0].path,
            e.finding.evidence[0].line_start or 0))
        return [_delta_row(e) for e in entries]

    by_severity = []
    for sev in Severity:
        counts = {s.value: sum(1 for e in delta.of(s) if e.finding.severity == sev)
                  for s in DeltaStatus}
        if any(counts.values()):
            by_severity.append((sev.value, counts))
    compared = " and ".join(delta.compared_sources)
    return {
        "heading": "Since the previous review" + (f" ({', '.join(when)})" if when else ""),
        "compared": f"{compared} findings" if compared else "no findings",
        "totals": delta.counts(), "by_severity": by_severity,
        "resolved": rows(DeltaStatus.resolved), "new": rows(DeltaStatus.new),
        "changed": rows(DeltaStatus.changed), "accepted": rows(DeltaStatus.accepted),
        "notes": delta.notes, "line_drift": delta.line_drift,
    }


def build_findings_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    census, metrics, git, deps, scan = inp.census, inp.metrics, inp.git, inp.deps, inp.scan
    live = [f for f in census.files if not f.excluded]
    analysed = [f for f in live if f.classification != Classification.binary]
    source_lines = sum(f.lines for f in live if f.classification == Classification.source)
    # Rank application code: a 3,000-line test file is not what "largest file" should mean.
    source_paths = {f.path for f in live if f.classification == Classification.source}
    ranked = [m for m in metrics.files if m.path in source_paths] or metrics.files
    largest = sorted(ranked, key=lambda m: -m.lines)[:5]
    longest = max((m for m in ranked if m.max_function_lines),
                  key=lambda m: m.max_function_lines or 0, default=None)
    languages = sorted(census.languages.items(), key=lambda kv: -kv[1])[:5]

    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    secrets_history = [f for f in secrets if is_history(f)]
    mf = inp.model_findings
    all_findings = merged_findings(scan.findings, mf.findings if mf else [])
    model_live = [f for f in all_findings if f.source == Source.model]
    by_sev = [(sev.value, n) for sev in Severity
              if (n := sum(1 for f in all_findings if f.severity == sev))]

    excluded: dict[str, list[str]] = defaultdict(list)
    for f in census.files:
        if f.excluded and f.exclusion_reason:
            excluded[f.exclusion_reason].append(f.path)
    not_analysed = [
        {"reason": reason, "count": len(paths), "examples": paths[:EXAMPLES_PER_REASON]}
        for reason, paths in sorted(excluded.items())
    ]
    binaries = [f.path for f in live if f.classification == Classification.binary]
    skipped_at_ingest = list(ctx.meta.skipped_at_ingest)
    gaps = model_gaps(inp)
    everything_analysed = not (
        not_analysed or skipped_at_ingest or binaries or census.failures or scan.skipped
        or not git.available or scan.notes or census.notes
        or gaps["windowed"]["count"] or gaps["failed_units_count"] or gaps["failed_modules"]
        or gaps["skipped_split"] or gaps["modules_without_units"] or gaps["failed_chunks"]
        or gaps["too_large"]
        or gaps["tool_rollup_failed"]
    )
    indicators = ai_indicators(git)
    numbers = {
        "total_findings": len(all_findings),
        "by_severity": by_sev,
        "critical_or_high": sum(1 for f in all_findings
                                if f.severity in (Severity.critical, Severity.high)),
        "scanner_findings": len(scan.findings),
        "model_findings": None if mf is None else len(model_live),
        "verification": None if mf is None else {
            "confirmed": mf.confirmed, "downgraded": mf.downgraded,
            "rejected": mf.rejected, "unverified": mf.unverified},
        "analysis_mode": analysis_mode(inp),
        "analysed_files": len(analysed),
        "source_lines": source_lines,
        "largest_files": largest,
        "largest_file": largest[0] if largest else None,
        "longest_function": longest,
        "languages": languages,
        "tests_present": any(f.classification == Classification.test for f in live),
        "secrets_current": len(secrets) - len(secrets_history),
        "secrets_history": len(secrets_history),
        "ai_indicators": indicators,
        "hardcoded": hardcoded_counts(scan.findings),
        "client_exposure": (exposure_counts(scan.findings)
                            if "client_exposure" in scan.scanners_run else None),
        "end_of_life": ({**eol_counts(scan.findings), "date": deps.eol_data_date,
                         "stale": data_age_warning(scan.notes)}
                        if "end_of_life" in scan.scanners_run else None),
    }
    tm = inp.tool_model
    prose_facts = {"executive_summary": {
        "tool": ctx.meta.name, "client": ctx.config.client,
        # Without a tool model the purpose is unknown; saying so stops the prose model
        # inventing one (a 32B model described a landing page as a code-analysis tool).
        "purpose": tm.purpose if tm else UNKNOWN_PURPOSE,
        "actors": [a.name for a in tm.actors] if tm else [],
        "size": {"files_analysed": len(analysed), "source_lines": source_lines,
                 "languages": dict(languages),
                 "largest_file": {"path": largest[0].path, "lines": largest[0].lines}
                 if largest else None},
        "findings": {"total": len(all_findings), "by_severity": dict(by_sev),
                     "scanner": len(scan.findings),
                     "model": numbers["model_findings"],
                     "verification": numbers["verification"]},
        "headline_findings": [{
            "title": f.title, "severity": f.severity.value, "category": f.category.value,
            "source": f.source.value, "impact": f.impact,
            "verification": f.verification.value if f.verification else "unverified"}
            for f in all_findings[:HEADLINE_FINDINGS]],
        "tests_present": numbers["tests_present"],
        "secrets": {"current": numbers["secrets_current"],
                    "in_history": numbers["secrets_history"]},
        "bus_factor": git.bus_factor, "top_author_share": git.top_author_share,
        "ai_tooling_indicators": indicators,
        "not_analysed": {"excluded_files": census.totals.excluded_files,
                         "failed_units": gaps["failed_units_count"],
                         "windowed_units": gaps["windowed"]["count"],
                         "failed_modules": len(gaps["failed_modules"])},
    }}
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "census": census, "metrics": metrics, "git": git,
        "deps": deps, "scan": scan, "severity_groups": _severity_groups(all_findings),
        "vulnerabilities": vulnerability_text(deps.advisories),
        "compact_severities": _compact(ctx.config.report.detail_from),
        "numbers": numbers, "not_analysed": not_analysed, "binaries": binaries,
        "skipped_at_ingest": skipped_at_ingest,
        "tracked_despite_gitignore": list(census.tracked_despite_gitignore),
        "model_gaps": gaps, "everything_analysed": everything_analysed,
        "prose_facts": prose_facts, "diagrams": {}, "delta": delta_context(inp.delta),
        "outlook": remediation_outlook(all_findings, ctx.config.report.effort_days),
    }
