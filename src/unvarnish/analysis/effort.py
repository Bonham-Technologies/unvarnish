"""Remediation-effort totals (UNVAR-42), computed from findings, never written by a model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from unvarnish.config import EffortDays, EngagementConfig
from unvarnish.schemas.finding import Effort, Finding

BANDS = [e.value for e in Effort]
NOT_ESTIMATED = "none"  # the count key for findings with no band


def effort_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Findings per band, every band present, plus "none" for those not estimated."""
    counts = dict.fromkeys([*BANDS, NOT_ESTIMATED], 0)
    for f in findings:
        counts[f.effort.value if f.effort else NOT_ESTIMATED] += 1
    return counts


def day_range(counts: Mapping[str, int], days: EffortDays) -> tuple[float, float]:
    """Engineer-days for the estimated findings. Each figure is the most a finding of that
    band should take; the low end is the band below's figure (S starts at 0)."""
    low = high = 0.0
    floor = 0.0
    for band in BANDS:
        ceiling = float(getattr(days, band))
        n = counts.get(band, 0)
        low += n * floor
        high += n * ceiling
        floor = ceiling
    return low, high


def fmt_days(value: float) -> str:
    """Up to two decimals, trailing zeros dropped: a configured 0.25 prints as 0.25."""
    text = f"{value:,.2f}".rstrip("0")
    return text.rstrip(".")


def effort_text(counts: Mapping[str, int]) -> str:
    """"2 S · 1 XL; 3 not estimated" for a table cell or a prompt line."""
    parts = [f"{counts[b]} {b}" for b in BANDS if counts.get(b)]
    text = " · ".join(parts)
    if counts.get(NOT_ESTIMATED):
        text += f"{'; ' if text else ''}{counts[NOT_ESTIMATED]} not estimated"
    return text or "no findings"


def days_text(counts: Mapping[str, int], days: EffortDays) -> str:
    low, high = day_range(counts, days)
    return f"{fmt_days(low)}–{fmt_days(high)}"


def effort_days_part(config: EngagementConfig) -> list[str]:
    """The day mapping for an inputs hash, only when set, so an engagement without it keeps
    its hashes. Setting it re-renders, and reruns compare for the consolidation prompt."""
    days = config.report.effort_days
    return [days.model_dump_json()] if days is not None else []
