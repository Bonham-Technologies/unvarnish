from pathlib import Path

from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.bus_factor import BusFactorScanner
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import AuthorStats, GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics


def _ctx(git: GitStats, share: float = 0.9) -> ScanContext:
    return ScanContext(
        tool="t", source_root=Path("."), census=Census(tool="t", files=[], totals=CensusTotals()),
        metrics=Metrics(tool="t", files=[]), git=git,
        dependencies=Dependencies(tool="t", dependencies=[]),
        options={"single_author_share": share},
    )


def _git(shares: list[float], commits: int = 10) -> GitStats:
    authors = [AuthorStats(name=f"A{i}", email=f"a{i}@x", commits=max(commits // len(shares), 1),
                           lines_changed=int(s * 1000), share=s) for i, s in enumerate(shares)]
    cumulative, bus = 0.0, 0
    for a in authors:
        cumulative += a.share
        bus += 1
        if cumulative >= 0.8:
            break
    return GitStats(tool="t", available=True, commit_count=commits, authors=authors,
                    bus_factor=bus, top_author_share=shares[0])


def test_single_author_concentration_is_high():
    findings = BusFactorScanner().run(_ctx(_git([0.97, 0.03])))
    assert [f.title for f in findings] == ["Single-author concentration"]
    assert findings[0].severity == Severity.high
    assert "97%" in findings[0].summary
    assert findings[0].evidence[0].path == "."


def test_low_bus_factor_is_medium():
    findings = BusFactorScanner().run(_ctx(_git([0.85, 0.10, 0.05])))
    assert [f.title for f in findings] == ["Low bus factor"]
    assert findings[0].severity == Severity.medium


def test_balanced_team_has_no_finding():
    assert BusFactorScanner().run(_ctx(_git([0.4, 0.35, 0.25]))) == []


def test_skips_without_history():
    assert BusFactorScanner().run(_ctx(GitStats(tool="t", available=False))) == []
    assert BusFactorScanner().run(_ctx(_git([1.0], commits=1))) == []


def test_builtin_registry_order():
    assert [s.name for s in builtin_scanners()] == [
        "secrets", "oversized_files", "hygiene", "bus_factor", "dependencies",
        "hardcoded_infra", "vendored_bulk", "generated_bulk", "client_exposure", "end_of_life",
    ]
