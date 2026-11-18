from pathlib import Path

import pytest

from unvarnish.analysis.languages import Classification
from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import build_context
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.dependencies import DependenciesScanner, is_pinned
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    DependencyRecord,
    FileRecord,
    Metrics,
)


def dep(eco: str, name: str, constraint: str | None, manifest="requirements.txt", dev=False):
    return DependencyRecord(ecosystem=eco, name=name, constraint=constraint, manifest=manifest,
                            dev=dev)


def ctx_with(deps: Dependencies, files: tuple[str, ...] = ()) -> ScanContext:
    census = Census(tool="t", totals=CensusTotals(), files=[
        FileRecord(path=p, bytes=10, lines=1, language=None,
                   classification=Classification.config, excluded=p.endswith(".lock"),
                   exclusion_reason="lockfile" if p.endswith(".lock") else None)
        for p in files])
    return ScanContext(tool="t", source_root=Path("."), census=census,
                       metrics=Metrics(tool="t", files=[]), git=GitStats(tool="t", available=False),
                       dependencies=deps)


@pytest.mark.parametrize("rec,pinned", [
    (dep("pypi", "a", "==1.2"), True), (dep("pypi", "a", "===1.2"), True),
    (dep("pypi", "a", ">=1.2"), False), (dep("pypi", "a", None), False),
    (dep("pypi", "a", "==1.*"), False),
    (dep("npm", "a", "1.2.3"), True), (dep("npm", "a", "^1.2.3"), False),
    (dep("npm", "a", "latest"), False), (dep("npm", "a", "1.x"), False),
    (dep("go", "a", "v1.2.3"), True), (dep("go", "a", None), True),
    (dep("cargo", "a", "1.2"), False), (dep("cargo", "a", "=1.2.0"), True),
    (dep("maven", "a", "1.2.3"), True), (dep("maven", "a", "[1.0,2.0)"), False),
    (dep("maven", "a", "LATEST"), False), (dep("maven", "a", "${lib.version}"), True),
])
def test_is_pinned(rec, pinned):
    assert is_pinned(rec) is pinned


def test_advisories_are_grouped_per_package():
    deps = Dependencies(tool="t", dependencies=[], advisories_checked=True, advisories=[
        {"id": "GHSA-1", "ids": ["GHSA-1"], "package": "flask", "version": "2.3.2",
         "ecosystem": "PyPI", "manifest": "requirements.txt", "summary": "Leak",
         "severity": "high"},
        {"id": "GHSA-2", "ids": ["GHSA-2"], "package": "flask", "version": "2.3.2",
         "ecosystem": "PyPI", "manifest": "requirements.txt", "summary": "DoS",
         "severity": "medium"}])
    findings = DependenciesScanner().run(ctx_with(deps))
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Known vulnerabilities in flask 2.3.2" and f.severity == Severity.high
    assert "GHSA-1" in f.summary and "GHSA-2" in f.summary
    assert f.evidence[0].path == "requirements.txt" and "GHSA-2" in f.evidence[0].note


def test_no_advisory_findings_when_unchecked():
    deps = Dependencies(tool="t", dependencies=[], advisories_checked=False,
                        advisories=[{"id": "X", "package": "p", "severity": "high"}])
    assert DependenciesScanner().run(ctx_with(deps)) == []


def test_unpinned_without_lockfile_on_synthetic_repo(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    InventoryPhase().run(ctx)
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    census = read_artifact(ctx.paths.census, Census).data
    sctx = ScanContext(tool=tool, source_root=ctx.source_root, census=census,
                       metrics=Metrics(tool=tool, files=[]),
                       git=GitStats(tool=tool, available=False), dependencies=deps)
    findings = DependenciesScanner().run(sctx)
    assert [f.title for f in findings] == ["Unpinned dependencies without a lockfile"]
    f = findings[0]
    assert f.severity == Severity.medium and f.evidence[0].path == "requirements.txt"
    assert "requests" in f.evidence[0].note and "flask" not in f.evidence[0].note


def test_lockfile_suppresses_unpinned_for_its_ecosystem():
    deps = Dependencies(tool="t", dependencies=[dep("pypi", "requests", ">=2"),
                                                dep("npm", "left-pad", "^1.0",
                                                    manifest="package.json")])
    findings = DependenciesScanner().run(ctx_with(deps, files=("poetry.lock",)))
    assert len(findings) == 1 and "left-pad" in findings[0].evidence[0].note
    assert all("requests" not in e.note for e in findings[0].evidence)


def test_dev_dependencies_are_ignored():
    deps = Dependencies(tool="t", dependencies=[dep("pypi", "pytest", ">=8", dev=True)])
    assert DependenciesScanner().run(ctx_with(deps)) == []


def test_registered():
    assert "dependencies" in {s.name for s in builtin_scanners()}
