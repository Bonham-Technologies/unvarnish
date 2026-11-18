import os
from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import PhaseRunner, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners import builtin_scanners
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.scan import ScannerFindings


def _findings(engagement, origin: str, kind: str):
    ingest_tool(engagement, "t", origin, kind)
    ctx = build_context(engagement, "t")
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    return read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings


def test_synthetic_repo_reports_vendor_dir_and_bulk_commit(engagement, synthetic_repo):
    findings = _findings(engagement, str(synthetic_repo), "repo")
    vendored = next(f for f in findings if f.scanner == "vendored_bulk")
    assert vendored.title == "Dependency or build directories in the source"
    assert vendored.severity == Severity.medium
    assert [e.path for e in vendored.evidence] == ["node_modules"]
    bulk = next(f for f in findings if f.scanner == "generated_bulk")
    assert bulk.title == "Bulk commits" and "2,000" in bulk.summary
    assert "Claude" in bulk.summary  # the generation commit carried an AI co-author trailer
    assert "generate processing" in bulk.evidence[0].note


def test_gitignored_vendor_dir_is_not_reported(engagement, tmp_path: Path):
    src = tmp_path / "pile"
    (src / "node_modules" / "x").mkdir(parents=True)
    (src / "node_modules" / "x" / "index.js").write_text("module.exports = 1;\n")
    (src / ".gitignore").write_text("node_modules/\n")
    (src / "app.js").write_text("console.log(1);\n")
    findings = _findings(engagement, str(src), "files")
    assert not any(f.scanner == "vendored_bulk" for f in findings)
    assert not any(f.scanner == "generated_bulk" for f in findings)  # no git history


def test_large_binaries_over_the_threshold(engagement, tmp_path: Path):
    src = tmp_path / "pile"
    src.mkdir()
    (src / "model.bin").write_bytes(os.urandom(2_000_000))
    (src / "tiny.bin").write_bytes(b"\x00\x01" * 10)
    (src / "app.py").write_text("print(1)\n")
    findings = _findings(engagement, str(src), "files")
    big = next(f for f in findings if f.title == "Large binary files in the source")
    assert [e.path for e in big.evidence] == ["model.bin"] and "2.0 MB" in big.evidence[0].note


def test_registered():
    names = {s.name for s in builtin_scanners()}
    assert {"vendored_bulk", "generated_bulk"} <= names
