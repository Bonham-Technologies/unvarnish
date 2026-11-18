from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase, sort_findings
from unvarnish.scanners import load_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.schemas.scan import ScannerFindings


class DummyScanner:
    name = "dummy"
    category = Category.process

    def __init__(self, severity: Severity = Severity.low) -> None:
        self.severity = severity
        self.seen_options: dict | None = None

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.seen_options = ctx.options
        return [
            Finding(
                tool=ctx.tool, category=self.category, severity=self.severity,
                title="Dummy finding", summary="s", impact="i", remediation="r",
                evidence=[Evidence(path="app.py", line_start=1)], source=Source.scanner,
                scanner=self.name,
            )
        ]


class BrokenScanner:
    name = "broken"
    category = Category.process

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise ValueError("kaboom")


def _prepare(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    return ctx


def test_scan_phase_collects_and_records_skips(ingested):
    ctx = _prepare(ingested)
    eng = ctx.engagement
    eng.config.scanners["dummy"] = {"threshold": 3}
    dummy = DummyScanner()
    phase = ScanPhase(scanners=[dummy, BrokenScanner()])
    result = phase.run(ctx)
    assert result.status == PhaseStatus.ok
    assert result.failures == ["broken: ValueError('kaboom')"]
    out = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert [f.title for f in out.findings] == ["Dummy finding"]
    assert out.findings[0].verification == "not_required"
    assert out.skipped[0].name == "broken" and "kaboom" in out.skipped[0].error
    assert out.scanners_run == ["dummy", "broken"]
    assert dummy.seen_options == {"threshold": 3}


def test_scan_phase_freshness_tracks_options(ingested):
    ctx = _prepare(ingested)
    phase = ScanPhase(scanners=[DummyScanner()])
    h1 = phase.inputs_hash(ctx)
    ctx.engagement.config.scanners["dummy"] = {"threshold": 9}
    assert phase.inputs_hash(ctx) != h1


def test_sort_findings_by_severity_then_path():
    def f(sev, path, title="t"):
        return Finding(tool="x", category=Category.security, severity=sev, title=title,
                       summary="s", impact="i", remediation="r",
                       evidence=[Evidence(path=path)], source=Source.scanner)

    out = sort_findings([f(Severity.low, "b.py"), f(Severity.critical, "z.py"),
                         f(Severity.low, "a.py")])
    assert [(x.severity, x.evidence[0].path) for x in out] == [
        (Severity.critical, "z.py"), (Severity.low, "a.py"), (Severity.low, "b.py"),
    ]


def test_load_scanners_includes_entry_points(monkeypatch):
    import importlib.metadata as md

    class FakeEP:
        name = "dummy"
        group = "unvarnish.scanners"

        def load(self):
            return DummyScanner

    class FakeEPs(list):
        def select(self, group):
            return self if group == "unvarnish.scanners" else []

    monkeypatch.setattr(md, "entry_points", lambda: FakeEPs([FakeEP()]))
    names = [s.name for s in load_scanners()]
    assert names.count("dummy") == 1
