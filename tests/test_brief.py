"""The engagement brief for leadership (UNVAR-99): comparison/brief.md."""
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from tests.test_render_documents import _phases
from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.export import exporter as exporter_module
from unvarnish.export.exporter import DOC_NAMES, export_engagement
from unvarnish.model.base import BackendError
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.compare import (
    EngagementContext,
    RenderBriefPhase,
    run_comparison,
)
from unvarnish.phases.ingest import ingest_tool
from unvarnish.render.brief import ACTION_BUCKETS, action_bucket
from unvarnish.render.findings import merged_findings
from unvarnish.render.prose import BLOCKS, FALLBACK
from unvarnish.schemas.delta import BaselineInfo, Delta, DeltaEntry, DeltaStatus
from unvarnish.schemas.finding import Effort, Evidence, Finding, Severity
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.verify import ModelFindings

runner = CliRunner()
SEVERITIES = [s.value for s in Severity]


def _per_tool(engagement, tool: str) -> dict:
    """What one tool's own JSON artifacts say, counted independently of the brief."""
    p = engagement.tool_paths(tool)
    scan = read_artifact(p.scanner_findings, ScannerFindings).data
    mf = (read_artifact(p.model_findings, ModelFindings).data.findings
          if p.model_findings.exists() else [])
    findings = merged_findings(scan.findings, mf)
    census = read_artifact(p.census, Census).data
    files = sum(1 for f in census.files if not f.excluded and f.classification != "binary")
    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    return {"files": files, "findings": findings,
            "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES},
            "secrets": len(secrets)}


def _set_config(engagement, **report):
    data = engagement.config.model_dump()
    data["report"].update(report)
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()


# --- the bucket rule, one test per boundary (acceptance criterion 4) -----------------------

@pytest.mark.parametrize(("severity", "effort", "bucket"), [
    ("critical", "S", "fix_now"),
    ("critical", "XL", "fix_now"),          # critical: effort never defers it
    ("critical", None, "fix_now"),
    ("high", "S", "fix_now"),
    ("high", "M", "fix_now"),               # M is the last band fixed now
    ("high", "L", "before_scaling"),        # L is the first band deferred
    ("high", "XL", "before_scaling"),
    ("high", None, "fix_now"),              # not estimated is not evidence of a large job
    ("medium", "S", "before_scaling"),      # medium: never fix now, whatever the effort
    ("medium", "XL", "before_scaling"),
    ("medium", None, "before_scaling"),
    ("low", "S", "accept"),                 # low and info: accept
    ("low", None, "accept"),
    ("info", "XL", "accept"),
])
def test_action_bucket_boundaries(severity, effort, bucket):
    assert action_bucket(Severity(severity), Effort(effort) if effort else None) == bucket


def test_every_severity_and_band_lands_in_exactly_one_bucket():
    keys = [b.key for b in ACTION_BUCKETS]
    assert keys == ["fix_now", "before_scaling", "accept"]
    for sev in Severity:
        for band in [*Effort, None]:
            assert action_bucket(sev, band) in keys


# --- the two-tool fixture (acceptance criteria 1 and 2) ------------------------------------

def test_prose_block_exists():
    assert "portfolio_summary" in BLOCKS


def test_two_tool_brief_totals_equal_the_sum_of_the_per_tool_artifacts(engagement,
                                                                       synthetic_repo):
    stub = _compare_stub()
    # alpha is model-analysed, beta scanner-only: the two tools' counts differ
    _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    prose_before = stub.count("prose")
    results = run_comparison(engagement, backend=stub)
    assert [r.phase for r in results] == ["compare", "render_comparison", "render_brief"]
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    assert engagement.brief_doc == engagement.comparison_dir / "brief.md"
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert doc.startswith("# Acme: Leadership Brief")
    assert "(s)" not in doc
    for heading in ("## Summary", "## Portfolio totals", "## By tool",
                    "## Highest-severity findings", "## Action plan"):
        assert heading in doc, heading

    alpha, beta = _per_tool(engagement, "alpha"), _per_tool(engagement, "beta")
    assert alpha["by_severity"] != beta["by_severity"]  # the fixture tells them apart
    total = {s: alpha["by_severity"][s] + beta["by_severity"][s] for s in SEVERITIES}
    n = sum(total.values())
    breakdown = ", ".join(f"{total[s]} {s}" for s in SEVERITIES if total[s])
    assert "| Tools reviewed | 2 (`alpha`, `beta`) |" in doc
    assert f"| Files analysed | {alpha['files'] + beta['files']:,} |" in doc
    assert f"| Findings | {n:,} ({breakdown}) |" in doc
    secrets = alpha["secrets"] + beta["secrets"]
    assert secrets and "| Credential-like values (secrets scanner) |" in doc
    for tool, counts in (("alpha", alpha), ("beta", beta)):
        cells = " | ".join(str(counts["by_severity"][s]) for s in SEVERITIES)
        assert f"| `{tool}` | {counts['files']:,} | {cells} |" in doc, tool
    assert f"| **Total** | {alpha['files'] + beta['files']:,} | " + " | ".join(
        str(total[s]) for s in SEVERITIES) + " |" in doc

    # The ten highest-severity findings across both tools, each with its tool and path.
    merged = sorted([("alpha", f) for f in alpha["findings"]]
                    + [("beta", f) for f in beta["findings"]],
                    key=lambda tf: SEVERITIES.index(tf[1].severity.value))
    top = doc.split("## Highest-severity findings", 1)[1].split("## Action plan", 1)[0]
    rows = [line for line in top.splitlines() if line.startswith("| ") and line[2].isdigit()]
    assert len(rows) == min(10, len(merged))
    worst = SEVERITIES.index(merged[0][1].severity.value)
    assert f"| 1 | {SEVERITIES[worst]} |" in rows[0]
    assert all("`alpha`" in r or "`beta`" in r for r in rows)
    shown = [r.split(" | ")[1] for r in rows]
    assert shown == [f.severity.value for _, f in merged[:len(rows)]]

    # The action plan's buckets add up to every finding.
    plan = doc.split("## Action plan", 1)[1]
    counts = {b.label: int(next(line for line in plan.splitlines()
                                if line.startswith(f"| {b.label} |")).split(" | ")[2])
              for b in ACTION_BUCKETS}
    assert sum(counts.values()) == n

    # The only model call is the one prose block.
    # tools_reviewed and the brief; one tool model, so no consolidation proposal
    assert stub.count("prose") - prose_before == 2
    assert "PROSE Write a short summary for leadership" in doc
    again = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.skipped for r in again)  # fresh


def test_brief_without_a_model_renders_from_scanner_data(engagement, synthetic_repo):
    """Air-gapped with no model configured (acceptance criteria 2 and 5)."""
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub, model_for=())  # scanners only
    assert engagement.config.models.default is None
    res = RenderBriefPhase().run(ectx)  # no injected backend, nothing configured
    assert res.status == PhaseStatus.ok, res
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert FALLBACK.format(reason="no model configured") in doc
    alpha, beta = _per_tool(engagement, "alpha"), _per_tool(engagement, "beta")
    n = sum(alpha["by_severity"].values()) + sum(beta["by_severity"].values())
    assert f"| Findings | {n:,} (" in doc
    assert "Scanner findings only (no model analysis): `alpha`, `beta`." in doc
    assert stub.count("prose") == 0 or all(  # no request went out for the brief
        "summary for leadership" not in r.messages[0].content for r in stub.requests)


def test_brief_prose_failure_falls_back_and_is_recorded(engagement, synthetic_repo):
    from unvarnish.schemas.analysis import Failures

    stub = _compare_stub(prose=BackendError("400"))
    _two_tools(engagement, synthetic_repo, stub)
    results = run_comparison(engagement, backend=stub)
    assert results[2].phase == "render_brief" and results[2].status == PhaseStatus.ok
    assert len(results[2].failures) == 1
    assert FALLBACK.format(reason="model call failed") in engagement.brief_doc.read_text()
    items = read_artifact(engagement.comparison_failures, Failures).data.items
    assert [f.unit_id for f in items if f.phase == "render_brief"] == ["portfolio_summary"]


def test_one_tool_brief_says_the_comparison_sections_were_skipped(engagement, synthetic_repo):
    stub = _compare_stub()
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    results = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert "| Tools reviewed | 1 (`alpha`) |" in doc
    assert "Only one tool was reviewed, so the comparison sections" in doc
    assert "were skipped" in doc


def test_brief_names_tools_not_run(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    ingest_tool(engagement, "gamma", str(synthetic_repo), "repo")  # registered, never run
    run_comparison(engagement, backend=stub)
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert "Not reviewed yet, so not counted: `gamma`." in doc
    assert "| Tools reviewed | 2 (`alpha`, `beta`) |" in doc


def _delta(tool: str, resolved: int, new: int) -> Delta:
    def f(i: int, status: DeltaStatus) -> DeltaEntry:
        return DeltaEntry(status=status, finding=Finding(
            tool=tool, category="security", severity="high", title=f"T{i}", summary="s",
            impact="i", remediation="r", source="scanner", scanner="hygiene",
            evidence=[Evidence(path=f"f{i}.py", line_start=1)]))
    entries = ([f(i, DeltaStatus.resolved) for i in range(resolved)]
               + [f(100 + i, DeltaStatus.new) for i in range(new)])
    return Delta(tool=tool, baseline=BaselineInfo(source="x"), line_drift=50, entries=entries)


def test_brief_shows_engineer_days_and_trend_when_available(engagement, synthetic_repo):
    from unvarnish.analysis.effort import day_range, effort_counts, fmt_days

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    run_comparison(engagement, backend=stub)
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert "Since the previous review" not in doc  # no delta yet: no trend column
    assert "engineer-days" not in doc

    _set_config(engagement, effort_days={"S": 0.5, "M": 2, "L": 5, "XL": 15})
    write_artifact(engagement.tool_paths("alpha").delta, _delta("alpha", 3, 1),
                   produced_by="render", inputs_hash="")
    results = run_comparison(engagement, backend=stub)
    assert results[2].status == PhaseStatus.ok  # the delta and the mapping re-render it
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert "Since the previous review" in doc
    assert "improved (3 resolved, 1 new)" in doc
    days = engagement.config.report.effort_days
    for tool in ("alpha", "beta"):
        low, high = day_range(effort_counts(_per_tool(engagement, tool)["findings"]), days)
        assert f"{fmt_days(low)}–{fmt_days(high)} engineer-days" in doc, tool
    both = (_per_tool(engagement, "alpha")["findings"]
            + _per_tool(engagement, "beta")["findings"])
    low, high = day_range(effort_counts(both), days)
    assert f"| Effort to fix (estimate) | {fmt_days(low)}–{fmt_days(high)} engineer-days" in doc


def test_brief_phase_before_any_run_is_not_ready(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    res = RenderBriefPhase().run(EngagementContext(engagement=engagement,
                                                   budget=BudgetTracker(None)))
    assert res.status == PhaseStatus.failed and res.not_ready
    assert not engagement.brief_doc.exists()


# --- export (acceptance criterion 3) -------------------------------------------------------

def _fake_render(src: str, fmt: str) -> bytes:
    return b"<svg/>" if fmt == "svg" else b"\x89PNG\r\n\x1a\n"


def _fake_pandoc_ok(cmd):
    Path(cmd[cmd.index("-o") + 1]).write_bytes(b"converted")


def test_brief_is_an_export_document(engagement, synthetic_repo, monkeypatch):
    assert "brief" in DOC_NAMES
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    monkeypatch.setattr(exporter_module, "run_pandoc", _fake_pandoc_ok)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["docx", "html", "pdf"], docs=["brief"],
                               tools=None, template=None, timestamp="20261126-120000",
                               render=_fake_render)
    assert [(i.doc, i.tool, i.fmt, i.status) for i in report.items] == [
        ("brief", "engagement", fmt, "ok") for fmt in ("docx", "html", "pdf")]
    assert {i.path for i in report.items} == {
        f"exports/brief-engagement-20261126-120000.{fmt}" for fmt in ("docx", "html", "pdf")}


def test_brief_not_rendered_is_skipped_and_naming_a_tool_leaves_it_out(engagement,
                                                                       synthetic_repo,
                                                                       monkeypatch):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    monkeypatch.setattr(exporter_module, "run_pandoc", _fake_pandoc_ok)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["html"], docs=["brief"], tools=None,
                               template=None, render=_fake_render)
    assert [(i.doc, i.status) for i in report.items] == [("brief", "skipped")]
    assert "comparison/brief.md does not exist" in report.items[0].detail
    run_comparison(engagement, backend=stub)
    report = export_engagement(engagement, formats=["html"], docs=None, tools=["alpha"],
                               template=None, render=_fake_render)
    assert "brief" not in {i.doc for i in report.items}


HAVE_PDF = all(shutil.which(t) for t in ("pandoc", "dot", "weasyprint"))


@pytest.mark.skipif(not HAVE_PDF, reason="pandoc, graphviz and weasyprint needed")
def test_export_doc_brief_end_to_end(engagement, synthetic_repo):
    import zipfile

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    out = runner.invoke(app, ["export", "--doc", "brief", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    produced = {p.suffix: p for p in engagement.exports_dir.glob("brief-engagement-*")}
    assert set(produced) == {".docx", ".html", ".pdf"}
    assert "<table" in produced[".html"].read_text(encoding="utf-8")
    assert "Leadership Brief" in produced[".html"].read_text(encoding="utf-8")
    assert produced[".pdf"].read_bytes()[:5] == b"%PDF-"
    with zipfile.ZipFile(produced[".docx"]) as z:
        assert "Portfolio totals" in z.read("word/document.xml").decode("utf-8")


def test_brief_totals_sum_end_of_life_known_exploited_and_exposure(engagement, synthetic_repo):
    """Checked tools are summed; a tool that was not checked is counted as such, not as 0."""
    from unvarnish.phases.compare import load_tool_inputs
    from unvarnish.render.brief import build_brief_context
    from unvarnish.render.markdown import make_env, render_document

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub, model_for=())
    alpha, beta = (load_tool_inputs(engagement, t) for t in ("alpha", "beta"))
    for i, past, kev in ((alpha, 2, 1), (beta, 1, 0)):
        i.scan.scanners_run.append("end_of_life")
        i.deps.eol_data_date = "2026-11-01"
        i.scan.findings += [Finding(
            tool=i.tool, category="dependency", severity="high", title=f"EOL {n}",
            summary="s", impact="i", remediation="r", source="scanner", scanner="end_of_life",
            tags=["past-eol"], evidence=[Evidence(path="package.json")]) for n in range(past)]
        i.deps.advisories_checked = True
        i.deps.exploit_data_date = "2026-11-01"
        i.deps.advisories = [{"id": f"A{n}", "kev": n < kev} for n in range(3)]
    beta.deps.exploit_data_date = None  # beta's exploit data was not checked
    ctx = build_brief_context(engagement, [alpha, beta], [])
    t = ctx["totals"]
    assert t["eol_past"] == {"count": 3, "checked": 2, "tools": 2}
    assert t["kev"] == {"count": 1, "checked": 1, "tools": 2}
    doc = render_document(make_env(), "brief.md.j2",
                          {**ctx, "prose": {"portfolio_summary": "Summary."}})
    assert "| End-of-life runtimes and frameworks | 3 past end of life, 0 near it |" in doc
    assert ("| Known-exploited dependency advisories (CISA KEV) | 1 (1 of 2 tools checked) |"
            in doc)
    assert ctx["prose_facts"]["portfolio_summary"]["end_of_life_runtimes"] == 3


# --- review fixes: freshness, the whole pipeline without a model, ties, empty cells ---------

def test_brief_reruns_when_a_tool_artifact_changes(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    run_comparison(engagement, backend=stub)
    p = engagement.tool_paths("beta").scanner_findings
    scan = read_artifact(p, ScannerFindings).data
    scan.findings.append(Finding(
        tool="beta", category="security", severity="critical", title="Brand new critical",
        summary="s", impact="i", remediation="r", source="scanner", scanner="hygiene",
        evidence=[Evidence(path="x.py", line_start=3)]))
    write_artifact(p, scan, produced_by="scan", inputs_hash="")
    results = run_comparison(engagement, backend=stub)
    assert results[2].phase == "render_brief" and results[2].status == PhaseStatus.ok
    doc = engagement.brief_doc.read_text(encoding="utf-8")
    assert "| 1 | critical | Brand new critical | `beta` | `x.py:3` |" in doc
    assert all(r.status == PhaseStatus.skipped for r in run_comparison(engagement, backend=stub))


def test_compare_without_a_model_still_writes_the_brief(engagement, synthetic_repo):
    """Acceptance criterion 5 through the whole engagement pipeline, not the phase alone."""
    _two_tools(engagement, synthetic_repo, _compare_stub(), model_for=())
    results = run_comparison(engagement)  # no backend injected, none configured
    assert [(r.phase, r.status) for r in results] == [
        ("compare", PhaseStatus.ok), ("render_comparison", PhaseStatus.ok),
        ("render_brief", PhaseStatus.ok)]
    assert FALLBACK.format(reason="no model configured") in engagement.brief_doc.read_text(
        encoding="utf-8")


def test_top_findings_order_ignores_artifact_order(engagement, synthetic_repo):
    from unvarnish.phases.compare import load_tool_inputs
    from unvarnish.render.brief import build_brief_context

    _two_tools(engagement, synthetic_repo, _compare_stub(), model_for=())
    alpha, beta = (load_tool_inputs(engagement, t) for t in ("alpha", "beta"))
    ties = [Finding(tool="alpha", category="security", severity="critical", title=t,
                    summary="s", impact="i", remediation="r", source="scanner",
                    scanner="hygiene", evidence=[Evidence(path="same.py", line_start=1)])
            for t in ("B tie", "A tie")]
    alpha.scan.findings += ties
    first = build_brief_context(engagement, [alpha, beta], [])["top"]
    alpha.scan.findings[-2:] = ties[::-1]
    second = build_brief_context(engagement, [alpha, beta], [])["top"]
    assert [t["title"] for t in first[:2]] == ["A tie", "B tie"]
    assert first == second


def test_empty_cells_say_no_findings_not_zero_days():
    from unvarnish.config import EffortDays
    from unvarnish.render.brief import days_cell

    days = EffortDays(S=0.5, M=2, L=5, XL=15)
    assert days_cell({"S": 0, "M": 0, "L": 0, "XL": 0, "none": 0}, days) is None
    assert days_cell({"S": 0, "M": 0, "L": 0, "XL": 0, "none": 2}, days) == (
        "0–0 engineer-days; 2 not estimated")
