import json

from tests.stub_backend import StubBackend
from tests.test_rollup_modules import MODULE
from tests.test_rollup_tool import TOOL
from unvarnish.artifacts import read_artifact
from unvarnish.model.budget import BudgetTracker
from unvarnish.model.prompts.verify import build_verify_request
from unvarnish.phases.base import PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.phases.verify import (
    VerifyPhase,
    collect_model_findings,
    dedupe_findings,
    downgrade,
    evidence_excerpt,
)
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source, Verification
from unvarnish.schemas.verify import ModelFindings


def _unit_reply(req) -> str:
    """UnitExtraction with one high finding at the unit's first line, same title everywhere."""
    user = req.messages[0].content
    if "lines " not in user:  # a repair call for a unit that already failed: keep failing
        return "garbage"
    rng = user.split("lines ", 1)[1].split("\n", 1)[0].split(" ", 1)[0]
    lo = int(rng.split("-")[0])
    return json.dumps({
        "purpose": "Does a thing.", "interface": [], "external_calls": [], "data_read": [],
        "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
        "candidate_findings": [{
            "category": "security", "severity": "high", "title": "Hardcoded credential",
            "summary": "s", "impact": "i", "remediation": "r", "line_start": lo,
            "line_end": lo, "excerpt": "x", "confidence": 0.9}],
        "confidence": 0.8,
    })


def _finding(title="t", path="a.py", line=1, severity=Severity.high, confidence=0.5,
             category=Category.security) -> Finding:
    return Finding(tool="t", category=category, severity=severity, title=title, summary="s",
                   impact="i", remediation="r", source=Source.model, model="m",
                   confidence=confidence,
                   evidence=[Evidence(path=path, line_start=line, line_end=line)])


def test_dedupe_merges_same_problem_in_same_file():
    a = _finding(line=1, confidence=0.4)
    b = _finding(title=" T ", line=50, confidence=0.9)
    c = _finding(path="b.py")
    out = dedupe_findings([a, b, c])
    assert len(out) == 2
    merged = next(f for f in out if f.evidence[0].path == "a.py")
    assert [e.line_start for e in merged.evidence] == [1, 50]
    assert merged.confidence == 0.9 and merged.id == a.id


def test_dedupe_keeps_different_categories_apart():
    out = dedupe_findings([_finding(), _finding(category=Category.reliability)])
    assert len(out) == 2


def test_evidence_excerpt_numbers_lines_with_context(tmp_path):
    (tmp_path / "a.py").write_text("".join(f"line {i}\n" for i in range(1, 21)))
    text = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=10, line_end=11),
                            context=2)
    assert text.startswith("a.py lines 8-13:\n")
    assert "     8: line 8" in text and "    13: line 13" in text and "line 14" not in text
    clamped = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=1, line_end=1),
                               context=5)
    assert clamped.startswith("a.py lines 1-6:")
    capped = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=1, line_end=20),
                              context=0, max_lines=3)
    assert capped.startswith("a.py lines 1-3:")
    whole = evidence_excerpt(tmp_path, Evidence(path="a.py", excerpt="recorded"))
    assert "whole file cited" in whole and "recorded" in whole
    missing = evidence_excerpt(tmp_path, Evidence(path="nope.py", line_start=1))
    assert "not readable" in missing


def test_downgrade_steps_one_level_and_floors():
    assert downgrade(Severity.critical) == Severity.high
    assert downgrade(Severity.high) == Severity.medium
    assert downgrade(Severity.low) == Severity.info
    assert downgrade(Severity.info) == Severity.info


def test_verify_request_contains_claim_and_evidence_only():
    f = _finding(title="Hardcoded credential")
    req = build_verify_request(f, ["a.py lines 1-3:\n     1: x = 1"], effort="low")
    body = req.messages[0].content
    assert body.startswith("Claim: Hardcoded credential\nCategory: security\n"
                           "Severity claimed: high\n")
    assert "     1: x = 1" in body and req.schema_name == "Verdict"
    assert "confirmed" in req.system and "rejected" in req.system


def _pipeline(engagement, tool, stub, budget=None):
    ctx = build_context(engagement, tool, budget=budget)
    for phase in (InventoryPhase(), SplitPhase(), ExtractPhase(backend=stub),
                  RollupModulesPhase(backend=stub), RollupToolPhase(backend=stub)):
        assert phase.run(ctx).status == PhaseStatus.ok, phase.name
    return ctx


def test_collect_gathers_unit_module_and_tool_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL})
    ctx = _pipeline(eng, tool, stub)
    titles = {f.title for f in collect_model_findings(ctx)}
    assert {"Hardcoded credential", "Mixed responsibilities", "No auth anywhere"} <= titles


def test_verify_downgrades_and_writes_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "downgraded", "reason": "overstated"}'})
    ctx = _pipeline(eng, tool, stub)
    res = VerifyPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    highs = [f for f in mf.findings if f.title == "Hardcoded credential"]
    assert highs and all(f.verification == Verification.downgraded for f in highs)
    assert all(f.severity == Severity.medium for f in highs)
    assert all(f.verification_note == "overstated" for f in highs)
    medium = next(f for f in mf.findings if f.title == "Mixed responsibilities")
    assert medium.verification == Verification.not_required
    tool_level = next(f for f in mf.findings if f.title == "No auth anywhere")
    assert tool_level.verification is None and "tool-level" in tool_level.verification_note
    assert mf.verified == len(highs) == mf.downgraded and mf.unverified == 1
    assert stub.count("Verdict") == len(highs)
    assert is_fresh(VerifyPhase(backend=stub), ctx)
    # dedupe collapsed the per-unit duplicates in app.py into one finding
    assert sum(1 for f in mf.findings if f.title == "Hardcoded credential"
               and f.evidence[0].path == "app.py") == 1


def test_verify_retains_rejected_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "rejected", "reason": "no such thing"}'})
    ctx = _pipeline(eng, tool, stub)
    VerifyPhase(backend=stub).run(ctx)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    rejected = [f for f in mf.findings if f.verification == Verification.rejected]
    assert rejected and mf.rejected == len(rejected)
    assert all(f.severity == Severity.high for f in rejected)  # severity untouched


def test_verify_keeps_finding_when_verification_fails(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL, "Verdict": "garbage"})
    ctx = _pipeline(eng, tool, stub)
    res = VerifyPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok and res.failures
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    highs = [f for f in mf.findings if f.title == "Hardcoded credential"]
    assert highs and all(f.verification is None for f in highs)
    assert all("verification failed" in (f.verification_note or "") for f in highs)
    assert mf.unverified == len(highs) + 1 and mf.verified == 0  # +1 tool-level finding
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert {f.phase for f in items} >= {"verify"}


def test_verify_budget_stop(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "confirmed", "reason": "yes"}'})
    ctx = _pipeline(eng, tool, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ctx = build_context(eng, tool, budget=tracker)
    assert VerifyPhase(backend=stub).run(ctx).status == PhaseStatus.stopped
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.stopped_for_budget and not is_fresh(VerifyPhase(backend=stub), ctx)


def test_verify_skipped_without_model(ingested):
    eng, tool = ingested
    assert VerifyPhase().run(build_context(eng, tool)).status == PhaseStatus.skipped
