"""Remediation-effort bands per finding and the cost-to-fix rollup (UNVAR-42)."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.test_compare_phase import _compare_stub, _two_tools
from tests.test_render_documents import _stub
from tests.test_verify import _unit_reply
from unvarnish.analysis.effort import day_range, effort_counts
from unvarnish.artifacts import read_artifact
from unvarnish.config import EffortDays, EngagementConfig, unknown_keys
from unvarnish.model.structured import strict_schema
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.compare import ComparePhase, run_comparison
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.render import RenderPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.render.findings import remediation_outlook
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.effort import EFFORT_RULES
from unvarnish.schemas.analysis import CandidateFinding, UnitExtraction
from unvarnish.schemas.comparison import Comparison, RiskRow
from unvarnish.schemas.finding import Effort, Evidence, Finding
from unvarnish.schemas.rollup import ModuleRollup
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import DirectoryRollup, ToolCandidateFinding, ToolRollup
from unvarnish.schemas.verify import ModelFindings, Verdict

SCANNERS_DIR = Path(__file__).parents[1] / "src" / "unvarnish" / "scanners"
DAYS = {"S": 0.5, "M": 2, "L": 5, "XL": 15}


def _f(severity: str = "high", effort: str | None = None, source: str = "model") -> Finding:
    return Finding(tool="t", category="security", severity=severity, title=f"T {severity}",
                   summary="s", impact="i", remediation="r", source=source,
                   evidence=[Evidence(path="a.py", line_start=1)], effort=effort)


# --- the Finding schema ---------------------------------------------------------------------

def test_finding_effort_is_optional_so_old_artifacts_load():
    old = {"tool": "t", "category": "security", "severity": "high", "title": "T",
           "summary": "s", "impact": "i", "remediation": "r", "source": "scanner",
           "evidence": [{"path": "a.py"}]}
    f = Finding.model_validate(old)
    assert f.effort is None and f.effort_note is None
    sf = ScannerFindings.model_validate({"tool": "t", "findings": [old]})
    assert sf.findings[0].effort is None
    assert Finding.model_validate({**old, "effort": "XL", "effort_note": "why"}).effort == "XL"
    with pytest.raises(ValidationError):
        Finding.model_validate({**old, "effort": "XXL"})
    # the id does not depend on the band, so a re-run keeps the baseline match
    assert Finding.model_validate({**old, "effort": "S"}).id == f.id


# --- criterion 1: every scanner finding has a band ------------------------------------------

def _finding_calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "Finding"]


def test_every_scanner_finding_call_carries_a_band():
    calls = 0
    for path in sorted(SCANNERS_DIR.glob("*.py")):
        for call in _finding_calls(path):
            calls += 1
            splats = [k.value for k in call.keywords if k.arg is None]
            assert any(isinstance(v, ast.Call) and getattr(v.func, "id", None) == "rule_effort"
                       for v in splats), f"{path.name}:{call.lineno}: a Finding with no band"
    assert calls >= 15


def test_band_table_covers_every_builtin_scanner_and_each_rule_is_used():
    assert set(EFFORT_RULES) == {s.name for s in builtin_scanners()}
    for scanner, rules in EFFORT_RULES.items():
        text = (SCANNERS_DIR / f"{scanner}.py").read_text(encoding="utf-8")
        for rule, (band, why) in rules.items():
            assert isinstance(band, Effort) and why and "\n" not in why
            assert f'"{rule}"' in text, f"{scanner}.{rule} is never used"


def test_scan_gives_every_finding_a_band(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results)
    findings = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings
    assert len(findings) >= 10
    missing = [f.title for f in findings if f.effort is None or not f.effort_note]
    assert not missing
    by_title = {f.title: f.effort for f in findings}
    assert by_title["No automated tests"] == Effort.XL
    assert by_title["Very large function"] == Effort.L
    assert by_title["No license file"] == Effort.S
    assert by_title["AWS access key ID in git history"] == Effort.M


def test_band_table_is_in_the_scan_inputs_hash(ingested, monkeypatch):
    """An engagement scanned before the bands existed rescans once, so its scanner findings
    get bands; a later change to the table rescans too."""
    eng, tool = ingested
    ctx = build_context(eng, tool)
    before = ScanPhase().inputs_hash(ctx)
    monkeypatch.setitem(EFFORT_RULES["hygiene"], "no_tests", (Effort.L, "changed"))
    assert ScanPhase().inputs_hash(ctx) != before


# --- criterion 4 (bands): a scanner rule's band is configurable ------------------------------

def test_scanner_band_override_from_config(ingested):
    eng, tool = ingested
    eng.config.scanners.setdefault("hygiene", {})["effort"] = {"no_tests": "L"}
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    findings = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings
    f = next(f for f in findings if f.title == "No automated tests")
    assert f.effort == Effort.L and "scanners.hygiene.effort.no_tests" in f.effort_note


def test_scanner_band_override_is_validated():
    def cfg_with(effort: dict) -> EngagementConfig:
        return EngagementConfig.model_validate({"scanners": {"hygiene": {"effort": effort}}})

    cfg = cfg_with({"no_tests": "l"})
    assert cfg.scanners["hygiene"]["effort"] == {"no_tests": "L"}
    with pytest.raises(ValidationError, match="huge"):
        cfg_with({"no_tests": "huge"})
    with pytest.raises(ValidationError, match="no_test"):
        cfg_with({"no_test": "S"})


# --- criterion 2: a model band is validated by the schema ------------------------------------

def _cand(**over) -> dict:
    return {"category": "security", "severity": "high", "title": "T", "summary": "s",
            "impact": "i", "remediation": "r", "line_start": 1, "line_end": 1,
            "confidence": 0.5, **over}


@pytest.mark.parametrize("cls", [CandidateFinding, ToolCandidateFinding])
def test_candidate_band_is_validated(cls):
    base = _cand() if cls is CandidateFinding else {
        k: v for k, v in _cand(paths=["a.py"]).items() if k not in ("line_start", "line_end")}
    assert cls.model_validate(base).effort is None  # missing: not estimated
    assert cls.model_validate({**base, "effort": "m", "effort_note": "one fix"}).effort == "M"
    assert cls.model_validate({**base, "effort": "None"}).effort is None
    with pytest.raises(ValidationError):
        cls.model_validate({**base, "effort": "huge"})


@pytest.mark.parametrize("cls", [UnitExtraction, ModuleRollup, DirectoryRollup, ToolRollup])
def test_structured_output_schemas_offer_the_bands(cls):
    schema = strict_schema(cls)
    assert schema["$defs"]["Effort"]["enum"] == ["S", "M", "L", "XL"]
    cand = next(d for n, d in schema["$defs"].items() if n.endswith("CandidateFinding"))
    assert {"effort", "effort_note"} <= set(cand["required"])
    # criterion 3: no model output carries a total or a day figure
    text = json.dumps(schema).lower()
    assert "total" not in text and "days" not in text


def test_verdict_may_carry_a_band():
    assert Verdict.model_validate({"verdict": "confirmed", "reason": "r"}).effort is None
    assert Verdict.model_validate({"verdict": "confirmed", "reason": "r",
                                   "effort": "xl"}).effort == "XL"
    assert strict_schema(Verdict)["$defs"]["Effort"]["enum"] == ["S", "M", "L", "XL"]


def test_verify_request_states_the_claimed_band_and_keeps_its_effort_level():
    from unvarnish.model.prompts.verify import build_verify_request

    req = build_verify_request(_f(effort="M"), ["x"], "high")
    assert req.effort == "high"  # the model's reasoning effort, not the band
    assert "Effort claimed: M\n" in req.messages[0].content
    assert "Effort claimed: not estimated" in build_verify_request(
        _f(), ["x"], None).messages[0].content


def _banded_unit_reply(req) -> str:
    data = json.loads(_unit_reply(req))
    for c in data["candidate_findings"]:
        c.update(effort="m", effort_note="move the value to configuration")
    return json.dumps(data)


def _verdict_l(req) -> str:
    body = req.messages[0].content
    if "Claim: Hardcoded credential" in body:
        assert "Effort claimed: M (move the value to configuration)" in body
    verdict = "rejected" if "README.md" in body else "confirmed"
    return json.dumps({"verdict": verdict, "reason": "checked the lines", "effort": "L"})


def test_model_bands_flow_through_and_the_verifier_adjusts(ingested):
    from tests.test_render_documents import _run_all

    eng, tool = ingested
    stub = _stub(UnitExtraction=_banded_unit_reply, Verdict=_verdict_l)
    ctx, results = _run_all(eng, tool, stub)
    assert all(r.status == PhaseStatus.ok for r in results), [r.message for r in results]
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    creds = [f for f in mf.findings if f.title == "Hardcoded credential"]
    confirmed = [f for f in creds if f.verification == "confirmed"]
    rejected = [f for f in creds if f.verification == "rejected"]
    assert confirmed and all(f.effort == Effort.L for f in confirmed)
    assert all("verifier" in (f.effort_note or "") for f in confirmed)
    assert rejected and all(f.effort == Effort.M for f in rejected)  # a rejection keeps it
    tool_level = next(f for f in mf.findings if f.title == "No auth anywhere")
    assert tool_level.effort is None
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "effort: L" in doc and "effort: not estimated" in doc
    assert "## Remediation outlook" in doc


# --- criterion 3: totals are computed from the JSON -----------------------------------------

def test_outlook_counts_bands_by_severity_from_the_findings():
    findings = [_f("high", "S"), _f("high", "M"), _f("medium", "XL"), _f("low", None)]
    out = remediation_outlook(findings, None)
    rows = {r["severity"]: r for r in out["rows"]}
    assert rows["high"]["counts"] == {"S": 1, "M": 1, "L": 0, "XL": 0, "none": 0}
    assert rows["medium"]["counts"]["XL"] == 1 and rows["low"]["counts"]["none"] == 1
    assert out["totals"] == {"S": 1, "M": 1, "L": 0, "XL": 1, "none": 1}
    assert out["total"] == 4 and out["days"] is None  # criterion 4: days are off by default
    with_days = remediation_outlook(findings, EffortDays(**DAYS))
    # each figure is the band's ceiling; the low end is the band below's (S from 0)
    assert with_days["days"]["low"] == "5.5" and with_days["days"]["high"] == "17.5"
    assert with_days["days"]["not_estimated"] == 1


def test_effort_counts_and_day_range():
    counts = effort_counts([_f(effort="S"), _f(effort="S"), _f(effort="XL"), _f()])
    assert counts == {"S": 2, "M": 0, "L": 0, "XL": 1, "none": 1}
    assert day_range(counts, EffortDays(**DAYS)) == (5.0, 16.0)


# --- criterion 4: the day mapping is configurable and off until set --------------------------

def test_effort_days_config():
    assert EngagementConfig().report.effort_days is None
    cfg = EngagementConfig.model_validate({"report": {"effort_days": DAYS}})
    assert cfg.report.effort_days.XL == 15
    with pytest.raises(ValidationError):
        EngagementConfig.model_validate({"report": {"effort_days": {"S": 1, "M": 2}}})
    with pytest.raises(ValidationError):  # bands must not shrink
        EngagementConfig.model_validate({"report": {"effort_days": {**DAYS, "L": 1}}})
    assert unknown_keys({"report": {"effort_days": {**DAYS, "XXL": 30}}}) == [
        "report.effort_days.XXL"]


def test_findings_doc_days_only_when_configured(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "## Remediation outlook" in doc and "| Severity | S | M | L | XL |" in doc
    assert "engineer-day" not in doc
    eng.config.report.effort_days = EffortDays(**DAYS)
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    assert results[-1].status == PhaseStatus.ok  # the day mapping re-renders
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "engineer-days" in doc and "estimate" in doc


def test_comparison_cost_to_fix_row_and_consolidation_fact(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    assert ComparePhase(backend=stub).run(ectx).status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    row = cmp.risk_table[0]
    assert sum(row.findings_by_effort.values()) == sum(row.findings_by_severity.values())
    consolidate = next(r for r in stub.requests if r.schema_name == "Consolidation")
    assert "## Cost to fix" in consolidate.messages[0].content
    assert "engineer-days" not in consolidate.messages[0].content
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text(encoding="utf-8")
    assert "| Cost to fix (effort bands) |" in doc and "engineer-days" not in doc

    engagement.config.report.effort_days = EffortDays(**DAYS)
    stub.requests.clear()
    run_comparison(engagement, backend=stub)
    consolidate = next(r for r in stub.requests if r.schema_name == "Consolidation")
    assert "engineer-days (estimate)" in consolidate.messages[0].content
    doc = engagement.comparison_doc.read_text(encoding="utf-8")
    assert "| Cost to fix (engineer-days, estimate) |" in doc


def test_old_risk_row_loads_without_bands():
    row = RiskRow.model_validate({"tool": "t", "model_analysed": False, "files_analysed": 1,
                                  "source_lines": 1, "largest_file_lines": 1,
                                  "tests_present": False, "secrets_current": 0,
                                  "secrets_history": 0, "bus_factor": None,
                                  "top_author_share": None})
    assert row.findings_by_effort == {}


# --- criterion 5: only the prompts whose schema or text changed are bumped -------------------

# Prompt versions and fingerprints on main before UNVAR-42. A prompt whose text is unchanged
# keeps its version (its caches stay valid); a prompt whose text changed must have a new one.
MAIN = {"extract": ("2026-10-19.1", "47d84c106dfa1f12"),
        "rollup_module": ("2026-10-18.1", "33eabfe704e6d666"),
        "rollup_tool": ("2026-10-19.1", "5f5118325e5a5704"),
        "verify": ("2026-10-19.2", "f86957fd21528734"),
        "compare": ("2026-10-19.2", "e0df6e518eedf1a6"),
        "ask": ("2026-10-17.1", "5da38c5cab521d36"),
        "prose": ("2026-10-18.1", "2ca3e3700d7c2943")}


def _h(*parts: str) -> str:
    return hashlib.sha256("\n\0".join(parts).encode("utf-8")).hexdigest()[:16]


def _prompts() -> dict[str, tuple[str, str]]:
    from unvarnish.model.prompts import compare, extract, rollup, verify
    from unvarnish.model.prompts.ask import ASK_PROMPT_VERSION, build_ask_system
    from unvarnish.render.prose import PROSE_PROMPT_VERSION, build_prose_system

    f = Finding(tool="t", category="security", severity="high", title="T", summary="s",
                impact="i", remediation="r", source="model",
                evidence=[Evidence(path="a.py", line_start=1)])
    return {
        "extract": (extract.PROMPT_VERSION, _h(extract.build_system_prompt())),
        "rollup_module": (rollup.ROLLUP_PROMPT_VERSION, _h(rollup.build_module_rollup_system())),
        "rollup_tool": (rollup.TOOL_ROLLUP_PROMPT_VERSION,
                        _h(rollup.build_directory_rollup_system(),
                           rollup.build_tool_rollup_system())),
        "verify": (verify.VERIFY_PROMPT_VERSION,
                   _h(verify.build_verify_system(),
                      verify.build_verify_request(f, ["x"], None).messages[0].content)),
        "compare": (compare.COMPARE_PROMPT_VERSION,
                    _h(compare.build_normalise_system(), compare.build_integrate_system(),
                       compare.build_consolidate_system())),
        "ask": (ASK_PROMPT_VERSION, _h(build_ask_system("S", 3))),
        "prose": (PROSE_PROMPT_VERSION, _h(build_prose_system("direct"),
                                           build_prose_system("measured"))),
    }


def test_prompt_versions_bumped_only_where_the_prompt_changed():
    now = _prompts()
    for name, (version, fp) in now.items():
        old_version, old_fp = MAIN[name]
        if fp == old_fp:
            assert version == old_version, f"{name}: unchanged prompt, version bumped"
        else:
            assert version > old_version, f"{name}: prompt changed without a version bump"
    changed = {n for n, (_, fp) in now.items() if fp != MAIN[n][1]}
    assert changed == {"extract", "rollup_module", "rollup_tool", "verify", "compare"}


def test_day_figures_and_cell_text_are_not_misleading():
    from unvarnish.analysis.effort import effort_text, fmt_days

    # A configured quarter day must not print as 0.2 in the mapping.
    assert fmt_days(0.25) == "0.25" and fmt_days(5.5) == "5.5" and fmt_days(16.0) == "16"
    assert fmt_days(1234.5) == "1,234.5"
    # A tool with no findings has nothing to estimate, not "none estimated".
    assert effort_text(effort_counts([])) == "no findings"
    assert effort_text({"S": 0, "M": 0, "L": 0, "XL": 0, "none": 2}) == "2 not estimated"
    mixed = {"S": 2, "M": 0, "L": 0, "XL": 1, "none": 3}
    assert effort_text(mixed) == "2 S · 1 XL; 3 not estimated"
