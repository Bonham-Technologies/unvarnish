"""Tests pinning the fixes from the slice 3 whole-branch review."""
import json
import threading

import pytest

from tests.conftest import LEAKED_KEY
from tests.stub_backend import StubBackend
from tests.test_render_documents import _prose, _run_all, _stub, _verdict
from tests.test_rollup_modules import MODULE, UNIT
from tests.test_rollup_tool import DIRECTORY, TOOL, _rolled
from tests.test_verify import _unit_reply
from unvarnish.artifacts import read_artifact
from unvarnish.config import BackendCapabilities, EngagementConfig
from unvarnish.model.base import BackendUnavailable, CompletionRequest, CompletionResponse, Message
from unvarnish.model.budget import BudgetTracker, load_ledger
from unvarnish.model.prompts.rollup import (
    ToolFacts,
    build_directory_rollup_request,
    build_tool_rollup_request,
)
from unvarnish.model.structured import complete_structured
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.modelrun import ItemOutcome, run_parallel
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.verify import VerifyPhase
from unvarnish.render.markdown import cell, code_span
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.rollup import ModuleDigest
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings, Verdict

# --- C1: a failed tool rollup must not suppress findings.md -----------------------------

def test_failed_tool_rollup_still_renders_findings(ingested):
    eng, tool = ingested
    good = _stub()
    ctx, results = _run_all(eng, tool, good)
    assert ctx.paths.tool_model.exists()
    bad = _stub(ToolRollup="nope")
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    from tests.test_render_documents import _phases
    from unvarnish.phases.base import PhaseRunner
    results = PhaseRunner(_phases(bad)).run(ctx, force=True)
    by_name = {r.phase: r for r in results}
    assert by_name["rollup_tool"].status == PhaseStatus.ok and by_name["rollup_tool"].failures
    assert by_name["verify"].status == PhaseStatus.ok
    assert by_name["render"].status == PhaseStatus.ok
    assert ctx.paths.findings_doc.exists()
    assert not ctx.paths.tool_model.exists()  # the stale tool model from the good run is gone
    assert not ctx.paths.capabilities.exists()
    assert not ctx.paths.architecture_doc.exists()


# --- I1: rollup outputs need room, and truncation widens the retry ------------------------

def test_rollup_requests_set_generous_max_tokens():
    facts = ToolFacts(tool="t", languages={}, frameworks=[], files_analysed=1, source_lines=1)
    assert build_tool_rollup_request(facts, [], [], effort=None).max_tokens >= 16_000
    d = ModuleDigest(id="x", path="a.py", units=1, lines=1, summary="s")
    assert build_directory_rollup_request("", [d], effort=None).max_tokens >= 8_000


class _TruncatingBackend:
    name = "trunc"
    model = "m"
    capabilities = BackendCapabilities()

    def __init__(self) -> None:
        self.requests: list[CompletionRequest] = []

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        self.requests.append(req)
        if len(self.requests) == 1:
            return CompletionResponse(text='{"verdict": "conf', model="m",
                                      stop_reason="max_tokens")
        return CompletionResponse(text='{"verdict": "confirmed", "reason": "ok"}', model="m")


def test_structured_retry_widens_max_tokens_after_truncation():
    backend = _TruncatingBackend()
    req = CompletionRequest(system="s", messages=[Message(role="user", content="u")],
                            max_tokens=1000)
    res = complete_structured(backend, req, Verdict)
    assert res.parsed.verdict == "confirmed" and res.attempts == 2
    assert backend.requests[1].max_tokens >= 2 * backend.requests[0].max_tokens


# --- I2: model text inside Markdown tables and code spans ----------------------------------

def test_cell_and_code_span_filters():
    assert cell("a | b\nc") == "a \\| b c"
    assert cell(None) == ""
    assert code_span("x = `y`") == "`x = 'y'`"
    assert code_span("") == ""


def test_tables_survive_pipes_and_newlines_in_model_text(ingested):
    eng, tool = ingested
    tool_json = json.loads(TOOL)
    tool_json["entry_points"][0]["description"] = "has | pipe\nand newline"
    tool_json["module_map"][0]["role"] = "entry | point"
    tool_json["business_rules"][0]["description"] = "limit 500 | or 600\nnext"
    stub = _stub(ToolRollup=json.dumps(tool_json))
    ctx, results = _run_all(eng, tool, stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    arch = ctx.paths.architecture_doc.read_text()
    assert "| main | cli | `app.py` | has \\| pipe and newline |" in arch
    assert "| `app.py` | entry \\| point |" in arch
    req = ctx.paths.requirements_doc.read_text()
    assert "| limit 500 \\| or 600 next | threshold | `app.py` |" in req


# --- I3: line-less (tool-level) findings are not sent to a strict verifier ----------------

def test_verify_leaves_tool_level_findings_unverified_without_a_call(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL, "Verdict": _verdict})
    ctx = _rolled(eng, tool, stub)
    assert RollupToolPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    assert VerifyPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    sent = [r.messages[0].content for r in stub.requests if r.schema_name == "Verdict"]
    assert not any("No auth anywhere" in body for body in sent)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    f = next(f for f in mf.findings if f.title == "No auth anywhere")
    assert f.verification is None and "tool-level" in (f.verification_note or "")
    assert f.severity.value == "high"


# --- I4: failed chunks are reported honestly ----------------------------------------------

def test_rollup_tool_reports_failed_chunks(ingested):
    eng, tool = ingested
    eng.config = EngagementConfig.model_validate({
        **eng.config.model_dump(), "pipeline": {"rollup_input_tokens": 1}})
    eng.save_config()

    def directory(req):
        body = req.messages[0].content
        if "static/" in body or "Malformed output:\ngarbage" in body:
            return "garbage"  # fail on the attempt, the retry, and the repair
        return DIRECTORY

    stub = _stub(DirectoryRollup=directory)
    ctx, results = _run_all(eng, tool, stub)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    tm = read_artifact(ctx.paths.tool_model, ToolModel).data
    n_modules = len(json.loads(ctx.paths.modules_index.read_text())["data"]["modules"])
    assert tm.chunks_attempted == n_modules and tm.chunks < n_modules
    assert tm.chunks_failed and all("static" in c for c in tm.chunks_failed)
    assert tm.modules_covered == n_modules - len(tm.chunks_failed)
    arch = ctx.paths.architecture_doc.read_text()
    assert f"{tm.chunks} of {tm.chunks_attempted} directory chunks" in arch
    assert "chunks failed" in arch.lower()
    findings = ctx.paths.findings_doc.read_text()
    assert "Directory chunks whose rollup failed" in findings


# --- I5: one broken template override must not take the other documents down -------------

def test_render_isolates_broken_template_override(ingested):
    eng, tool = ingested
    override = eng.root / "templates"
    override.mkdir()
    (override / "architecture.md.j2").write_text("# broken {{ no_such_variable }}\n")
    ctx, results = _run_all(eng, tool, _stub())
    render = results[-1]
    assert render.status == PhaseStatus.ok
    assert any("architecture.md.j2" in f for f in render.failures)
    assert ctx.paths.findings_doc.exists() and ctx.paths.requirements_doc.exists()
    assert not ctx.paths.architecture_doc.exists()


# --- I6: worker crashes become recorded failures; cost survives a final-call outage --------

def test_run_parallel_records_worker_exceptions():
    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        if item == 1:
            raise OSError("disk full")
        return ItemOutcome(result=item)

    out = run_parallel([0, 1, 2], worker, workers=2, budget=BudgetTracker(None), phase="p")
    assert sorted(out.results) == [0, 2] and out.processed == 3
    assert len(out.failures) == 1 and out.failures[0].phase == "p"
    assert "disk full" in out.failures[0].error


def test_rollup_tool_records_cost_when_final_call_is_an_outage(ingested):
    eng, tool = ingested
    eng.config = EngagementConfig.model_validate({
        **eng.config.model_dump(), "pipeline": {"rollup_input_tokens": 1}})
    eng.save_config()
    stub = StubBackend({"UnitExtraction": UNIT, "ModuleRollup": MODULE,
                        "DirectoryRollup": DIRECTORY, "ToolRollup": BackendUnavailable("503")})
    ctx = _rolled(eng, tool, stub)
    with pytest.raises(BackendUnavailable):
        RollupToolPhase(backend=stub).run(ctx)
    phases = {e.phase for e in load_ledger(eng).entries}
    assert "rollup_tool" in phases


# --- I7: model text that reaches disk is redacted ----------------------------------------

def test_redact_text_removes_secrets():
    out = redact_text(f"the key is {LEAKED_KEY} ok")
    assert LEAKED_KEY not in out and "redacted" in out
    assert redact_text("nothing here") == "nothing here"


def test_verifier_notes_and_model_excerpts_are_redacted(ingested):
    eng, tool = ingested
    module = json.loads(MODULE)
    module["candidate_findings"][0]["excerpt"] = f"KEY = '{LEAKED_KEY}'"
    verdict = json.dumps({"verdict": "confirmed", "reason": f"line 1 holds {LEAKED_KEY}"})
    stub = _stub(ModuleRollup=json.dumps(module), Verdict=verdict, prose=_prose)
    ctx, results = _run_all(eng, tool, stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    raw = ctx.paths.model_findings.read_text()
    assert LEAKED_KEY not in raw
    for p in ctx.paths.module_dir.glob("*.json"):
        assert LEAKED_KEY not in p.read_text()
    assert LEAKED_KEY not in ctx.paths.findings_doc.read_text()
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    noted = [f for f in mf.findings if f.verification_note and "redacted" in f.verification_note]
    assert noted
