"""Known-issues burn-down, task 4: model layer and analysis."""
import json
import threading
from types import SimpleNamespace

import pytest

from tests.stub_backend import StubBackend
from unvarnish.model.base import CompletionRequest, Message


def _req(max_tokens=100):
    return CompletionRequest(system="s", messages=[Message(role="user", content="u")],
                             max_tokens=max_tokens)


def test_dry_run_labels_cost_as_an_estimate():
    from unvarnish.cli import _usd
    from unvarnish.config import Prices
    from unvarnish.schemas.cost import Usage

    assert _usd(Usage(input_tokens=1_000_000), Prices(input_per_mtok=2, output_per_mtok=10)) \
        == " (≈ USD 2.00)"


def test_style_blocks_inside_script_templates_are_not_split_twice():
    from unvarnish.analysis.split import split_file

    src = (b"<html><body>\n<script type=\"text/template\">\n<div class=\"x\"></div>\n"
           b"<style>.x { color: red; }</style>\n</script>\n</body></html>\n")
    units = split_file(src, "a.html", "html", 8000, tool="t", generated=False)
    spans = sorted((u.byte_start, u.byte_end) for u in units)
    assert all(b[0] >= a[1] for a, b in zip(spans, spans[1:], strict=False)), spans


def test_openai_backend_switches_to_max_completion_tokens():
    import httpx2 as httpx
    import openai

    from tests.test_rc_fixes import _backend
    from unvarnish.model.base import CompletionResponse  # noqa: F401

    req_http = httpx.Request("POST", "http://llm/v1/chat/completions")
    bad = openai.BadRequestError(
        "Unsupported parameter: 'max_tokens' is not supported with this model. Use "
        "'max_completion_tokens' instead.", response=httpx.Response(400, request=req_http),
        body=None)
    ok = SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content="{}", refusal=None), finish_reason="stop")],
        usage=None, model="m")
    sent = []

    class Comp:
        def create(self, **kw):
            sent.append(kw)
            if "max_tokens" in kw:
                raise bad
            return ok

    b, _ = _backend([])
    b._client = SimpleNamespace(chat=SimpleNamespace(completions=Comp()))
    assert b.complete(_req()).text == "{}"
    assert "max_completion_tokens" in sent[-1] and "max_tokens" not in sent[-1]
    b.complete(_req())  # remembered: no failed attempt the second time
    assert "max_tokens" not in sent[-1] and len(sent) == 3


def test_render_runs_after_a_budget_stop():
    from unvarnish.phases.base import PhaseResult, PhaseRunner, PhaseStatus

    class P:
        def __init__(self, name, status, after_stop=False):
            self.name, self._status, self.runs_after_stop = name, status, after_stop
            self.ran = False

        def inputs_hash(self, ctx):
            return "h"

        def outputs(self, ctx):
            return []

        def run(self, ctx):
            self.ran = True
            return PhaseResult(phase=self.name, status=self._status)

    extract = P("extract", PhaseStatus.stopped)
    verify = P("verify", PhaseStatus.ok)
    render = P("render", PhaseStatus.ok, after_stop=True)
    PhaseRunner([extract, verify, render]).run(SimpleNamespace())
    assert render.ran and not verify.ran


def test_dedupe_keeps_counts_and_unknown_confidence():
    from tests.test_verify import _finding
    from unvarnish.phases.verify import dedupe_findings

    a = _finding(title="Missing error handling", line=10, confidence=None)
    b = _finding(title="Missing error handling", line=300, confidence=None)
    [merged] = dedupe_findings([a, b])
    assert merged.confidence is None and "occurrences:2" in merged.tags


def test_collect_reads_only_units_in_the_current_index(ingested):
    from tests.test_rollup_modules import MODULE
    from tests.test_rollup_tool import TOOL
    from tests.test_verify import _pipeline, _unit_reply
    from unvarnish.phases.verify import collect_model_findings

    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL})
    ctx = _pipeline(eng, tool, stub)
    before = len(collect_model_findings(ctx))
    stale = ctx.paths.unit_dir / "deadbeef0000.json"
    stale.write_text(next(ctx.paths.unit_dir.glob("*.json")).read_text())
    assert len(collect_model_findings(ctx)) == before


def test_store_and_system_module_lists_keep_only_known_paths():
    from unvarnish.phases.rollup_tool import build_tool_model
    from unvarnish.schemas.cost import Usage
    from unvarnish.schemas.toolmodel import ToolRollup

    roll = ToolRollup.model_validate({
        "purpose": "p", "actors": [], "entry_points": [], "internal_stack": [],
        "module_map": [], "data_flows": [], "deployment_assumptions": [], "capabilities": [],
        "business_rules": [], "open_questions": [], "candidate_findings": [], "confidence": .5,
        "data_stores": [{"name": "db", "kind": "db", "description": "d",
                         "modules": ["app.py", "invented.py"]}],
        "external_systems": [{"name": "api", "kind": "http", "direction": "outbound",
                              "description": "d", "modules": ["nope.py", "app.py"]}]})
    tm = build_tool_model("t", roll, {"app.py"}, chunk_rollups=[], backend_name="b",
                          model="m", usage=Usage(), attempts=1, modules_covered=1)
    assert tm.data_stores[0].modules == ["app.py"] and tm.external_systems[0].modules == [
        "app.py"]


def test_chunk_labels_are_unique():
    from unvarnish.phases.rollup_tool import partition_digests
    from unvarnish.schemas.rollup import ModuleDigest

    digests = [ModuleDigest(id=str(i), path=f"src/big/m{i:03}.py", units=1, lines=10,
                            summary="x" * 400) for i in range(60)]
    chunks = partition_digests(digests, 2000)
    labels = [label for label, _ in chunks]
    assert len(chunks) > 1 and len(set(labels)) == len(labels)


def test_prose_tags_accept_single_quotes():
    from unvarnish.render.markdown import PROSE_TAG_RE

    assert PROSE_TAG_RE.findall("{% prose 'executive_summary' %} {% prose \"deployment\" %}") \
        == ["executive_summary", "deployment"]


def test_truncated_prose_is_retried_with_more_room():
    from unvarnish.model.base import CompletionResponse
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.render.prose import generate_prose
    from unvarnish.schemas.cost import Usage

    calls = []

    class B:
        name, model = "b", "m"
        capabilities = None

        def complete(self, req):
            calls.append(req.max_tokens)
            stop = "max_tokens" if len(calls) == 1 else "end_turn"
            return CompletionResponse(text="text " * len(calls), model="m", usage=Usage(),
                                      stop_reason=stop)

    out = generate_prose(B(), {"deployment": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert calls == [2000, 4000] and out.text["deployment"].strip() == "text text"
    assert out.failures == []


def test_module_rollup_message_fits_the_context_window():
    from tests.test_rollup_modules import UNIT  # noqa: F401
    from unvarnish.model.prompts.rollup import build_module_message
    from unvarnish.schemas.analysis import Unit, UnitExtraction, UnitKind, UnitResult
    from unvarnish.schemas.cost import Usage

    big = "x" * 4000
    results = [UnitResult(
        unit=Unit(id=f"u{i}", tool="t", module_id="a.py", path="a.py", language="python",
                  kind=UnitKind.function, line_start=i, line_end=i, byte_start=0, byte_end=1,
                  token_estimate=1, split_method="structural"),
        extraction=UnitExtraction(purpose=big, confidence=.5), backend="b", model="m",
        usage=Usage(), prompt_version="v") for i in range(1, 41)]
    text = build_module_message("a.py", "python", 100, results, [], max_tokens=8000)
    from unvarnish.analysis.tokens import estimate_tokens

    assert estimate_tokens(text) <= 8000 and "omitted to fit" in text


def test_call_structured_reraises_configuration_errors():
    from unvarnish.model.base import BackendConfigError
    from unvarnish.phases.modelrun import call_structured
    from unvarnish.schemas.analysis import UnitExtraction

    stub = StubBackend({"UnitExtraction": BackendConfigError("no key")})
    with pytest.raises(BackendConfigError):
        call_structured(stub, CompletionRequest(system="s", messages=[
            Message(role="user", content="u")], schema_name="UnitExtraction"),
            UnitExtraction, phase="extract", item_id="x", path="a", stop=threading.Event())


def test_empty_module_map_has_no_mermaid():
    from unvarnish.render.architecture import module_mermaid_or_none

    assert module_mermaid_or_none(SimpleNamespace(module_map=[])) is None


def test_data_inventory_used_by_matches_whole_names():
    from unvarnish.phases.rollup_tool import uses_store

    assert uses_store("Orders DB", ["orders db"])
    assert uses_store("IndexedDB video-editor-db", ["video-editor-db IndexedDB"])
    assert not uses_store("DB", ["Orders DB"])           # a fragment is not a match
    assert not uses_store("Orders DB", ["Orders"])


def test_render_with_failed_prose_stays_stale(ingested):
    """A model call that failed left fallback text that only --force replaced."""
    from unvarnish.model.base import BackendError
    from unvarnish.phases.base import PhaseRunner, build_context, is_fresh
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    eng, tool = ingested
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    failing = StubBackend({"prose": BackendError("server error")})
    RenderPhase(backend=failing).run(ctx)
    assert not is_fresh(RenderPhase(backend=failing), ctx)


def test_model_text_is_redacted_before_it_is_stored():
    from unvarnish.scanners.secrets import redact_model_text
    from unvarnish.schemas.analysis import UnitExtraction

    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    e = UnitExtraction(purpose=f"Uses {key} to sign requests", risks=[f"key {key}"],
                       confidence=.5)
    clean = redact_model_text(e)
    assert key not in json.dumps(clean.model_dump())


def test_probe_context_detects_truncation():
    from unvarnish.model.base import CompletionResponse
    from unvarnish.model.probe import probe_context
    from unvarnish.schemas.cost import Usage

    class Truncating:
        name, model = "b", "m"

        def complete(self, req):
            return CompletionResponse(text="I do not see a code word.", model="m",
                                      usage=Usage(input_tokens=4096))

    class Honest:
        name, model = "b", "m"

        def complete(self, req):
            word = req.messages[0].content.split("code word is ", 1)[1].split(".")[0]
            return CompletionResponse(text=word, model="m", usage=Usage(input_tokens=6200))

    ok, note = probe_context(Truncating(), 6000)
    assert not ok and "truncat" in note
    assert probe_context(Honest(), 6000)[0]


def test_documents_cap_long_model_lists():
    from unvarnish.render.markdown import make_env

    env = make_env()
    assert env.filters["cap"](list(range(100)), 60) == list(range(60))
    assert env.globals["more"](list(range(100)), 60) == "(+40 more in the analysis files)"
    assert env.globals["more"](list(range(10)), 60) == ""


def test_templates_cap_every_model_written_list():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src/unvarnish/render/templates"
    arch = (root / "architecture.md.j2").read_text(encoding="utf-8")
    req = (root / "requirements.md.j2").read_text(encoding="utf-8")
    for name in ("tm.entry_points", "tm.data_flows", "tm.deployment_assumptions"):
        assert f"in {name} | cap %" in arch and f"more({name})" in arch
    for name in ("capabilities", "req.open_questions", "req.business_rules"):
        assert f"in {name} | cap %" in req and f"more({name})" in req
