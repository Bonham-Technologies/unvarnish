import pytest
from jinja2 import DictLoader, Environment, TemplateRuntimeError

from tests.stub_backend import StubBackend
from unvarnish.model.base import BackendError, BackendUnavailable
from unvarnish.model.budget import BudgetTracker
from unvarnish.render.markdown import ProseExtension, make_env, prose_block_names
from unvarnish.render.prose import (
    BLOCKS,
    FALLBACK,
    build_prose_request,
    clean_prose,
    generate_prose,
)
from unvarnish.schemas.cost import Usage


def _env(source: str) -> Environment:
    return Environment(loader=DictLoader({"t.md.j2": source}), extensions=[ProseExtension])


def test_prose_tag_renders_from_prose_dict():
    env = _env('A {% prose "executive_summary" %} B')
    out = env.get_template("t.md.j2").render(prose={"executive_summary": "X"})
    assert out == "A X B"


def test_prose_tag_unknown_block_raises():
    env = _env('{% prose "nope" %}')
    with pytest.raises(TemplateRuntimeError, match="nope"):
        env.get_template("t.md.j2").render(prose={})


def test_prose_block_names_from_template_source():
    env = _env('x {% prose "a_block" %} y {%  prose  "b_block"  %} {% prose "a_block" %}')
    assert prose_block_names(env, "t.md.j2") == ["a_block", "b_block"]


def test_findings_template_declares_executive_summary():
    assert "executive_summary" in prose_block_names(make_env(), "findings.md.j2")


def test_prose_request_carries_tone_instruction_and_facts():
    block = BLOCKS["executive_summary"]
    req = build_prose_request(block, {"tool": "x", "critical": 2}, tone="direct", effort="low")
    assert req.schema_name == "prose" and req.output_schema is None
    assert "minor, simply, just" in req.system
    assert '"critical": 2' in req.messages[0].content
    assert f"under {block.max_words} words" in req.messages[0].content
    measured = build_prose_request(block, {}, tone="measured", effort=None)
    assert "acknowledge uncertainty" in measured.system and "minimise" in measured.system


def test_clean_prose_strips_fences_and_whitespace():
    assert clean_prose("```markdown\nHello.\n```\n") == "Hello."
    assert clean_prose("  Plain.  ") == "Plain."


def test_generate_prose_without_backend_falls_back():
    res = generate_prose(None, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert res.text == {"executive_summary": FALLBACK.format(reason="no model configured")}
    assert res.failures == [] and res.usage.total() == 0


def test_generate_prose_with_backend():
    stub = StubBackend({"prose": "A paragraph."})
    res = generate_prose(stub, {"executive_summary": {"a": 1}, "deployment": {}},
                         tone="direct", effort=None, budget=BudgetTracker(None))
    assert res.text == {"executive_summary": "A paragraph.", "deployment": "A paragraph."}
    assert res.usage.total() == 240 and stub.count("prose") == 2


def test_generate_prose_unknown_block_falls_back():
    stub = StubBackend({"prose": "A paragraph."})
    res = generate_prose(stub, {"nonexistent": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert res.text["nonexistent"].startswith("_No model-written text")
    assert "unknown prose block" in res.text["nonexistent"]
    assert res.failures and res.failures[0].unit_id == "nonexistent"
    assert stub.requests == []


def test_generate_prose_failure_and_refusal_fall_back():
    stub = StubBackend({"prose": BackendError("400")})
    res = generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert "model call failed" in res.text["executive_summary"] and len(res.failures) == 1

    def refuse(req):
        return ""
    stub2 = StubBackend({"prose": refuse})
    res2 = generate_prose(stub2, {"executive_summary": {}}, tone="direct", effort=None,
                          budget=BudgetTracker(None))
    assert "empty" in res2.text["executive_summary"] and len(res2.failures) == 1


def test_generate_prose_outage_propagates():
    stub = StubBackend({"prose": BackendUnavailable("down")})
    with pytest.raises(BackendUnavailable):
        generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                       budget=BudgetTracker(None))


def test_generate_prose_budget_stop():
    stub = StubBackend({"prose": "A paragraph."})
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    res = generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=tracker)
    assert res.stopped_for_budget and "budget cap" in res.text["executive_summary"]
    assert stub.requests == []
