import json
from datetime import UTC, datetime

from tests.conftest import LEAKED_KEY
from tests.stub_backend import StubBackend
from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.index import build_index
from unvarnish.ask.loop import AskStep, call_args, find_citations, run_question, write_session
from unvarnish.ask.tools import AskTools
from unvarnish.model.budget import BudgetTracker
from unvarnish.schemas.cost import Usage


def _ready(engagement, synthetic_repo):
    _two_tools(engagement, synthetic_repo, _compare_stub())
    index = build_index(engagement)
    return index, AskTools(engagement, index)


def _answer(text: str, citations: list[str] | None = None) -> str:
    return json.dumps({"action": "answer", "answer": text, "citations": citations or []})


def _call(tool: str, **args) -> str:
    return json.dumps({"action": "call", "tool": tool, **args})


def _search_then_answer(req) -> str:
    """Call search_index on the first turn, then answer citing the first hit."""
    last = req.messages[-1].content
    if last.startswith("Result of search_index"):
        body = last.split('<tool_result name="search_index">\n', 1)[1].split("\n</tool_result>")[0]
        hits = json.loads(body)["hits"]
        return _answer(f"It is handled in {hits[0]['id']} ({hits[0]['path']}).", [hits[0]["id"]])
    return _call("search_index", query="does a thing", tool_name="alpha")


def test_call_args_maps_step_fields_and_tool_filter():
    step = AskStep(action="call", tool="get_findings", severity="high")
    assert call_args(step, "beta") == ("get_findings", {"tool": "beta", "severity": "high"})
    step = AskStep(action="call", tool="grep_source", pattern="x", tool_name="alpha",
                   max_results=3)
    assert call_args(step, None) == ("grep_source", {"pattern": "x", "tool": "alpha",
                                                     "max_results": 3})
    step = AskStep(action="call", tool="get_tool", tool_name="alpha")
    assert call_args(step, None) == ("get_tool", {"name": "alpha"})


def test_find_citations_validates_ids_and_paths(engagement, synthetic_repo):
    index, _ = _ready(engagement, synthetic_repo)
    unit_id = next(d.id for d in index.docs if d.kind == "unit")
    cap_id = next(d.id for d in index.docs if d.kind == "capability")
    text = f"See {unit_id} and app.py:12-20, also {cap_id} and nothing.py:3 and deadbeefdeadbeef."
    cites = find_citations(text, ["tool:alpha", "bogus", "README.md"], index)
    assert unit_id in cites and cap_id in cites and "app.py:12-20" in cites
    assert "tool:alpha" in cites and "README.md" in cites
    assert "bogus" not in cites and "nothing.py:3" not in cites
    assert "deadbeefdeadbeef" not in cites


def test_loop_calls_tool_then_answers_with_citations(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _search_then_answer})
    res = run_question(engagement, stub, tools, index, "Where is the thing handled?",
                       budget=BudgetTracker(None), effort=None, max_calls=12)
    assert res.completed and res.verified and res.citations
    assert [s.kind for s in res.steps] == ["call", "answer"]
    assert res.steps[0].tool == "search_index" and res.steps[0].args["tool"] == "alpha"
    assert res.usage.total() == 240 and stub.count("AskStep") == 2
    path = write_session(engagement, [res], datetime.now(UTC))
    text = path.read_text()
    assert path.parent == engagement.ask_sessions_dir and path.suffix == ".md"
    assert "Where is the thing handled?" in text and res.citations[0] in text
    assert "Unverified" not in text


def test_uncited_answer_is_marked_unverified(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _answer("It just does.")})
    res = run_question(engagement, stub, tools, index, "Why?", budget=BudgetTracker(None),
                       effort=None, max_calls=12)
    assert res.completed and not res.verified and res.citations == []
    text = write_session(engagement, [res], datetime.now(UTC)).read_text()
    assert "Unverified: no citations" in text


def test_loop_stops_at_max_tool_calls(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _call("get_findings")})
    res = run_question(engagement, stub, tools, index, "Everything?", budget=BudgetTracker(None),
                       effort=None, max_calls=3)
    assert not res.completed and not res.verified
    assert sum(1 for s in res.steps if s.kind == "call") == 3
    assert "did not produce an answer" in res.answer
    forced = stub.requests[-1].messages[-1].content
    assert "no tool calls left" in forced.lower()


def test_tool_errors_are_fed_back_not_raised(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    seen: list[str] = []

    def script(req) -> str:
        last = req.messages[-1].content
        seen.append(last[:60])
        if last.startswith("Result of get_unit"):
            assert "unit id" in last  # the tool error, fed back as a result
            return _answer("Could not find it; see README.md.", ["README.md"])
        return _call("get_unit", id="nope")

    res = run_question(engagement, StubBackend({"AskStep": script}), tools, index, "?",
                       budget=BudgetTracker(None), effort=None, max_calls=12)
    assert res.completed and res.verified and res.steps[0].result_preview
    assert "error" in res.steps[0].result_preview


def test_structured_failure_and_budget_stop(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    res = run_question(engagement, StubBackend({"AskStep": "garbage"}), tools, index, "?",
                       budget=BudgetTracker(None), effort=None, max_calls=2)
    assert not res.completed and res.answer.startswith("No answer:")
    assert res.steps[-1].kind == "error"
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    res = run_question(engagement, StubBackend({"AskStep": _answer("x")}), tools, index, "?",
                       budget=tracker, effort=None, max_calls=2)
    assert res.stopped_for_budget and not res.completed


def test_answers_and_tool_results_are_redacted(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _answer(f"The key is {LEAKED_KEY}, see app.py:2.",
                                           ["app.py:2"])})
    res = run_question(engagement, stub, tools, index, "key?", budget=BudgetTracker(None),
                       effort=None, max_calls=2)
    assert LEAKED_KEY not in res.answer and "redacted" in res.answer
    assert LEAKED_KEY not in write_session(engagement, [res], datetime.now(UTC)).read_text()
