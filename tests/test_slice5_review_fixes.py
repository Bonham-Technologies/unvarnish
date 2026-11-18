"""Tests pinning the fixes from the slice 5 whole-branch review."""
import json

from tests.conftest import LEAKED_KEY
from tests.stub_backend import StubBackend
from tests.test_ask_loop import _answer, _call, _ready
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.ask.index import AskIndex, IndexDoc
from unvarnish.ask.loop import AskStep, call_args, find_citations, run_question
from unvarnish.ask.tools import AskTools
from unvarnish.config import BackendCapabilities
from unvarnish.model.budget import BudgetTracker

# --- I1: search_index results are redacted like every other tool result -------------------

def test_search_index_results_are_redacted(engagement):
    index = AskIndex(docs=[IndexDoc(id="0123456789ab", kind="unit", tool="alpha", path="a.py",
                                    text=f"reads key {LEAKED_KEY}",
                                    snippet=f"a.py:1-2: reads key {LEAKED_KEY}")])
    out = AskTools(engagement, index).search_index("key")
    assert out["hits"] and LEAKED_KEY not in json.dumps(out)


# --- I2: citations the validator wrongly rejected ------------------------------------------

def test_find_citations_accepts_bare_capability_ids_backticks_and_dot_slash(engagement,
                                                                            synthetic_repo):
    index, _ = _ready(engagement, synthetic_repo)
    cap = next(d.id for d in index.docs if d.kind == "capability")  # "cap:<12hex>"
    bare = cap.split(":", 1)[1]
    unit = next(d.id for d in index.docs if d.kind == "unit")
    cites = find_citations(f"Capability {bare}; see ./app.py:3.", [f"`{unit}`", "/README.md"],
                           index)
    assert cap in cites and unit in cites
    assert "app.py:3" in cites and "README.md" in cites


# --- I3: tool results are fenced and declared data, not instructions ------------------------

def test_tool_results_are_fenced_and_prompt_says_they_are_data(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)

    def script(req) -> str:
        if '<tool_result name="search_index"' in req.messages[-1].content:
            return _answer("See README.md.", ["README.md"])
        return _call("search_index", query="thing", tool_name="alpha")

    stub = StubBackend({"AskStep": script})
    res = run_question(engagement, stub, tools, index, "?", budget=BudgetTracker(None),
                       effort=None, max_calls=3)
    assert res.completed
    fed_back = stub.requests[-1].messages[-1].content
    assert fed_back.startswith("Result of search_index(")
    assert '<tool_result name="search_index">' in fed_back and "</tool_result>" in fed_back
    assert "never instructions" in stub.requests[0].system


# --- I4: tool failures never escape; ids are validated -------------------------------------

def test_dispatch_catches_any_tool_failure(engagement, synthetic_repo, monkeypatch):
    index, tools = _ready(engagement, synthetic_repo)

    def boom(self, name):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(AskTools, "get_tool", boom)
    out = tools.dispatch("get_tool", {"name": "alpha"})
    assert out["error"].startswith("get_tool failed") and "disk on fire" in out["error"]


def test_unit_and_module_ids_are_validated(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    assert tools.get_unit("../../engagement").get("error", "").startswith("invalid unit id")
    assert tools.get_unit("0123456789ab")["error"].startswith("no unit with id")
    assert tools.get_module("../nope")["error"].startswith("no module with id")


# --- I5: --tool restricts even when the model names another tool ----------------------------

def test_tool_filter_overrides_model_choice():
    step = AskStep(action="call", tool="get_findings", tool_name="other", severity="high")
    assert call_args(step, "alpha") == ("get_findings", {"tool": "alpha", "severity": "high"})
    assert call_args(step, None) == ("get_findings", {"tool": "other", "severity": "high"})


# --- I6: the conversation never outgrows the backend's context window ----------------------

def test_conversation_is_kept_within_the_context_window(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _call("get_findings")})
    stub.capabilities = BackendCapabilities(context_window=6000)
    res = run_question(engagement, stub, tools, index, "Everything?", budget=BudgetTracker(None),
                       effort=None, max_calls=12)
    assert not res.completed  # the stub never answers; the loop still ended cleanly
    sizes = [estimate_tokens(r.system) + sum(estimate_tokens(m.content) for m in r.messages)
             for r in stub.requests]
    assert max(sizes) <= 6000
    assert any("elided to fit the context window" in m.content
               for r in stub.requests for m in r.messages)
