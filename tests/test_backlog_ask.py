"""Known-issues burn-down, task 6: ask mode."""
import json
from datetime import UTC, datetime

from typer.testing import CliRunner

from tests.conftest import LEAKED_KEY
from tests.stub_backend import StubBackend
from tests.test_ask_loop import _answer, _call, _ready
from unvarnish.ask.loop import run_question, write_session
from unvarnish.cli import app
from unvarnish.model.budget import BudgetTracker

runner = CliRunner()


def test_a_call_without_a_tool_does_not_spend_the_forced_answer(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    replies = iter([json.dumps({"action": "call"}), _call("search_index", query="thing"),
                    _answer("Found it in README.md.", ["README.md"])])
    stub = StubBackend({"AskStep": lambda req: next(replies)})
    res = run_question(engagement, stub, tools, index, "Where?", budget=BudgetTracker(None),
                       effort=None, max_calls=3)
    assert res.completed and res.answer.startswith("Found it")
    assert any("name a tool" in (m.content or "") for r in stub.requests for m in r.messages)


def test_unknown_tools_get_an_error_result(engagement, synthetic_repo):
    _, tools = _ready(engagement, synthetic_repo)
    assert "unknown tool" in tools.dispatch("delete_everything", {})["error"]


def test_schema_is_sent_once_on_non_native_backends(engagement, synthetic_repo):
    from unvarnish.ask.loop import AskStep
    from unvarnish.model.structured import strict_schema

    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _answer("See README.md.", ["README.md"])}, json_schema=False)
    run_question(engagement, stub, tools, index, "Q?", budget=BudgetTracker(None), effort=None,
                 max_calls=2)
    system = stub.requests[0].system
    assert json.dumps(strict_schema(AskStep)) not in system  # not appended a second time
    assert "action" in system


def test_bm25_is_built_once_per_index(engagement, synthetic_repo, monkeypatch):
    import unvarnish.ask.index as index_mod

    index, _ = _ready(engagement, synthetic_repo)
    built = []
    real = index_mod.BM25

    def counting(*a, **k):
        built.append(1)
        return real(*a, **k)

    monkeypatch.setattr(index_mod, "BM25", counting)
    index.search("thing")
    index.search("other thing")
    index.search("thing", tool="alpha")
    assert len(built) <= 2  # one for all tools, one for the alpha filter


def test_grep_source_cuts_very_long_lines(engagement, synthetic_repo):
    _, tools = _ready(engagement, synthetic_repo)
    src = engagement.tool_paths("alpha").source / "bundle.js"
    src.write_text("x" * 60_000 + "NEEDLE" + "y" * 60_000 + "\nshort NEEDLE line\n")
    from unvarnish.phases.base import build_context
    from unvarnish.phases.inventory import InventoryPhase

    InventoryPhase().run(build_context(engagement, "alpha"))  # the census must list the file
    out = tools.grep_source(pattern="NEEDLE", tool="alpha")
    lines = [m for m in out["matches"] if m["path"] == "bundle.js"]
    assert [m["line"] for m in lines] == [2]
    assert all(len(m["text"]) <= 2_000 for m in out["matches"])


def test_sessions_redact_questions_and_name_files_to_the_millisecond(engagement):
    from unvarnish.ask.loop import AskResult

    started = datetime(2026, 10, 19, 12, 0, 0, 123456, tzinfo=UTC)
    r = AskResult(question=f"Is {LEAKED_KEY} still valid?", answer="No.", tool_filter=None)
    path = write_session(engagement, [r], started)
    assert path.name == "20261019-120000-123.md"
    assert LEAKED_KEY not in path.read_text()


def test_ask_log_is_named_for_ask(engagement):
    from unvarnish.util.logging import setup_run_logging

    assert setup_run_logging(engagement, prefix="ask").name.startswith("ask-")


def test_interactive_blank_lines_do_not_end_the_session(tmp_path, synthetic_repo, fake_llm):
    from tests.test_cli_ask import _engagement

    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("One, see README.md.", ["README.md"]))
    out = runner.invoke(app, ["ask", "-e", str(eng.root)], input="\nfirst?\nexit\n")
    assert out.exit_code == 0, out.output
    assert "One, see README.md." in out.output


def test_ctrl_c_still_reports_the_saved_session(tmp_path, synthetic_repo, fake_llm,
                                                monkeypatch):
    import unvarnish.cli as cli
    from tests.test_cli_ask import _engagement

    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("One, see README.md.", ["README.md"]))
    asked = iter(["first?"])

    def fake_input(prompt=""):
        try:
            return next(asked)
        except StopIteration:
            raise KeyboardInterrupt from None

    monkeypatch.setattr(cli.console, "input", fake_input)
    out = runner.invoke(app, ["ask", "-e", str(eng.root)])
    assert "Session saved" in out.output


def test_large_tool_results_are_truncated_with_a_note(engagement, synthetic_repo, monkeypatch):
    import unvarnish.ask.tools as tools_mod

    _, tools = _ready(engagement, synthetic_repo)
    monkeypatch.setattr(tools_mod, "RESULT_CHARS", 200)
    out = tools.dispatch("get_tool", {"name": "alpha"})
    assert "truncated" in json.dumps(out)


def test_get_module_by_path(engagement, synthetic_repo):
    _, tools = _ready(engagement, synthetic_repo)
    out = tools.get_module("app.py")
    assert out["path"] == "app.py" and out["tool"] in ("alpha", "beta")
