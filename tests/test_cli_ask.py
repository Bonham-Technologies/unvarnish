import json

from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()


def _engagement(tmp_path, synthetic_repo, fake, **extra) -> Engagement:
    eng = Engagement.create(tmp_path / "acme", client="Acme")
    conf = {**eng.config.model_dump(), **model_config(fake), **extra}
    eng.config = EngagementConfig.model_validate(conf)
    eng.save_config()
    ingest_tool(eng, "alpha", str(synthetic_repo), "repo")
    fake.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    return eng


def _answer(text: str, citations=None) -> str:
    return json.dumps({"action": "answer", "answer": text, "citations": citations or []})


def test_ask_without_model_exits_2(tmp_path, synthetic_repo):
    eng = Engagement.create(tmp_path / "acme")
    ingest_tool(eng, "alpha", str(synthetic_repo), "repo")
    out = runner.invoke(app, ["ask", "anything?", "-e", str(eng.root)])
    assert out.exit_code == 2 and "needs a model" in out.output


def test_ask_one_shot_answers_and_saves_session(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("The entry point is app.py:5.", ["app.py:5"]))
    out = runner.invoke(app, ["ask", "Where is the entry point?", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert "The entry point is app.py:5." in out.output and "app.py:5" in out.output
    assert "unverified" not in out.output.lower()
    sessions = list(eng.ask_sessions_dir.glob("*.md"))
    assert len(sessions) == 1 and "Where is the entry point?" in sessions[0].read_text()
    assert eng.index_file.exists()
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "ask" in cost.output


def test_ask_uncited_answer_warns(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("Trust me."))
    out = runner.invoke(app, ["ask", "Why?", "-e", str(eng.root)])
    assert out.exit_code == 0 and "unverified" in out.output.lower()


def test_ask_interactive_until_exit(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("One, see README.md.", ["README.md"]),
                    _answer("Two, see README.md.", ["README.md"]))
    out = runner.invoke(app, ["ask", "-e", str(eng.root)], input="first?\nsecond?\nexit\n")
    assert out.exit_code == 0, out.output
    assert "One, see README.md." in out.output and "Two, see README.md." in out.output
    session = next(eng.ask_sessions_dir.glob("*.md")).read_text()
    assert "## Q1. first?" in session and "## Q2. second?" in session


def test_ask_loop_limit_exits_1(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm, ask={"max_tool_calls": 2})
    # autofill answers every turn with action "call" (first enum value), so the loop hits
    # the limit, is asked to answer, still calls, and gives up
    out = runner.invoke(app, ["ask", "Everything?", "-e", str(eng.root)])
    assert out.exit_code == 1, out.output
    assert "did not produce an answer" in out.output


def test_ask_unknown_tool_filter_exits_2(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    out = runner.invoke(app, ["ask", "x?", "--tool", "nope", "-e", str(eng.root)])
    assert out.exit_code == 2 and "unknown tool" in out.output
