import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import fill_schema, request_schema
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()


def _engagement(tmp_path, synthetic_repo, fake, tools=("alpha", "beta")) -> Engagement:
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham Technologies")
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **model_config(fake)})
    eng.save_config()
    for name in tools:
        ingest_tool(eng, name, str(synthetic_repo), "repo")
    return eng


def test_compare_before_run_exits_2(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 2 and "unvarnish run" in out.output


def test_compare_two_tools_end_to_end(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert eng.comparison_doc.exists() and eng.comparison_file.exists()
    doc = eng.comparison_doc.read_text()
    assert "| Measure | alpha | beta |" in doc
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert "(engagement)" in status.output and "render_comparison" in status.output
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "compare" in cost.output and "(engagement)" in cost.output
    again = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert again.exit_code == 0 and "fresh" in again.output


def test_compare_single_tool_exits_0(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm, tools=("alpha",))
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert "Skipped: one tool" in eng.comparison_doc.read_text()


def test_compare_failed_consolidation_exits_1(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    filled = lambda body: json.dumps(fill_schema(request_schema(body)))  # noqa: E731
    # normalise and integration grouping succeed; consolidation fails
    fake_llm.script(filled, filled, "garbage", "garbage", "garbage")
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 1, out.output
    assert "recorded failure" in out.output
    assert json.loads(eng.comparison_file.read_text())["data"]["consolidation"] is None
