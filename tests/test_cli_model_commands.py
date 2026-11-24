import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import FakeLLM
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement

runner = CliRunner()


def _engagement(tmp_path, fake: FakeLLM | None = None, **extra) -> Engagement:
    eng = Engagement.create(tmp_path / "e", client="Acme")
    data = eng.config.model_dump()
    if fake is not None:
        data.update(model_config(fake))
    data.update(extra)
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    return eng


def test_config_check_without_model(tmp_path):
    eng = _engagement(tmp_path)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0 and "no model configured" in r.output


def test_config_check_without_model_says_scanners_work_and_prints_no_table(tmp_path):
    # UNVAR-83: a header-only table made the first command a new user runs look broken.
    eng = _engagement(tmp_path)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "┏" not in r.output and "schema" not in r.output
    lines = [line for line in r.output.splitlines() if line.strip()]
    assert len(lines) == 1, r.output
    assert "still runs the scanners" in r.output and "models.default" in r.output
    assert "extract:" not in r.output and "other phases:" not in r.output


GOOD_EXTRACTION = json.dumps({
    "purpose": "Assigns one.", "interface": [], "external_calls": [], "data_read": [],
    "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
    "candidate_findings": [], "confidence": 0.5,
})


def test_config_check_probes_backend(tmp_path, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script(GOOD_EXTRACTION)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "fake-model" in r.output and "probe" in r.output.lower() and "ok" in r.output
    assert fake_llm.requests and fake_llm.requests[0]["path"] == "/v1/messages"
    r2 = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r2.exit_code == 0 and len(fake_llm.requests) == 1


def test_config_check_headers_are_not_truncated_at_80_columns(tmp_path, fake_llm: FakeLLM,
                                                              monkeypatch):
    # UNVAR-83: at 80 columns the headers read "json_sche…" and "tool_call…".
    from rich.console import Console

    from unvarnish import cli

    monkeypatch.setattr(cli, "console", Console(width=80))
    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script(GOOD_EXTRACTION)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    for word in ("phase", "backend", "model", "json", "schema", "tool", "calling", "context",
                 "probe"):
        assert word in r.output, r.output
    assert "…" not in r.output, r.output
    assert max(len(line) for line in r.output.splitlines()) <= 80


def test_config_check_missing_key_is_exit_2(tmp_path, fake_llm: FakeLLM, monkeypatch):
    eng = _engagement(tmp_path, fake_llm)
    monkeypatch.delenv("UNVARNISH_TEST_KEY", raising=False)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2 and "UNVARNISH_TEST_KEY" in r.output


def test_cache_clear(tmp_path):
    eng = _engagement(tmp_path)
    d = eng.cache_dir / "responses"
    d.mkdir(parents=True)
    (d / "a.json").write_text("{}")
    r = runner.invoke(app, ["cache", "clear", "-e", str(eng.root)], input="n\n")
    assert r.exit_code == 1 and (d / "a.json").exists()
    r = runner.invoke(app, ["cache", "clear", "--yes", "-e", str(eng.root)])
    assert r.exit_code == 0 and "1" in r.output and not (d / "a.json").exists()


def test_run_exit_code_3_on_budget(tmp_path, synthetic_repo, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm, budget={"max_tokens": 150},
                      pipeline={"concurrency": 1})
    good = json.dumps({"purpose": "p", "interface": [], "external_calls": [], "data_read": [],
                       "data_written": [], "auth_behaviour": None, "error_handling": None,
                       "risks": [], "candidate_findings": [], "confidence": 0.5})
    fake_llm.script(*([good] * 300))
    r = runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 3, r.output
    assert "budget" in r.output.lower()
    st = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert st.exit_code == 0 and "budget" in st.output.lower()


def test_run_exit_code_2_on_backend_error(tmp_path, synthetic_repo, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm)
    err = {"status": 401, "body": {"type": "error", "error": {
        "type": "authentication_error", "message": "bad key"}}}
    fake_llm.script(*([err] * 50))
    r = runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 2 and "bad key" in r.output


# --- fixes from the whole-branch review -------------------------------------
def test_config_check_probes_with_the_real_extraction_schema(tmp_path, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm)
    good = json.dumps({"purpose": "p", "interface": [], "external_calls": [], "data_read": [],
                       "data_written": [], "auth_behaviour": None, "error_handling": None,
                       "risks": [], "candidate_findings": [], "confidence": 0.5})
    fake_llm.script(good)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    schema = fake_llm.requests[0]["output_config"]["format"]["schema"]
    assert "candidate_findings" in schema["properties"]
    assert eng.config.pipeline.rate_limit_retries == 8


def test_config_check_probe_usage_reaches_the_cost_ledger(tmp_path, fake_llm: FakeLLM):
    """UNVAR-33: the structured-output probe and the context probe spend tokens."""
    from unvarnish.model.budget import load_ledger

    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script(GOOD_EXTRACTION)
    r = runner.invoke(app, ["config", "check", "--probe-context", "-e", str(eng.root)])
    assert len(fake_llm.requests) == 2, r.output
    entries = [e for e in load_ledger(eng).entries
               if e.tool == "(engagement)" and e.phase == "config-check"]
    assert entries and sum(e.usage.total() for e in entries) > 0
    # One entry per probe: the structured check and the context probe.
    assert sum(e.usage.input_tokens for e in entries) >= 200
    shown = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "config-check" in shown.output and "(engagement)" in shown.output
