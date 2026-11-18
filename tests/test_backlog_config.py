"""Known-issues burn-down, task 3: configuration."""
import json
import logging

from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.config import EngagementConfig, unknown_keys
from unvarnish.engagement import Engagement

runner = CliRunner()


def test_unknown_keys_are_named_with_their_path():
    data = {"client": "A", "clinet": "typo", "pipeline": {"concurency": 4},
            "backends": {"a": {"type": "anthropic", "api_keyenv": "X"}},
            "models": {"phases": {"extract": {"backend": "a", "model": "m", "efort": "low"}}},
            "scanners": {"secrets": {"anything": 1}}}  # scanner options are free-form
    assert sorted(unknown_keys(data)) == ["backends.a.api_keyenv", "clinet",
                                          "models.phases.extract.efort", "pipeline.concurency"]


def test_loading_warns_about_unknown_keys(tmp_path, caplog):
    eng = Engagement.create(tmp_path / "e", client="A")
    text = eng.config_file.read_text(encoding="utf-8") + "reprot: {tone: direct}\n"
    eng.config_file.write_text(text, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        Engagement.load(eng.root)
    assert "reprot" in caplog.text
    out = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert "reprot" in out.output


def test_templates_dir_resolves_against_the_engagement(tmp_path):
    from unvarnish.phases.render import override_dirs

    cfg = EngagementConfig.model_validate({"report": {"templates_dir": "brand/templates"}})
    assert (tmp_path / "brand/templates") in override_dirs(tmp_path, cfg)


def test_status_and_cost_survive_corrupt_artifacts(ingested):
    eng, tool = ingested
    from unvarnish.phases.base import build_context

    ctx = build_context(eng, tool)
    ctx.paths.extract_state.parent.mkdir(parents=True, exist_ok=True)
    ctx.paths.extract_state.write_text("{not json", encoding="utf-8")
    out = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert "unreadable" in out.output
    eng.cost_file.write_text("{broken", encoding="utf-8")
    out = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert out.exit_code == 0 and "unreadable" in out.output


def test_freshness_reads_only_the_meta_at_the_end(tmp_path):
    from unvarnish.artifacts import write_artifact
    from unvarnish.phases.base import _recorded_hash
    from unvarnish.schemas.cost import Usage

    p = tmp_path / "big.json"
    write_artifact(p, Usage(input_tokens=1), produced_by="t", inputs_hash="abc123")
    assert _recorded_hash(p) == "abc123"
    payload = json.loads(p.read_text())
    payload["data"]["padding"] = "x" * 5_000_000
    p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    import time
    t = time.perf_counter()
    assert _recorded_hash(p) == "abc123"
    assert time.perf_counter() - t < 0.01


def test_anthropic_backends_default_to_a_1m_context():
    cfg = EngagementConfig.model_validate({"backends": {
        "a": {"type": "anthropic"},
        "b": {"type": "anthropic", "capabilities": {"context_window": 200000}},
        "c": {"type": "openai_compatible", "base_url": "http://x/v1"}}})
    assert cfg.backends["a"].capabilities.context_window == 1_000_000
    assert cfg.backends["b"].capabilities.context_window == 200_000
    assert cfg.backends["c"].capabilities.context_window == 200_000
