from pathlib import Path

import yaml

from unvarnish.config import DEFAULT_SCANNER_OPTIONS, EngagementConfig, deep_merge, load_config


def test_defaults():
    cfg = EngagementConfig()
    assert cfg.schema_version == 1
    assert cfg.pipeline.unit_tokens == 8000
    assert cfg.pipeline.concurrency == 8
    assert cfg.report.tone == "direct"
    assert cfg.ask.max_tool_calls == 12
    assert cfg.scanners == DEFAULT_SCANNER_OPTIONS


def test_partial_scanner_override_keeps_other_defaults():
    cfg = EngagementConfig(scanners={"oversized_files": {"file_lines": 500}})
    assert cfg.scanners["oversized_files"]["file_lines"] == 500
    assert cfg.scanners["oversized_files"]["function_lines"] == 150
    assert cfg.scanners["bus_factor"]["single_author_share"] == 0.9


def test_deep_merge_nested():
    base = {"a": {"x": 1, "y": 2}, "b": 1}
    override = {"a": {"y": 3}, "c": 4}
    assert deep_merge(base, override) == {"a": {"x": 1, "y": 3}, "b": 1, "c": 4}


def test_load_config_merges_user_defaults(tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "userconf"
    user_dir.mkdir()
    (user_dir / "config.yaml").write_text(
        yaml.safe_dump({"consultant": "Bonham Technologies", "pipeline": {"concurrency": 2}})
    )
    monkeypatch.setenv("UNVARNISH_CONFIG_DIR", str(user_dir))
    eng_file = tmp_path / "engagement.yaml"
    eng_file.write_text(yaml.safe_dump({"client": "Acme", "pipeline": {"unit_tokens": 4000}}))
    cfg = load_config(eng_file)
    assert cfg.client == "Acme"
    assert cfg.consultant == "Bonham Technologies"
    assert cfg.pipeline.concurrency == 2
    assert cfg.pipeline.unit_tokens == 4000


def test_backend_config_shapes():
    cfg = EngagementConfig(
        backends={
            "onprem": {
                "type": "openai_compatible",
                "base_url": "http://llm.internal:8000/v1",
                "api_key_env": "ONPREM_KEY",
                "capabilities": {"tool_calling": False, "context_window": 32768},
            }
        }
    )
    b = cfg.backends["onprem"]
    assert b.type == "openai_compatible"
    assert b.capabilities.tool_calling is False
    assert b.capabilities.json_schema is True
