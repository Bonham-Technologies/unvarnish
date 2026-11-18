import pytest

from unvarnish.config import BackendConfig, EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.registry import (
    BackendConfigError,
    NoModelConfigured,
    load_api_key,
    resolve_backend,
    resolve_model_ref,
)


def test_request_defaults():
    r = CompletionRequest(system="s", messages=[Message(role="user", content="u")])
    assert r.max_tokens == 8000 and r.output_schema is None and r.cache_system is True


def test_resolve_model_ref_prefers_phase_override():
    cfg = EngagementConfig(models={"default": {"backend": "a", "model": "m1"},
                                   "phases": {"extract": {"backend": "b", "model": "m2"}}})
    assert resolve_model_ref(cfg, "extract").model == "m2"
    assert resolve_model_ref(cfg, "verify").model == "m1"
    assert resolve_model_ref(EngagementConfig(), "extract") is None


def test_load_api_key_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "sk-test")
    assert load_api_key(BackendConfig(type="anthropic", api_key_env="MY_KEY"), "a") == "sk-test"
    assert load_api_key(BackendConfig(type="openai_compatible"), "a") is None


def test_missing_api_key_is_config_error(monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    with pytest.raises(BackendConfigError, match="MISSING_KEY"):
        load_api_key(BackendConfig(type="anthropic", api_key_env="MISSING_KEY"), "a")


def test_resolve_backend_errors(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    with pytest.raises(NoModelConfigured):
        resolve_backend(eng, "extract")
    eng.config = EngagementConfig.model_validate(
        {**eng.config.model_dump(), "models": {"default": {"backend": "ghost", "model": "m"}}}
    )
    with pytest.raises(BackendConfigError, match="ghost"):
        resolve_backend(eng, "extract")


def test_resolve_backend_builds_openai_compatible(tmp_path, monkeypatch):
    monkeypatch.setenv("ONPREM_KEY", "k")
    eng = Engagement.create(tmp_path / "e")
    eng.config = EngagementConfig.model_validate({
        "backends": {"onprem": {"type": "openai_compatible", "base_url": "http://127.0.0.1:9/v1",
                                "api_key_env": "ONPREM_KEY"}},
        "models": {"default": {"backend": "onprem", "model": "qwen"}},
    })
    b = resolve_backend(eng, "extract")
    assert b.name == "onprem" and b.model == "qwen"
