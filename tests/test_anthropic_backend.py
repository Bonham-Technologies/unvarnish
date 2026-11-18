import pytest

from tests.fake_llm import FakeLLM, anthropic_message
from unvarnish.config import BackendCapabilities
from unvarnish.model.anthropic_backend import AnthropicBackend
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionRequest, Message

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
          "additionalProperties": False}


def _backend(fake: FakeLLM, **caps) -> AnthropicBackend:
    return AnthropicBackend(name="a", model="claude-opus-5-5", api_key="test", base_url=fake.url,
                            capabilities=BackendCapabilities(**caps), max_retries=2)


def _req(**kw) -> CompletionRequest:
    base = dict(system="S" * 10, messages=[Message(role="user", content="hello")])
    base.update(kw)
    return CompletionRequest(**base)


def test_request_shape_with_schema_cache_and_effort(fake_llm: FakeLLM):
    fake_llm.script('{"ok": true}')
    resp = _backend(fake_llm).complete(_req(output_schema=SCHEMA, effort="medium"))
    assert resp.text == '{"ok": true}' and resp.model == "claude-opus-5-5"
    sent = fake_llm.requests[0]
    assert sent["path"] == "/v1/messages"
    assert sent["model"] == "claude-opus-5-5" and sent["max_tokens"] == 8000
    assert sent["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert sent["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert sent["output_config"]["effort"] == "medium"
    assert sent["messages"] == [{"role": "user", "content": "hello"}]
    assert "temperature" not in sent


def test_no_schema_when_backend_lacks_capability(fake_llm: FakeLLM):
    fake_llm.script("plain")
    _backend(fake_llm, json_schema=False).complete(_req(output_schema=SCHEMA, cache_system=False))
    sent = fake_llm.requests[0]
    assert "output_config" not in sent or "format" not in sent["output_config"]
    assert "cache_control" not in sent["system"][0]


def test_usage_includes_cache_tokens(fake_llm: FakeLLM):
    fake_llm.script(lambda body: anthropic_message("x", model=body["model"], input_tokens=50,
                                                   output_tokens=7, cache_read=400, cache_write=12))
    resp = _backend(fake_llm).complete(_req())
    assert (resp.usage.input_tokens, resp.usage.output_tokens) == (50, 7)
    assert (resp.usage.cache_read_tokens, resp.usage.cache_write_tokens) == (400, 12)
    assert resp.stop_reason == "end_turn"


def test_refusal_is_reported_not_raised(fake_llm: FakeLLM):
    fake_llm.script(lambda body: anthropic_message(
        "", model=body["model"], stop_reason="refusal",
        stop_details={"type": "refusal", "category": "cyber"}))
    resp = _backend(fake_llm).complete(_req())
    assert resp.refusal_category == "cyber" and resp.text == "" and resp.stop_reason == "refusal"


def test_anthropic_backend_retries_429_without_caching(fake_llm: FakeLLM):
    fake_llm.script({"status": 429}, '{"ok": true}')
    resp = _backend(fake_llm).complete(_req())
    assert resp.text == '{"ok": true}'
    assert len(fake_llm.requests) == 2
    assert resp.usage.input_tokens == 100  # from the successful call only


def test_errors_map_to_backend_errors(fake_llm: FakeLLM):
    fake_llm.script({"status": 401, "body": {"type": "error", "error": {
        "type": "authentication_error", "message": "bad key"}}})
    with pytest.raises(BackendUnavailable, match="bad key"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 400, "body": {"type": "error", "error": {
        "type": "invalid_request_error", "message": "nope"}}})
    with pytest.raises(BackendError, match="nope"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 500}, {"status": 500}, {"status": 500})
    with pytest.raises(BackendUnavailable):
        _backend(fake_llm).complete(_req())


# --- fixes from the whole-branch review -------------------------------------
def test_rate_limit_is_retried_with_backoff_then_succeeds(fake_llm: FakeLLM):
    sleeps: list[float] = []
    b = AnthropicBackend(name="a", model="m", api_key="t", base_url=fake_llm.url,
                         capabilities=BackendCapabilities(), max_retries=0,
                         rate_limit_retries=5, sleep=sleeps.append)
    fake_llm.script({"status": 429}, {"status": 429}, {"status": 429}, '{"ok": true}')
    assert b.complete(_req()).text == '{"ok": true}'
    assert len(fake_llm.requests) == 4 and len(sleeps) == 3


def test_rate_limit_ceiling_raises_unavailable(fake_llm: FakeLLM):
    b = AnthropicBackend(name="a", model="m", api_key="t", base_url=fake_llm.url,
                         capabilities=BackendCapabilities(), max_retries=0,
                         rate_limit_retries=1, sleep=lambda s: None)
    fake_llm.script({"status": 429}, {"status": 429}, {"status": 429})
    with pytest.raises(BackendUnavailable, match="rate limit"):
        b.complete(_req())
    assert len(fake_llm.requests) == 2
