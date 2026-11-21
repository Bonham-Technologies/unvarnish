import pytest

from tests.fake_llm import FakeLLM, openai_completion
from unvarnish.config import BackendCapabilities
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionRequest, Message
from unvarnish.model.openai_backend import OpenAICompatibleBackend

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
          "additionalProperties": False}


def _backend(fake: FakeLLM, **caps) -> OpenAICompatibleBackend:
    return OpenAICompatibleBackend(name="onprem", model="qwen", api_key="k",
                                   base_url=fake.url + "/v1",
                                   capabilities=BackendCapabilities(**caps), max_retries=2)


def _req(**kw) -> CompletionRequest:
    base = dict(system="SYS", messages=[Message(role="user", content="hello")])
    base.update(kw)
    return CompletionRequest(**base)


def test_request_shape_with_json_schema(fake_llm: FakeLLM):
    fake_llm.script('{"ok": true}')
    resp = _backend(fake_llm).complete(_req(output_schema=SCHEMA, schema_name="unit",
                                            temperature=0.0))
    assert resp.text == '{"ok": true}' and resp.model == "qwen" and resp.stop_reason == "stop"
    sent = fake_llm.requests[0]
    assert sent["path"] == "/v1/chat/completions"
    assert sent["messages"][0] == {"role": "system", "content": "SYS"}
    assert sent["messages"][1] == {"role": "user", "content": "hello"}
    assert sent["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "unit", "schema": SCHEMA, "strict": True},
    }
    assert sent["max_tokens"] == 8000 and sent["temperature"] == 0.0


def test_no_response_format_without_capability(fake_llm: FakeLLM):
    fake_llm.script("text")
    _backend(fake_llm, json_schema=False).complete(_req(output_schema=SCHEMA))
    assert "response_format" not in fake_llm.requests[0]


def test_usage_and_refusal(fake_llm: FakeLLM):
    def refused(body):
        c = openai_completion("", model=body["model"], prompt_tokens=9, completion_tokens=1)
        c["choices"][0]["message"]["refusal"] = "I can't help with that"
        c["usage"]["prompt_tokens_details"] = {"cached_tokens": 5}
        return c

    fake_llm.script(refused)
    resp = _backend(fake_llm).complete(_req())
    assert resp.refusal_category == "refusal"
    assert resp.usage.input_tokens == 9 and resp.usage.cache_read_tokens == 5


def test_errors(fake_llm: FakeLLM):
    fake_llm.script({"status": 401, "body": {"error": {"message": "bad key",
                                                       "type": "invalid_request_error"}}})
    with pytest.raises(BackendUnavailable, match="bad key"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 400, "body": {"error": {"message": "nope",
                                                       "type": "invalid_request_error"}}})
    with pytest.raises(BackendError, match="nope"):
        _backend(fake_llm).complete(_req())


# --- fixes from the whole-branch review -------------------------------------
def test_rate_limit_is_retried_then_succeeds(fake_llm: FakeLLM):
    sleeps: list[float] = []
    b = OpenAICompatibleBackend(name="o", model="m", api_key="k", base_url=fake_llm.url + "/v1",
                                capabilities=BackendCapabilities(), max_retries=0,
                                rate_limit_retries=3, sleep=sleeps.append)
    fake_llm.script({"status": 429}, "ok")
    assert b.complete(_req()).text == "ok"
    assert len(fake_llm.requests) == 2 and len(sleeps) == 1


def test_display_url_never_prints_credentials_or_a_query():
    """UNVAR-78: the unreachable-server error names the base URL, so it must be safe to print."""
    from unvarnish.model.base import display_url

    assert display_url("http://llm:11434/v1") == "http://llm:11434/v1"
    assert display_url("https://user:s3cret@gw.example/v1/?key=abc") == "https://gw.example/v1"
    assert display_url("not a url") == "(unparseable URL)"
    assert display_url("http://u:p@[::1]:8080/v1?t=x") == "http://[::1]:8080/v1"
    assert display_url(None) == "(unparseable URL)"
