import json
import urllib.error
import urllib.request

from tests.fake_llm import FakeLLM, anthropic_message, openai_completion


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_fake_serves_anthropic_and_openai_shapes(fake_llm: FakeLLM):
    fake_llm.script('{"a": 1}', '{"b": 2}')
    code, body = _post(fake_llm.url + "/v1/messages", {"model": "m", "messages": []})
    assert code == 200 and body["content"][0]["text"] == '{"a": 1}'
    assert body["usage"]["input_tokens"] > 0
    code, body = _post(fake_llm.url + "/v1/chat/completions", {"model": "m", "messages": []})
    assert code == 200 and body["choices"][0]["message"]["content"] == '{"b": 2}'
    assert [r["path"] for r in fake_llm.requests] == ["/v1/messages", "/v1/chat/completions"]


def test_fake_status_and_callable(fake_llm: FakeLLM):
    fake_llm.script({"status": 429}, lambda body: f"model={body['model']}")
    code, _ = _post(fake_llm.url + "/v1/messages", {"model": "m", "messages": []})
    assert code == 429
    code, body = _post(fake_llm.url + "/v1/messages", {"model": "zed", "messages": []})
    assert code == 200 and body["content"][0]["text"] == "model=zed"


def test_builders():
    m = anthropic_message("hi", model="x", stop_reason="refusal",
                          stop_details={"type": "refusal", "category": "cyber"})
    assert m["stop_details"]["category"] == "cyber"
    o = openai_completion("hi", model="x", finish_reason="length")
    assert o["choices"][0]["finish_reason"] == "length"
