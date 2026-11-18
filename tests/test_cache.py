from pathlib import Path

import pytest

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import (
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
    Message,
)
from unvarnish.model.cache import CachingBackend, cache_key, clear_cache
from unvarnish.schemas.cost import Usage


class Scripted:
    name = "s"
    model = "m"
    capabilities = BackendCapabilities()

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, req):
        self.calls += 1
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _req(content="q", **kw):
    return CompletionRequest(system="sys", messages=[Message(role="user", content=content)], **kw)


def _resp(text="ok"):
    return CompletionResponse(text=text, usage=Usage(input_tokens=5, output_tokens=2), model="m")


def test_cache_hit_skips_backend_and_zeroes_usage(tmp_path: Path):
    inner = Scripted(_resp("first"))
    cb = CachingBackend(inner, tmp_path / "responses")
    a = cb.complete(_req())
    b = cb.complete(_req())
    assert inner.calls == 1
    assert a.text == b.text == "first"
    assert a.cached is False and b.cached is True
    assert b.usage == Usage()
    assert len(list((tmp_path / "responses").glob("*.json"))) == 1


def test_cache_key_sensitivity():
    k = cache_key("s", "m", _req())
    assert k == cache_key("s", "m", _req())
    assert k != cache_key("s", "m", _req("other"))
    assert k != cache_key("s", "m2", _req())
    assert k != cache_key("s", "m", _req(effort="high"))
    assert k != cache_key("s", "m", _req(output_schema={"type": "object"}))


def test_cache_never_stores_errors(tmp_path: Path):
    inner = Scripted(BackendUnavailable("down"), _resp("later"))
    cb = CachingBackend(inner, tmp_path / "responses")
    with pytest.raises(BackendUnavailable):
        cb.complete(_req())
    assert list((tmp_path / "responses").glob("*.json")) == []
    assert cb.complete(_req()).text == "later"


def test_refusals_and_empty_not_cached(tmp_path: Path):
    inner = Scripted(CompletionResponse(text="", model="m", refusal_category="cyber"), _resp("x"))
    cb = CachingBackend(inner, tmp_path / "responses")
    assert cb.complete(_req()).refusal_category == "cyber"
    assert cb.complete(_req()).text == "x"
    assert inner.calls == 2


def test_clear_cache(tmp_path: Path):
    cb = CachingBackend(Scripted(_resp(), _resp()), tmp_path / "responses")
    cb.complete(_req("a"))
    cb.complete(_req("b"))
    assert clear_cache(tmp_path / "responses") == 2
    assert clear_cache(tmp_path / "responses") == 0


# --- fixes from the whole-branch review -------------------------------------
def test_truncated_responses_are_not_cached(tmp_path: Path):
    inner = Scripted(CompletionResponse(text='{"a": 1', model="m", stop_reason="max_tokens"),
                     _resp("ok"))
    cb = CachingBackend(inner, tmp_path / "responses")
    cb.complete(_req())
    assert cb.complete(_req()).text == "ok" and inner.calls == 2


def test_forget_removes_conversation_entries(tmp_path: Path):
    inner = Scripted(_resp("a"), _resp("b"), _resp("c"))
    cb = CachingBackend(inner, tmp_path / "responses")
    r1, r2 = _req("one"), _req("two")
    cb.complete(r1)
    cb.complete(r2)
    assert len(list((tmp_path / "responses").glob("*.json"))) == 2
    cb.forget([r1])
    assert len(list((tmp_path / "responses").glob("*.json"))) == 1
    assert cb.complete(r1).text == "c"  # re-fetched


def test_concurrent_identical_requests_do_not_crash(tmp_path: Path):
    import threading

    inner = Scripted(*[_resp("same")] * 8)
    cb = CachingBackend(inner, tmp_path / "responses")
    errors: list[BaseException] = []

    def go():
        try:
            cb.complete(_req())
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(list((tmp_path / "responses").glob("*.json"))) == 1
    assert list((tmp_path / "responses").glob("*.tmp*")) == []
