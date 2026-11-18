import json

import pytest
from pydantic import BaseModel

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse, Message, ModelRefusal
from unvarnish.model.structured import (
    StructuredOutputError,
    complete_structured,
    extract_json,
    strict_schema,
)
from unvarnish.schemas.analysis import UnitExtraction
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.verify import Verdict


class Out(BaseModel):
    name: str
    count: int
    note: str | None = None


class Scripted:
    name = "s"
    model = "m"

    def __init__(self, *texts, json_schema=True):
        self.texts = list(texts)
        self.capabilities = BackendCapabilities(json_schema=json_schema)
        self.requests: list[CompletionRequest] = []

    def complete(self, req):
        self.requests.append(req)
        t = self.texts.pop(0)
        if isinstance(t, CompletionResponse):
            return t
        return CompletionResponse(text=t, usage=Usage(input_tokens=10, output_tokens=3), model="m")


def _req():
    return CompletionRequest(system="sys", messages=[Message(role="user", content="go")])


def test_strict_schema_shape():
    s = strict_schema(Out)
    assert s["additionalProperties"] is False
    assert sorted(s["required"]) == ["count", "name", "note"]
    assert "default" not in json.dumps(s)
    nested = strict_schema(UnitExtraction)
    for d in nested["$defs"].values():
        if d.get("type") == "object":
            assert d.get("additionalProperties") is False
            assert sorted(d["required"]) == sorted(d["properties"])


def test_extract_json_handles_fences_prose_and_truncation():
    assert extract_json('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert extract_json('Sure! {"a": {"b": "}"}} trailing') == '{"a": {"b": "}"}}'
    assert extract_json('{"a": [1, 2') == '{"a": [1, 2'


def test_happy_path_native_schema():
    b = Scripted('{"name": "x", "count": 2, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.parsed == Out(name="x", count=2) and r.attempts == 1
    assert b.requests[0].output_schema is not None
    assert b.requests[0].output_schema["additionalProperties"] is False
    assert r.usage.input_tokens == 10


def test_json_in_prompt_mode_embeds_schema():
    b = Scripted('here you go: {"name": "x", "count": 1, "note": null}', json_schema=False)
    r = complete_structured(b, _req(), Out)
    assert r.parsed.name == "x"
    assert b.requests[0].output_schema is None
    assert '"additionalProperties"' in b.requests[0].system and "JSON" in b.requests[0].system


def test_retry_with_validation_error_then_success():
    b = Scripted('{"name": "x"}', '{"name": "x", "count": 3, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.parsed.count == 3 and r.attempts == 2
    second = b.requests[1]
    assert second.messages[-2].role == "assistant" and second.messages[-1].role == "user"
    assert "count" in second.messages[-1].content
    assert r.usage.input_tokens == 20


def test_retry_then_repair_then_failure():
    b = Scripted("nonsense", "still bad", "{broken")
    with pytest.raises(StructuredOutputError) as exc:
        complete_structured(b, _req(), Out)
    assert exc.value.attempts == 3 and exc.value.last_text == "{broken"
    repair = b.requests[2]
    assert repair.effort == "low" and repair.cache_system is False
    assert "still bad" in repair.messages[0].content


def test_truncated_json_is_repaired():
    b = Scripted('{"name": "x", "count": 1, "no', '{"name": "x", "count": 1, "no',
                 '{"name": "x", "count": 1, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.attempts == 3 and r.parsed.count == 1


def test_refusal_raises_model_refusal():
    b = Scripted(CompletionResponse(text="", model="m", refusal_category="cyber",
                                    stop_reason="refusal"))
    with pytest.raises(ModelRefusal) as exc:
        complete_structured(b, _req(), Out)
    assert exc.value.category == "cyber"


# --- fixes from the whole-branch review -------------------------------------
def test_strict_schema_strips_unsupported_keywords():
    s = json.dumps(strict_schema(UnitExtraction))
    for kw in ('"minimum"', '"maximum"', '"multipleOf"', '"minLength"', '"maxLength"'):
        assert kw not in s, kw
    assert '"title": "' not in s  # schema-level titles are strings; the `title` field stays
    assert '"enum"' in s and '"$defs"' in s  # the parts the API does support stay


def test_failed_structured_output_is_not_pinned_by_cache(tmp_path):
    from unvarnish.model.cache import CachingBackend

    inner = Scripted("nonsense", "still bad", "{broken",
                     '{"name": "x", "count": 1, "note": null}')
    cb = CachingBackend(inner, tmp_path / "responses")
    with pytest.raises(StructuredOutputError):
        complete_structured(cb, _req(), Out)
    r = complete_structured(cb, _req(), Out)  # second run must reach the backend again
    assert r.parsed.count == 1 and len(inner.requests) == 4


def test_strict_schema_keeps_properties_named_like_keywords():
    """Found by the live smoke test: stripping schema-level `title` must not strip a field
    called `title` (every finding has one), nor fields named `default`, `format`, ..."""
    from pydantic import BaseModel

    from unvarnish.schemas.analysis import CandidateFinding

    s = strict_schema(CandidateFinding)
    assert "title" in s["properties"] and "title" in s["required"]

    class Odd(BaseModel):
        default: str
        format: str
        pattern: int

    o = strict_schema(Odd)
    assert set(o["properties"]) == {"default", "format", "pattern"}
    assert set(o["required"]) == {"default", "format", "pattern"}
    assert "title" not in o  # the schema-level title is still stripped


def test_complete_structured_falls_back_to_json_in_prompt_on_grammar_error():
    """Found by the live smoke test: the API rejects large schemas with a 400 'compiled
    grammar is too large'. The call must then succeed without native structured output."""
    from unvarnish.model.base import BackendError

    class GrammarLimited:
        name = "g"
        model = "m"
        capabilities = BackendCapabilities()

        def __init__(self) -> None:
            self.requests: list[CompletionRequest] = []

        def complete(self, req: CompletionRequest) -> CompletionResponse:
            self.requests.append(req)
            if req.output_schema is not None:
                raise BackendError("g: bad request: Error code: 400 - The compiled grammar is "
                                   "too large, which would cause performance issues.")
            return CompletionResponse(text='{"verdict": "confirmed", "reason": "ok"}', model="m")

    backend = GrammarLimited()
    req = CompletionRequest(system="s", messages=[Message(role="user", content="u")])
    res = complete_structured(backend, req, Verdict)
    assert res.parsed.verdict == "confirmed"
    assert backend.requests[0].output_schema is not None  # native attempt first
    assert backend.requests[-1].output_schema is None  # then JSON-in-prompt
    assert "JSON schema" in backend.requests[-1].system
