from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from unvarnish.model.base import (
    Backend,
    BackendError,
    CompletionRequest,
    Message,
    ModelRefusal,
)
from unvarnish.schemas.cost import Usage
from unvarnish.util.hidden_text import CANDIDATE_RE, escape_hidden

JSON_IN_PROMPT_SUFFIX = (
    "\n\nRespond with exactly one JSON object and nothing else: no prose, no code fences. "
    "It must validate against this JSON schema:\n"
)
JSON_IN_PROMPT_SHORT = (
    "\n\nRespond with exactly one JSON object and nothing else: no prose, no code fences. "
    "It must validate against the schema above."
)
REPAIR_SYSTEM = (
    "You repair malformed JSON. You receive a JSON schema and a model's malformed output. "
    "Return exactly one JSON object that validates against the schema, preserving every value "
    "from the malformed output that can be kept. Output the JSON object only."
)
FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
log = logging.getLogger("unvarnish.structured")


class StructuredOutputError(BackendError):
    def __init__(self, attempts: int, last_error: str, last_text: str) -> None:
        super().__init__(
            f"structured output failed after {attempts} attempts: {last_error[:200]}"
        )
        self.attempts = attempts
        self.last_error = last_error
        self.last_text = last_text


@dataclass
class StructuredResult[T: BaseModel]:
    parsed: T
    usage: Usage
    attempts: int
    raw_text: str


# Keywords the structured-output APIs reject or ignore; pydantic enforces them client-side.
UNSUPPORTED_KEYWORDS = {"default", "title", "minimum", "maximum", "exclusiveMinimum",
                        "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern",
                        "minItems", "maxItems", "format"}


NAME_MAPS = {"properties", "$defs", "definitions"}  # their keys are names, not keywords


def _strictify(node: Any, *, names: bool = False) -> Any:
    if isinstance(node, dict):
        if names:  # a property or definition called "title" or "default" is a field, not a keyword
            return {k: _strictify(v) for k, v in node.items()}
        out = {k: _strictify(v, names=k in NAME_MAPS) for k, v in node.items()
               if k not in UNSUPPORTED_KEYWORDS}
        if out.get("type") == "object" and "properties" in out:
            out["additionalProperties"] = False
            out["required"] = list(out["properties"].keys())
        return out
    if isinstance(node, list):
        return [_strictify(x) for x in node]
    return node


def strict_schema(model_cls: type[BaseModel]) -> dict:
    """Pydantic schema made strict: no extra properties, every property required, no defaults."""
    return _strictify(model_cls.model_json_schema())


def extract_json(text: str) -> str:
    """The first balanced top-level JSON object in `text`; the tail from `{` if unbalanced."""
    m = FENCE_RE.search(text)
    if m:
        text = m.group(1)
    start = text.find("{")
    if start < 0:
        return text.strip()
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


BARE_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def repair_json(text: str) -> str:
    """Fix the slips a model makes when the server does not enforce the schema: unquoted
    keys and trailing commas. String contents are never touched."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    expect_key = False  # just after "{" or ",": a key may follow
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string, expect_key = True, False
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # trailing comma: drop it
                continue
            expect_key = True
        elif c == "{":
            expect_key = True
        elif expect_key and not c.isspace():
            m = BARE_KEY_RE.match(text, i)
            if m:
                j = m.end()
                while j < n and text[j] in " \t":
                    j += 1
                if j < n and text[j] == ":":
                    out.append(f'"{m.group(0)}"')
                    i, expect_key = m.end(), False
                    continue
            expect_key = False
        out.append(c)
        i += 1
    return "".join(out)


def _parse[T: BaseModel](model_cls: type[T], text: str, stop_reason: str | None) -> T:
    if stop_reason in ("max_tokens", "length"):
        raise ValueError(f"output truncated (stop_reason={stop_reason})")
    raw = extract_json(text)
    try:
        return model_cls.model_validate_json(raw)
    except ValidationError:
        repaired = repair_json(raw)
        if repaired == raw:
            raise
        return model_cls.model_validate_json(repaired)  # a retry call costs more than this


GRAMMAR_ERROR_MARKERS = ("compiled grammar", "grammar is too large")


def is_schema_rejection(exc: BaseException) -> bool:
    """The API refused the structured-output schema itself (too large to compile)."""
    msg = str(exc).lower()
    return any(m in msg for m in GRAMMAR_ERROR_MARKERS)


def escape_request(req: CompletionRequest) -> CompletionRequest:
    """The request with hidden characters (bidi controls, zero-width and tag characters,
    encoded runs) in its system prompt and messages written as [U+XXXX] escapes: source and
    rule files reach every structured call (extract, rollups, verify, compare, ask), and the
    model must see what a reviewer would, never steer on what nobody sees (UNVAR-92). Lines
    are unchanged, so cited line numbers still hold; a request without any is returned as is,
    so its cache key does not change."""
    texts = [req.system, *(m.content for m in req.messages)]
    if not any(CANDIDATE_RE.search(t) for t in texts):
        return req
    return req.model_copy(update={
        "system": escape_hidden(req.system, at_start=False),
        "messages": [m.model_copy(update={"content": escape_hidden(m.content, at_start=False)})
                     for m in req.messages],
    })


def complete_structured[T: BaseModel](
    backend: Backend, req: CompletionRequest, model_cls: type[T]
) -> StructuredResult[T]:
    """Attempt, retry with the validation error, then a repair call. Raises after the third.

    When the backend rejects the schema itself (a grammar too large to compile), the whole
    conversation is retried once in JSON-in-prompt mode, which has no such limit."""
    req = escape_request(req)
    native = backend.capabilities.json_schema
    try:
        return _complete_structured(backend, req, model_cls, native=native)
    except BackendError as exc:
        if native and not isinstance(exc, StructuredOutputError) and is_schema_rejection(exc):
            log.warning("%s: schema rejected by the backend (%s); retrying %s without native "
                        "structured output", backend.name, str(exc)[:120], model_cls.__name__)
            return _complete_structured(backend, req, model_cls, native=False)
        raise


def _base_request(req: CompletionRequest, model_cls: type[BaseModel], schema: dict, *,
                  native: bool) -> CompletionRequest:
    return req.model_copy(update={
        "output_schema": schema if native else None,
        "schema_name": model_cls.__name__,
        "system": (req.system if native
                   else req.system + JSON_IN_PROMPT_SHORT if req.schema_in_system
                   else req.system + JSON_IN_PROMPT_SUFFIX + json.dumps(schema)),
    })


def first_request(backend: Backend, req: CompletionRequest,
                  model_cls: type[BaseModel]) -> CompletionRequest:
    """The request complete_structured sends first for `req`: what a message batch must hold
    for its reply to be found in the response cache by the call that follows (UNVAR-94)."""
    req = escape_request(req)
    native = backend.capabilities.json_schema
    return _base_request(req, model_cls, strict_schema(model_cls), native=native)


def _complete_structured[T: BaseModel](
    backend: Backend, req: CompletionRequest, model_cls: type[T], *, native: bool
) -> StructuredResult[T]:
    schema = strict_schema(model_cls)
    base = _base_request(req, model_cls, schema, native=native)
    usage = Usage()
    messages = list(base.messages)
    last_text, last_error = "", ""
    sent: list[CompletionRequest] = []
    max_tokens = base.max_tokens

    for attempt in (1, 2):
        req_n = base.model_copy(update={"messages": messages, "max_tokens": max_tokens})
        sent.append(req_n)
        resp = backend.complete(req_n)
        usage = usage + resp.usage
        if resp.refusal_category is not None or resp.stop_reason == "refusal":
            raise ModelRefusal(resp.refusal_category)
        try:
            parsed = _parse(model_cls, resp.text, resp.stop_reason)
            return StructuredResult(parsed, usage, attempt, resp.text)
        except (ValidationError, ValueError) as exc:
            last_text, last_error = resp.text, str(exc)[:1500]
        if resp.stop_reason in ("max_tokens", "length"):
            max_tokens *= 2  # the output did not fit; give the retry room instead of repeating
        messages = messages + [
            Message(role="assistant", content=resp.text or "(empty)"),
            Message(role="user", content=(
                "Your previous output was not valid. Error:\n" + last_error
                + "\nReturn only a JSON object that matches the schema.")),
        ]

    repair = CompletionRequest(
        system=REPAIR_SYSTEM,
        messages=[Message(role="user", content=(
            "Schema:\n" + json.dumps(schema) + "\n\nMalformed output:\n" + last_text))],
        output_schema=schema if native else None, schema_name=model_cls.__name__,
        max_tokens=max_tokens, effort="low", cache_system=False,
    )
    sent.append(repair)
    resp = backend.complete(repair)
    usage = usage + resp.usage
    if resp.refusal_category is not None:
        raise ModelRefusal(resp.refusal_category)
    try:
        parsed = _parse(model_cls, resp.text, resp.stop_reason)
        return StructuredResult(parsed, usage, 3, resp.text)
    except (ValidationError, ValueError) as exc:
        forget = getattr(backend, "forget", None)
        if callable(forget):  # a failed conversation must not be pinned by the cache
            forget(sent)
        raise StructuredOutputError(3, str(exc)[:1500], resp.text) from exc
