from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Scripted = str | dict | Callable[[dict], str | dict]


def anthropic_message(text: str, *, model: str, input_tokens: int = 100, output_tokens: int = 20,
                      cache_read: int = 0, cache_write: int = 0, stop_reason: str = "end_turn",
                      stop_details: dict | None = None) -> dict:
    return {
        "id": "msg_fake", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": text}] if text else [],
        "stop_reason": stop_reason, "stop_sequence": None, "stop_details": stop_details,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                  "cache_read_input_tokens": cache_read,
                  "cache_creation_input_tokens": cache_write},
    }


def openai_completion(text: str, *, model: str, prompt_tokens: int = 100,
                      completion_tokens: int = 20, finish_reason: str = "stop") -> dict:
    return {
        "id": "chatcmpl-fake", "object": "chat.completion", "created": 0, "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                     "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "total_tokens": prompt_tokens + completion_tokens},
    }


def fill_schema(schema: dict, root: dict | None = None) -> Any:
    """A minimal instance of a JSON schema: first enum value, empty arrays, 'stub' strings."""
    root = root or schema
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return fill_schema(root["$defs"][name], root)
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    if "anyOf" in schema:
        options = [o for o in schema["anyOf"] if o.get("type") != "null"]
        return fill_schema(options[0], root) if options else None
    t = schema.get("type")
    if t == "object":
        return {k: fill_schema(v, root) for k, v in schema.get("properties", {}).items()}
    if t == "array":
        return []
    if t == "string":
        return "stub"
    if t == "integer":
        return 1
    if t == "number":
        return 0.5
    if t == "boolean":
        return False
    if t == "null":
        return None
    return "stub"


def _request_schema(body: dict) -> dict | None:
    fmt = (body.get("output_config") or {}).get("format") or {}
    if fmt.get("schema"):
        return fmt["schema"]
    rf = (body.get("response_format") or {}).get("json_schema") or {}
    return rf.get("schema")


request_schema = _request_schema  # public name for tests that script schema-filled replies


class FakeLLM:
    """A local HTTP server that answers Anthropic Messages and OpenAI chat-completion calls."""

    def __init__(self) -> None:
        self._queue: deque[Scripted] = deque()
        self.requests: list[dict[str, Any]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.autofill = False  # answer unscripted structured requests with schema-filled JSON

    @property
    def url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def script(self, *responses: Scripted) -> None:
        with self._lock:
            self._queue.extend(responses)

    def _next(self) -> Scripted | None:
        with self._lock:
            return self._queue.popleft() if self._queue else None

    def start(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                with fake._lock:
                    fake.requests.append({"path": self.path, **body})
                scripted = fake._next()
                if scripted is None:
                    schema = _request_schema(body)
                    if fake.autofill and schema:
                        scripted = json.dumps(fill_schema(schema))
                    elif fake.autofill:
                        scripted = "Model-written paragraph."
                    else:
                        scripted = '{"echo": true}'
                if callable(scripted):
                    scripted = scripted(body)
                status = 200
                if isinstance(scripted, dict) and "status" in scripted:
                    status = int(scripted["status"])
                    scripted = scripted.get("body") or scripted.get("text") or {
                        "type": "error",
                        "error": {"type": "rate_limit_error", "message": "slow down"},
                    }
                model = body.get("model", "fake")
                if isinstance(scripted, str):
                    if self.path.startswith("/v1/messages"):
                        payload = anthropic_message(scripted, model=model)
                    else:
                        payload = openai_completion(scripted, model=model)
                else:
                    payload = scripted
                raw = json.dumps(payload).encode()
                self.send_response(status)
                if status >= 400:
                    self.send_header("retry-after", "0")  # keep SDK retries fast in tests
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
