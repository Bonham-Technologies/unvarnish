from __future__ import annotations

import threading
from collections.abc import Callable

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse
from unvarnish.schemas.cost import Usage

Reply = str | Exception | Callable[[CompletionRequest], "str | Exception"]


class StubBackend:
    """In-process Backend. Replies are chosen by `req.schema_name` (the pydantic class name
    that complete_structured sets, or "prose" for prose blocks); a reply may be text, an
    exception to raise, or a callable of the request."""

    name = "stub"
    model = "stub-model"

    def __init__(self, replies: dict[str, Reply] | None = None,
                 default: Reply = '{"echo": true}', *, json_schema: bool = True) -> None:
        self.replies = replies or {}
        self.default = default
        self.capabilities = BackendCapabilities(json_schema=json_schema)
        self.requests: list[CompletionRequest] = []
        self._lock = threading.Lock()

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        with self._lock:
            self.requests.append(req)
        reply = self.replies.get(req.schema_name, self.default)
        if callable(reply):
            reply = reply(req)
        if isinstance(reply, Exception):
            raise reply
        return CompletionResponse(text=reply, model=self.model,
                                  usage=Usage(input_tokens=100, output_tokens=20))

    def forget(self, reqs) -> int:
        return 0

    def count(self, schema_name: str) -> int:
        return sum(1 for r in self.requests if r.schema_name == schema_name)
