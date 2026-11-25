from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse
from unvarnish.model.batch import BatchResult
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

    def _reply(self, req: CompletionRequest) -> CompletionResponse:
        reply = self.replies.get(req.schema_name, self.default)
        if callable(reply):
            reply = reply(req)
        if isinstance(reply, Exception):
            raise reply
        return CompletionResponse(text=reply, model=self.model,
                                  usage=Usage(input_tokens=100, output_tokens=20))

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        with self._lock:
            self.requests.append(req)
        return self._reply(req)

    def forget(self, reqs) -> int:
        return 0

    def count(self, schema_name: str) -> int:
        return sum(1 for r in self.requests if r.schema_name == schema_name)


class BatchStubBackend(StubBackend):
    """A StubBackend with `batch: true`: it also answers the Message Batches calls, from the
    same reply table, so a batched run can be compared with a synchronous one. `requests`
    still holds only the synchronous calls; `batched` holds what went in batches.

    `fail(req)` may name a request's batch outcome instead of a reply ("errored",
    "expired"); `polls` is how many status checks report a batch as still in progress."""

    batch = True

    def __init__(self, replies: dict[str, Reply] | None = None, *,
                 fail: Callable[[CompletionRequest], str | None] | None = None,
                 polls: int = 1, **kw) -> None:
        super().__init__(replies, **kw)
        self.fail = fail
        self.polls = polls
        self.batches: dict[str, list[tuple[str, CompletionRequest]]] = {}
        self.batched: list[CompletionRequest] = []
        self.status_checks: list[str] = []
        self.sleeps: list[float] = []
        self.on_sleep: Callable[[], None] | None = None
        self._pending: dict[str, int] = {}

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.on_sleep is not None:
            self.on_sleep()

    def submit_batch(self, items: list[tuple[str, CompletionRequest]]) -> str:
        batch_id = f"msgbatch_stub{len(self.batches) + 1}"
        self.batches[batch_id] = list(items)
        self.batched.extend(req for _, req in items)
        self._pending[batch_id] = self.polls
        return batch_id

    def batch_ended(self, batch_id: str) -> bool:
        self.status_checks.append(batch_id)
        if self._pending[batch_id] > 0:
            self._pending[batch_id] -= 1
            return False
        return True

    def batch_results(self, batch_id: str) -> Iterator[BatchResult]:
        for custom_id, req in self.batches[batch_id]:
            failed = self.fail(req) if self.fail else None
            if failed:
                yield BatchResult(custom_id=custom_id, error=failed)
                continue
            try:
                yield BatchResult(custom_id=custom_id, response=self._reply(req))
            except Exception as exc:  # noqa: BLE001 - the batch reports it per request
                yield BatchResult(custom_id=custom_id, error=f"errored: {exc}")

    def count_batched(self, schema_name: str) -> int:
        return sum(1 for r in self.batched if r.schema_name == schema_name)
