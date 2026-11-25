from __future__ import annotations

import threading

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import Backend, CompletionRequest, CompletionResponse
from unvarnish.model.budget import RunInterrupted

_LIMITERS: dict[tuple[str, int], threading.BoundedSemaphore] = {}
_LOCK = threading.Lock()
# Set on Ctrl-C. A call that was already waiting for a slot when it came is never sent:
# with several tools in parallel most workers wait here, past their budget check.
_INTERRUPTED = threading.Event()


def stop_new_calls() -> None:
    _INTERRUPTED.set()


def allow_new_calls() -> None:
    _INTERRUPTED.clear()


def new_calls_stopped() -> bool:
    return _INTERRUPTED.is_set()


def limiter_for(key: str, concurrency: int) -> threading.BoundedSemaphore:
    """One semaphore per engagement and limit, shared by every backend built for it."""
    with _LOCK:
        lim = _LIMITERS.get((key, concurrency))
        if lim is None:
            lim = _LIMITERS[(key, concurrency)] = threading.BoundedSemaphore(max(1, concurrency))
        return lim


class LimitedBackend:
    """Holds a slot of the engagement's limiter for the duration of each model call, so
    `pipeline.concurrency` caps in-flight requests across tools running in parallel."""

    def __init__(self, inner: Backend, limiter: threading.BoundedSemaphore) -> None:
        self.inner = inner
        self._limiter = limiter

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def model(self) -> str:
        return self.inner.model

    @property
    def capabilities(self) -> BackendCapabilities:
        return self.inner.capabilities

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        with self._limiter:
            if _INTERRUPTED.is_set():
                raise RunInterrupted("interrupted")
            return self.inner.complete(req)
