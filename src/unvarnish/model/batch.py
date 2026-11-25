"""Opt-in Message Batches mode (UNVAR-94).

A batched phase sends the first call of each of its requests in one message batch, waits for
the batch to end, and writes every usable reply into the response cache under the request's
cache key. The phase then runs exactly as it does synchronously: its first calls are cache
hits, and only what the batch could not answer (an errored, expired or refused request, a
reply that does not parse, a retry) is sent as an ordinary call. So a batched run produces
the same artifacts as a synchronous one on the same replies, and nothing is ever dropped.

The submitted batch ids are kept in a state file until the results are in the cache, so a
run stopped while a batch is in progress picks the same batch up on the next run.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from unvarnish.config import EngagementConfig
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
)
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.schemas.cost import BATCH_RATE, Usage

__all__ = ["BATCH_PHASES", "BATCH_RATE", "BatchResult", "BatchRetryLater", "batch_configured",
           "find_batcher", "run_batch"]  # BATCH_RATE lives with the ledger that prices it
log = logging.getLogger("unvarnish.batch")

# The phases whose calls may go in batches. Extract needs its neighbours' summaries in order,
# and the rollups wait on each other, so they stay synchronous (option B of UNVAR-94).
BATCH_PHASES = ("verify", "render")
POLL_SECONDS = 30   # between status checks; a batch usually ends within the hour
MAX_BATCH_REQUESTS = 100_000          # the API's limits per batch
MAX_BATCH_BYTES = 200 * 1024 * 1024   # of 256 MB, leaving room for the request envelope
MAX_RESULT_TRIES = 10  # rate-limited result downloads, a poll apart, before the run stops
RETENTION_NOTICE = ("backend {name!r} sends verify and prose through the Message Batches API: "
                    "the provider keeps results for 29 days, and batches are not eligible for "
                    "zero data retention")


class BatchRetryLater(BackendError):
    """A batch endpoint rate limited the request (HTTP 429). Nothing is wrong with the batch:
    ask again later, and never drop it, or its requests would be paid for twice."""


@dataclass
class BatchResult:
    custom_id: str
    response: CompletionResponse | None = None
    error: str | None = None  # "expired", "canceled", or "errored: <type>: <message>"


class Batcher(Protocol):
    name: str
    model: str
    batch: bool

    def sleep(self, seconds: float) -> None: ...
    def submit_batch(self, items: list[tuple[str, CompletionRequest]]) -> str: ...
    def batch_ended(self, batch_id: str) -> bool: ...
    def batch_results(self, batch_id: str) -> Iterable[BatchResult]: ...


class SubmittedBatch(BaseModel):
    batch_id: str
    keys: list[str] = Field(default_factory=list)  # the custom ids: the requests' cache keys


class BatchState(BaseModel):
    backend: str
    model: str
    batches: list[SubmittedBatch] = Field(default_factory=list)


@dataclass
class BatchOutcome:
    usage: Usage = field(default_factory=Usage)
    submitted: int = 0   # requests sent in new batches this run
    cached: int = 0      # replies written to the response cache
    unanswered: int = 0  # errored, expired, refused, empty or cut off: sent as calls instead
    resumed: bool = False


def batch_configured(config: EngagementConfig, phase: str) -> bool:
    """Whether `phase`'s calls go in batches: a batchable phase on a `batch: true` backend."""
    from unvarnish.model.registry import resolve_model_ref

    if phase not in BATCH_PHASES:
        return False
    ref = resolve_model_ref(config, phase)
    cfg = config.backends.get(ref.backend) if ref else None
    return bool(cfg and cfg.batch)


def find_batcher(backend: Any) -> Batcher | None:
    """The backend in a wrapper chain (cache, limiter, refusal retry) that batches, if any."""
    node, depth = backend, 0
    while node is not None and depth < 8:
        if getattr(node, "batch", False) is True and callable(getattr(node, "submit_batch",
                                                                      None)):
            return node
        node = getattr(node, "inner", None) or getattr(node, "primary", None)
        depth += 1
    return None


def _chunks(pending: list[tuple[str, CompletionRequest]]
            ) -> Iterable[list[tuple[str, CompletionRequest]]]:
    chunk: list[tuple[str, CompletionRequest]] = []
    size = 0
    for item in pending:
        n = len(json.dumps(item[1].model_dump(mode="json"), ensure_ascii=False))
        if chunk and (len(chunk) >= MAX_BATCH_REQUESTS or size + n > MAX_BATCH_BYTES):
            yield chunk
            chunk, size = [], 0
        chunk.append(item)
        size += n
    if chunk:
        yield chunk


def _load_state(path: Path) -> BatchState | None:
    from unvarnish.artifacts import read_artifact

    if not path.exists():
        return None
    try:
        return read_artifact(path, BatchState).data
    except Exception:  # unreadable: its batch is lost to us, the requests go again
        log.warning("%s unreadable; its batch is not resumed", path)
        return None


def _save_state(path: Path, state: BatchState, phase: str) -> None:
    from unvarnish.artifacts import write_artifact

    path.parent.mkdir(parents=True, exist_ok=True)
    write_artifact(path, state, produced_by=phase, inputs_hash="")


def _done(path: Path, state: BatchState, batch_id: str, phase: str) -> None:
    """Forget a batch whose results are in the cache (or lost): a later stop must not leave it
    in the state file, or the next run would collect it again and bill its usage twice."""
    state.batches = [b for b in state.batches if b.batch_id != batch_id]
    if state.batches:
        _save_state(path, state, phase)
    else:
        path.unlink(missing_ok=True)


def _stopping(budget: BudgetTracker) -> bool:
    from unvarnish.model.limit import new_calls_stopped

    return budget.interrupted.is_set() or new_calls_stopped()


def _pause(batcher: Batcher, budget: BudgetTracker) -> bool:
    """One poll interval in one-second steps, so that Ctrl-C ends it at once (False)."""
    for _ in range(POLL_SECONDS):
        if _stopping(budget):
            return False
        batcher.sleep(1.0)
    return True


def _wait(batcher: Batcher, batch_id: str, budget: BudgetTracker) -> bool:
    """Until the batch ends (True), or a stop (False). A stop leaves the state file: the next
    run picks the same batch up. A rate-limited status check counts as still in progress."""
    while True:
        try:
            if batcher.batch_ended(batch_id):
                return True
        except BatchRetryLater as exc:
            log.info("status check of batch %s rate limited (%s); checking again later",
                     batch_id, exc)
        if not _pause(batcher, budget):
            log.info("stopped while message batch %s is in progress; the next run collects it",
                     batch_id)
            return False


def _collect(batcher: Batcher, cache: Any, batch_id: str, budget: BudgetTracker,
             out: BatchOutcome, phase: str) -> str:
    """The batch's replies into the cache once it ends: "done"; "stopped" on a stop, the batch
    kept for the next run; "lost" when its results cannot be read (a non-fatal error), its
    uncollected requests then going as ordinary calls. A rate-limited download is tried again
    a poll later, skipping the replies already taken; a fatal error propagates with the batch
    kept. The batch's usage counts once it is done or lost, never while it is kept, so that
    the run which finally collects it bills it exactly once."""
    usage = Usage()
    seen: set[str] = set()
    try:
        if not _wait(batcher, batch_id, budget):
            return "stopped"
        for attempt in range(1, MAX_RESULT_TRIES + 1):
            try:
                for r in batcher.batch_results(batch_id):
                    if r.custom_id in seen:
                        continue
                    seen.add(r.custom_id)
                    usage = _take(cache, batch_id, r, usage, out)
                break
            except BatchRetryLater as exc:
                if attempt == MAX_RESULT_TRIES:
                    raise BackendUnavailable(
                        f"results of batch {batch_id} still rate limited after "
                        f"{MAX_RESULT_TRIES} tries: {exc}; the next run collects it") from exc
                log.info("results of batch %s rate limited (%s); trying again later",
                         batch_id, exc)
                if not _pause(batcher, budget):
                    return "stopped"
    except BackendError as exc:
        if getattr(exc, "fatal", False):
            raise
        log.warning("%s: batch %s cannot be read (%s); its requests go again", phase,
                    batch_id, exc)
        out.usage = out.usage + usage  # the replies already cached are used, and were paid
        return "lost"
    out.usage = out.usage + usage
    return "done"


def _take(cache: Any, batch_id: str, r: BatchResult, usage: Usage,
          out: BatchOutcome) -> Usage:
    """One result into the cache, or counted as unanswered; the batch's usage so far."""
    if r.response is not None:
        usage = usage + r.response.usage
        if cache.store(r.custom_id, r.response):
            out.cached += 1
            return usage
        why = (f"refused ({r.response.refusal_category})" if r.response.refusal_category
               else f"stop reason {r.response.stop_reason}" if r.response.text.strip()
               else "empty reply")
    else:
        why = r.error or "no result"
    out.unanswered += 1
    log.info("batch %s: request %s %s; it goes as an ordinary call", batch_id,
             r.custom_id[:12], why)
    return usage


def run_batch(backend: Any, requests: list[CompletionRequest], state_path: Path, *,
              budget: BudgetTracker, phase: str) -> BatchOutcome:
    """Answer `requests` through message batches, into `backend`'s response cache.

    `backend` is the phase's backend: a CachingBackend over a chain that holds a batcher.
    Requests already cached are not sent. A stored batch (a run stopped while it was in
    progress) is collected first and its requests are never sent again in a batch. The cap
    is checked once before a new batch: a batch is one spend that cannot stop half way.
    A stop (Ctrl-C) returns at once and keeps the state; the phase then stops as it does
    synchronously, without calls, and the next run collects the batch."""
    from unvarnish.model.cache import CachingBackend

    out = BatchOutcome()
    batcher = find_batcher(backend)
    if batcher is None:
        return out
    if not isinstance(backend, CachingBackend):
        log.warning("%s: batch mode needs the response cache; sending calls instead", phase)
        return out
    covered: set[str] = set()
    state = _load_state(state_path)
    if state is not None and (state.backend, state.model) == (batcher.name, batcher.model):
        out.resumed = True
        for sub in list(state.batches):
            log.info("%s: resuming message batch %s", phase, sub.batch_id)
            got = _collect(batcher, backend, sub.batch_id, budget, out, phase)
            if got == "stopped":
                return out
            if got == "done":
                covered.update(sub.keys)
            _done(state_path, state, sub.batch_id, phase)
    elif state is not None:
        log.info("%s: stored batch was for %s/%s; not resumed", phase, state.backend,
                 state.model)
    state_path.unlink(missing_ok=True)

    by_key = {backend.key(r): r for r in requests}
    pending = [(k, r) for k, r in by_key.items() if k not in covered and not backend.has(r)]
    if not pending:
        return out
    try:
        budget.check()
    except BudgetExceeded:  # the cap or a stop: the synchronous path stops and records it
        return out
    state = BatchState(backend=batcher.name, model=batcher.model)
    try:
        for chunk in _chunks(pending):
            batch_id = batcher.submit_batch(chunk)
            state.batches.append(SubmittedBatch(batch_id=batch_id, keys=[k for k, _ in chunk]))
            _save_state(state_path, state, phase)  # before the wait: a stop can resume it
            out.submitted += len(chunk)
            log.info("%s: message batch %s submitted with %d requests; checking every %ds "
                     "(results usually within the hour)", phase, batch_id, len(chunk),
                     POLL_SECONDS)
    except BackendError as exc:
        if getattr(exc, "fatal", False):
            raise
        log.warning("%s: batch submission failed (%s); the rest go as ordinary calls", phase,
                    exc)
    for sub in list(state.batches):
        if _collect(batcher, backend, sub.batch_id, budget, out, phase) == "stopped":
            return out
        _done(state_path, state, sub.batch_id, phase)
    state_path.unlink(missing_ok=True)
    return out
