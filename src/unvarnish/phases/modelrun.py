from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import BaseModel

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.model.base import (
    Backend,
    BackendConfigError,
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    ModelRefusal,
)
from unvarnish.model.batch import BatchOutcome, run_batch
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.structured import (
    StructuredOutputError,
    StructuredResult,
    complete_structured,
)
from unvarnish.phases.base import ToolContext
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.cost import CostEntry, Usage

log = logging.getLogger("unvarnish.modelrun")


def call_structured[T: BaseModel](
    backend: Backend, req: CompletionRequest, model_cls: type[T], *, phase: str,
    item_id: str | None, path: str | None, stop: threading.Event,
) -> tuple[StructuredResult[T] | None, FailureRecord | None]:
    """One structured call. Recoverable errors become a FailureRecord; an outage stops the run."""
    try:
        return complete_structured(backend, req, model_cls), None
    except ModelRefusal as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=f"refused ({exc.category})")
    except StructuredOutputError as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=exc.last_error[:500], attempts=exc.attempts)
    except BackendUnavailable:
        stop.set()  # nothing else can succeed; let the other workers drain
        raise
    except BackendConfigError:
        stop.set()  # configuration is wrong for every item: stop, never record per item
        raise
    except BackendError as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=str(exc)[:500])


@dataclass
class ItemOutcome[T]:
    result: T | None = None
    failures: list[FailureRecord] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)


@dataclass
class ParallelOutcome[T]:
    results: list[T] = field(default_factory=list)
    failures: list[FailureRecord] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    processed: int = 0
    stopped_for_budget: bool = False
    fatal: BackendUnavailable | None = None

    @property
    def stopped(self) -> bool:
        return self.stopped_for_budget or self.fatal is not None


def run_parallel[I, T](
    items: Sequence[I], worker: Callable[[I, threading.Event], ItemOutcome[T]], *,
    workers: int, budget: BudgetTracker, phase: str = "model",
) -> ParallelOutcome[T]:
    """Run `worker` over `items` in a thread pool against a shared budget.

    The budget is checked before each item and charged after it. A budget cap or a backend
    outage sets the stop event: pending items are skipped, running ones drain, and the outcome
    records what finished. Any other exception from a worker (a disk write failing, a bug on
    one pathological input) becomes a recorded failure for that item: one bad item never kills
    a run. An interrupt propagates after the pool drains.
    """
    stop = threading.Event()
    budget_hit = threading.Event()
    out: ParallelOutcome[T] = ParallelOutcome()

    def guarded(item: I) -> ItemOutcome[T] | None:
        if stop.is_set():
            return None
        try:
            budget.check()
        except BudgetExceeded:
            budget_hit.set()
            stop.set()
            return None
        try:
            result = worker(item, stop)
        except BudgetExceeded:  # interrupted while waiting for a model slot
            budget_hit.set()
            stop.set()
            return None
        except BackendUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            log.exception("%s: worker failed on %r", phase, item)
            return ItemOutcome(failures=[FailureRecord(phase=phase, error=repr(exc)[:500])])
        budget.add(result.usage)
        return result

    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = [pool.submit(guarded, item) for item in items]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except BackendUnavailable as exc:
                out.fatal = out.fatal or exc
                continue
            if res is None:
                continue
            out.processed += 1
            out.failures.extend(res.failures)
            out.usage = out.usage + res.usage
            if res.result is not None:
                out.results.append(res.result)
    except BaseException:  # interrupt: stop the workers, then propagate
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    out.stopped_for_budget = budget_hit.is_set()
    return out


def has_failures(ctx: ToolContext, phase: str) -> bool:
    """True while failures.json holds entries for `phase`: the phase stays stale until a run
    retries them, whatever inputs hash its artifact records (UNVAR-29). Unreadable: False."""
    if not ctx.paths.failures.exists():
        return False
    try:
        items = read_artifact(ctx.paths.failures, Failures).data.items
    except Exception:  # merge_failures rewrites an unreadable file on the next run
        return False
    return any(f.phase == phase for f in items)


def merge_failures(ctx: ToolContext, phase: str, items: list[FailureRecord]) -> None:
    """Replace `phase`'s entries in failures.json, keeping every other phase's entries."""
    existing: list[FailureRecord] = []
    if ctx.paths.failures.exists():
        try:
            existing = read_artifact(ctx.paths.failures, Failures).data.items
        except Exception:  # unreadable: start over rather than fail the phase
            log.warning("failures.json unreadable; rewriting it")
    kept = [f for f in existing if f.phase != phase]
    write_artifact(ctx.paths.failures, Failures(tool=ctx.tool, items=kept + items),
                   produced_by=phase, inputs_hash="")


def batch_first_calls(ctx: ToolContext, phase: str, backend: Backend,
                      requests: list[CompletionRequest], budget: BudgetTracker) -> Usage:
    """Send the first call of each request in a message batch when the phase's backend has
    `batch: true` (UNVAR-94); the replies land in the response cache, where the phase's
    ordinary calls find them. The batch's usage goes in the ledger at once, marked as billed
    at the batch rate, and is returned for the phase's artifact and its budget. It reaches the
    ledger even when a later batch raises: the batches collected before it are in the cache,
    so the next run gets their replies free and would never bill them. On such an error the
    phase ends here, so the budget counts it too; otherwise the phase adds it to the budget
    once its workers have used the replies."""
    out = BatchOutcome()
    try:
        run_batch(backend, requests, ctx.paths.batch_state(phase), budget=budget,
                  phase=phase, out=out)
    except BaseException:
        budget.add(out.usage)
        raise
    finally:
        if out.usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=phase, backend=backend.name, model=backend.model,
                usage=out.usage, at=datetime.now(UTC), batch=True))
    if out.submitted or out.resumed:
        log.info("%s %s: batch answered %d, %d go as ordinary calls", phase, ctx.tool,
                 out.cached, out.unanswered)
    return out.usage
