from __future__ import annotations

import fcntl
import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.engagement import Engagement
from unvarnish.schemas.cost import CostEntry, CostLedger, Usage

log = logging.getLogger(__name__)

CACHE_READ_WEIGHT = 10


class BudgetExceeded(Exception):
    pass


class RunInterrupted(BudgetExceeded):
    """Ctrl-C. A subclass of BudgetExceeded so every phase stops the way it does at the cap:
    pending work is skipped, running calls finish, and the phase stays stale to resume."""


class BudgetTracker:
    def __init__(self, max_tokens: int | None) -> None:
        self.max_tokens = max_tokens
        self.usage = Usage()
        self._lock = threading.Lock()
        self.interrupted = threading.Event()  # set by the CLI on Ctrl-C; checked by check()

    def interrupt(self) -> None:
        self.interrupted.set()

    @property
    def stop_reason(self) -> str:
        return "interrupted" if self.interrupted.is_set() else "budget cap reached"

    def add(self, usage: Usage) -> None:
        with self._lock:
            self.usage = self.usage + usage

    @property
    def used(self) -> int:
        """Tokens counted against the cap. Cache reads are billed at about a tenth of input on
        every provider that offers caching, so they count at a tenth."""
        u = self.usage
        return (u.input_tokens + u.output_tokens + u.cache_write_tokens
                + u.cache_read_tokens // CACHE_READ_WEIGHT)

    @property
    def exceeded(self) -> bool:
        return self.max_tokens is not None and self.used > self.max_tokens

    def check(self) -> None:
        if self.interrupted.is_set():
            raise RunInterrupted("interrupted")
        if self.exceeded:
            raise BudgetExceeded(
                f"budget cap of {self.max_tokens:,} tokens exceeded ({self.used:,} counted; "
                f"cache reads count at 1/{CACHE_READ_WEIGHT})"
            )


_LEDGER_LOCK = threading.Lock()


def load_ledger(eng: Engagement) -> CostLedger:
    if not eng.cost_file.exists():
        return CostLedger()
    return read_artifact(eng.cost_file, CostLedger).data


@contextmanager
def _ledger_file_lock(eng: Engagement) -> Iterator[None]:
    """Serialise ledger writes across processes. `config check` records its probes while a
    `run`, `compare` or `ask` in another process may be writing the ledger, and the engagement
    lock does not cover it; an unguarded read-modify-write drops entries or corrupts the file.
    Held only for one write, so a blocking wait is short. Best effort: where the lock file
    cannot be opened or the filesystem refuses `flock` (ENOLCK on some NFS), the write goes
    ahead unguarded, as it did before, rather than losing the entry."""
    path = eng.root / ".unvarnish" / "cost.lock"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o666)  # the umask decides, as for run.lock
    except OSError as exc:
        log.debug("%s: cannot open the ledger lock (%s); writing unguarded", path, exc)
        yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            log.debug("%s: the filesystem refused a file lock (%s); writing unguarded", path,
                      exc)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def record_cost(eng: Engagement, entry: CostEntry) -> None:
    with _LEDGER_LOCK, _ledger_file_lock(eng):
        ledger = load_ledger(eng)
        ledger.entries.append(entry)
        write_artifact(eng.cost_file, ledger, produced_by="cost", inputs_hash="")
