"""The engagement lock: one writing command (run, compare, ask) per engagement at a time.

Two runs on one engagement would each enforce the token cap on their own and rewrite
`cost.json` over each other. The lock is `.unvarnish/run.lock` in the engagement:

- Mutual exclusion is `flock` on the open file. The kernel drops it when the holder exits,
  however it exits, and it holds across Docker containers that share a kernel and a mount.
- The file's contents (a `LockInfo`) name the holder, for the refusal message and for judging
  leftovers. A clean release empties the file; a holder that died leaves its details behind.
- While held, a heartbeat thread touches the file's mtime. A holder on another kernel (the
  macOS host and a container in Docker Desktop's VM, two machines on a network share) can't
  be seen through `flock` everywhere, so its lock counts as stale once the heartbeat is older
  than `stale_after`.

The file is never deleted or replaced: a new inode at the path would let a second process
lock it while the first still holds the old one.
"""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ValidationError

log = logging.getLogger(__name__)

BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")
PROC_STAT = Path("/proc/stat")
PID_NS_LINK = "/proc/self/ns/pid"
MAX_LOCK_BYTES = 64 * 1024
HEARTBEAT_MAX_SECONDS = 30.0


class LockInfo(BaseModel):
    """Who holds the lock. Written to the lock file as JSON."""

    pid: int
    hostname: str
    started_at: datetime
    command: str
    # Linux's per-boot kernel id: every container on one kernel sees the same one, so two
    # holders with equal boot ids share a kernel (and so share flock). None off Linux.
    boot_id: str | None = None
    # PIDs compare only within one PID namespace (each container has its own).
    pid_ns: str | None = None

    def describe(self) -> str:
        started = self.started_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (f"PID {self.pid} on host {self.hostname} (unvarnish {self.command}, "
                f"started {started})")


@dataclass
class StaleLock:
    """A lock left by a holder judged gone, which `acquire` took over."""

    holder: LockInfo | None  # None: the file's contents could not be read
    reason: str

    def describe(self) -> str:
        who = self.holder.describe() if self.holder else "an unknown process"
        return f"took over a stale engagement lock held by {who}: {self.reason}"


class EngagementLocked(Exception):
    def __init__(self, path: Path, holder: LockInfo | None) -> None:
        self.path = path
        self.holder = holder
        who = (holder.describe() if holder
               else "another process (the lock file's contents are unreadable)")
        super().__init__(
            f"another unvarnish command is working on this engagement: {who}. Wait for it to "
            f"finish; if that process is gone, see \"Stale engagement lock\" in "
            f"docs/operations.md. Lock file: {path}")


def _read_text(path: Path | str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _pid_ns() -> str | None:
    try:
        return os.readlink(PID_NS_LINK)
    except OSError:
        return None


def current_info(command: str) -> LockInfo:
    return LockInfo(pid=os.getpid(), hostname=socket.gethostname(),
                    started_at=datetime.now(UTC), command=command,
                    boot_id=_read_text(BOOT_ID_FILE), pid_ns=_pid_ns())


def _boot_time() -> float | None:
    """When this kernel booted, as a Unix time (Linux `btime`); None where it can't be read."""
    try:
        for line in PROC_STAT.read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def same_kernel(a: LockInfo, b: LockInfo) -> bool:
    """True when both holders run on one kernel. Boot ids decide when either side has one, so
    a container whose hostname matches the macOS host is not mistaken for it."""
    if a.boot_id or b.boot_id:
        return a.boot_id == b.boot_id
    return a.hostname == b.hostname


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # exists, owned by someone else
        return True
    return True


def _read_contents(fd: int) -> tuple[bool, LockInfo | None]:
    """(whether the file has contents, the holder they name or None if unreadable)."""
    raw = os.pread(fd, MAX_LOCK_BYTES, 0)
    if not raw.strip():
        return False, None
    try:
        return True, LockInfo.model_validate_json(raw)
    except (ValidationError, ValueError):
        return True, None


class EngagementLock:
    def __init__(self, path: Path, *, command: str, stale_after: timedelta,
                 heartbeat_seconds: float | None = None) -> None:
        self.path = path
        self.command = command
        self.stale_after = stale_after
        self.heartbeat_seconds = heartbeat_seconds or max(
            0.5, min(HEARTBEAT_MAX_SECONDS, stale_after.total_seconds() / 4))
        self.taken_over: StaleLock | None = None
        self._fd: int | None = None
        self._stop = threading.Event()
        self._beat: threading.Thread | None = None

    # --- acquire ---------------------------------------------------------------------------
    def acquire(self) -> StaleLock | None:
        """Take the lock, or raise EngagementLocked naming the live holder. Returns the stale
        lock this took over, if any, so the caller can warn about it."""
        if self._fd is not None:
            raise RuntimeError("engagement lock already held")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Python descriptors are not inherited by child processes (PEP 446), so git and the
        # scanners never hold the lock past this process.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o666)  # the umask decides, as for
        # every other engagement file, so a group-shared engagement stays lockable
        try:
            kernel_lock = self._flock(fd)
            has_contents, previous = _read_contents(fd)
            stale = None
            if has_contents:
                reason = self._gone(fd, previous, kernel_lock)
                if reason is None:
                    raise EngagementLocked(self.path, previous)
                stale = StaleLock(previous, reason)
            data = current_info(self.command).model_dump_json(indent=2) + "\n"
            os.ftruncate(fd, 0)
            os.pwrite(fd, data.encode("utf-8"), 0)
            os.fsync(fd)
        except BaseException:
            os.close(fd)  # closing drops the flock, if this took it
            raise
        self._fd = fd
        self.taken_over = stale
        self._stop.clear()
        self._beat = threading.Thread(target=self._heartbeat, name="engagement-lock",
                                      daemon=True)
        self._beat.start()
        return stale

    def _flock(self, fd: int) -> bool:
        """True when the kernel lock is held; False when the filesystem cannot lock."""
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:  # another open file holds it: a live holder on this kernel
            _, holder = _read_contents(fd)
            raise EngagementLocked(self.path, holder) from None
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                _, holder = _read_contents(fd)
                raise EngagementLocked(self.path, holder) from None
            log.warning("%s: the filesystem refused a file lock (%s); falling back to the lock "
                        "file's contents, which cannot stop two runs starting in the same "
                        "instant", self.path, exc.strerror or exc)
            return False

    def _gone(self, fd: int, previous: LockInfo | None, kernel_lock: bool) -> str | None:
        """Why the previous holder counts as gone, or None while it may be alive."""
        here = current_info(self.command)
        if previous is not None and same_kernel(previous, here):
            if kernel_lock:
                # Same kernel and the flock was free: the holder's descriptor is closed.
                return "its process has exited"
            if (previous.pid_ns is not None and previous.pid_ns == here.pid_ns
                    and (previous.pid == here.pid or not _pid_alive(previous.pid))):
                return "its process has exited"
        mtime = os.fstat(fd).st_mtime
        if (previous is not None and previous.boot_id and here.boot_id
                and previous.boot_id != here.boot_id and previous.hostname == here.hostname):
            # This machine's name, another boot: a reboot (or a killed run) ended the holder
            # if its last heartbeat predates this kernel. A live twin-named machine sharing the
            # folder beats every few seconds, so its heartbeat would be newer than this boot.
            booted = _boot_time()
            if booted is not None and mtime < booted:
                return "the machine has restarted since its last heartbeat"
        age = time.time() - mtime
        if age > self.stale_after.total_seconds():
            return (f"no heartbeat for {age / 60:.0f} minute(s), more than the "
                    f"{self.stale_after.total_seconds() / 60:g} allowed "
                    "(pipeline.lock_stale_minutes)")
        return None

    def _heartbeat(self) -> None:
        while not self._stop.wait(self.heartbeat_seconds):
            fd = self._fd
            if fd is None:
                return
            try:
                if os.utime in os.supports_fd:
                    os.utime(fd)
                else:
                    os.utime(self.path)
            except OSError as exc:  # a missed beat only brings staleness closer
                log.debug("engagement lock heartbeat failed: %s", exc)

    # --- release ---------------------------------------------------------------------------
    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        self._stop.set()
        if self._beat is not None:
            self._beat.join(timeout=5)
            self._beat = None
        self._fd = None
        try:
            os.ftruncate(fd, 0)  # empty means released cleanly: the next run need not judge it
        except OSError as exc:
            log.debug("could not empty the engagement lock file: %s", exc)
        finally:
            os.close(fd)  # drops the flock

    def __enter__(self) -> EngagementLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
