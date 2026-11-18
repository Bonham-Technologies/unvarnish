"""UNVAR-6: one writing command (run, compare, ask) per engagement at a time."""

from __future__ import annotations

import errno
import os
import select
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish import lock as lockmod
from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.lock import EngagementLock, EngagementLocked, LockInfo

runner = CliRunner()

HOLDER = """
import sys, time
from datetime import timedelta
from pathlib import Path
from unvarnish.lock import EngagementLock
EngagementLock(Path(sys.argv[1]), command="run", stale_after=timedelta(minutes=10)).acquire()
print("ready", flush=True)
time.sleep(float(sys.argv[2]))
"""


@contextmanager
def holder(lock_file: Path, seconds: float = 120) -> Iterator[subprocess.Popen]:
    """A separate process holding the engagement lock until killed (or `seconds` pass)."""
    proc = subprocess.Popen([sys.executable, "-c", HOLDER, str(lock_file), str(seconds)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 30)
        line = proc.stdout.readline() if ready else ""
        if line.strip() != "ready":
            proc.kill()
            _, err = proc.communicate(timeout=10)
            pytest.fail(f"lock holder did not start: {err}")
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)


def _setup(tmp_path: Path, synthetic_repo: Path) -> Path:
    eng = tmp_path / "acme"
    assert runner.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = runner.invoke(app, ["add", "expense-bot", "--repo", str(synthetic_repo), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    return eng


def _lock_file(eng: Path) -> Path:
    return Engagement.load(eng).lock_file


def _foreign(path: Path, *, age: timedelta) -> LockInfo:
    """Lock contents left by a run on another machine (or another kernel), heartbeat `age` ago."""
    info = LockInfo(pid=4242, hostname="elsewhere", started_at=datetime.now(UTC) - age,
                    command="run", boot_id="another-kernel", pid_ns="pid:[1]")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(info.model_dump_json(), encoding="utf-8")
    then = time.time() - age.total_seconds()
    os.utime(path, (then, then))
    return info


# --- the ticket's test --------------------------------------------------------------------


def test_second_run_is_refused_then_takes_over_when_the_holder_dies(tmp_path: Path,
                                                                      synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    lock_file = _lock_file(eng)
    with holder(lock_file) as proc:
        refused = runner.invoke(app, ["run", "-e", str(eng)])
        assert refused.exit_code == 2, refused.output
        assert f"PID {proc.pid}" in refused.output
        assert "started" in refused.output
        assert not (eng / "tools" / "expense-bot" / "inventory" / "census.json").exists()
        proc.kill()  # SIGKILL: no cleanup, so the lock file keeps the dead holder's details
        proc.wait(timeout=10)
    proceeds = runner.invoke(app, ["run", "-e", str(eng)])
    assert proceeds.exit_code == 0, proceeds.output
    assert "stale" in proceeds.output and f"PID {proc.pid}" in proceeds.output
    assert (eng / "tools" / "expense-bot" / "inventory" / "census.json").exists()
    # Released on normal exit: the next run starts without a stale-lock warning.
    again = runner.invoke(app, ["run", "-e", str(eng)])
    assert again.exit_code == 0 and "stale" not in again.output


# --- which commands lock -------------------------------------------------------------------


def test_read_only_commands_do_not_need_the_lock(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    with holder(_lock_file(eng)) as proc:
        for args in (["status"], ["cost"], ["run", "--dry-run"]):
            r = runner.invoke(app, [*args, "-e", str(eng)])
            assert r.exit_code == 0, (args, r.output)
            assert str(proc.pid) not in r.output
        exported = runner.invoke(app, ["export", "-e", str(eng)])
        assert str(proc.pid) not in exported.output and "locked" not in exported.output


def test_compare_and_ask_take_the_lock(tmp_path: Path, synthetic_repo: Path, fake_llm):
    eng = _setup(tmp_path, synthetic_repo)
    cfg_file = eng / "engagement.yaml"
    cfg = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    cfg.update(model_config(fake_llm))
    cfg_file.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    with holder(_lock_file(eng)) as proc:
        for args in (["compare"], ["ask", "what does it do?"]):
            r = runner.invoke(app, [*args, "-e", str(eng)])
            assert r.exit_code == 2, (args, r.output)
            assert f"PID {proc.pid}" in r.output
    assert fake_llm.requests == []  # refused before any model call


# --- release on error and on Ctrl-C ---------------------------------------------------------


def _assert_released(lock_file: Path) -> None:
    assert lock_file.read_text(encoding="utf-8") == ""
    lock = EngagementLock(lock_file, command="test", stale_after=timedelta(minutes=10))
    assert lock.acquire() is None
    lock.release()


def test_run_releases_the_lock_on_ctrl_c(tmp_path: Path, synthetic_repo: Path, monkeypatch):
    eng = _setup(tmp_path, synthetic_repo)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("unvarnish.cli.wait", interrupted)
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 130, r.output
    _assert_released(_lock_file(eng))


def test_run_releases_the_lock_on_error(tmp_path: Path, synthetic_repo: Path, monkeypatch):
    eng = _setup(tmp_path, synthetic_repo)

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("unvarnish.cli.build_context", broken)
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code != 0 and isinstance(r.exception, RuntimeError)
    _assert_released(_lock_file(eng))


# --- stale age -------------------------------------------------------------------------------


def test_stale_age_is_configurable(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    lock_file = _lock_file(eng)
    _foreign(lock_file, age=timedelta(minutes=3))
    refused = runner.invoke(app, ["run", "-e", str(eng)])  # default: 10 minutes
    assert refused.exit_code == 2 and "PID 4242" in refused.output, refused.output
    assert "elsewhere" in refused.output

    cfg_file = eng / "engagement.yaml"
    cfg = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    cfg["pipeline"]["lock_stale_minutes"] = 2
    cfg_file.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    _foreign(lock_file, age=timedelta(minutes=3))
    taken = runner.invoke(app, ["run", "-e", str(eng)])
    assert taken.exit_code == 0, taken.output
    assert "stale" in taken.output and "PID 4242" in taken.output


# --- the lock itself -------------------------------------------------------------------------


def _lock(path: Path, **kw) -> EngagementLock:
    kw.setdefault("stale_after", timedelta(minutes=10))
    return EngagementLock(path, command="test", **kw)


def test_two_holders_in_one_process_conflict(tmp_path: Path):
    path = tmp_path / ".unvarnish" / "run.lock"
    with _lock(path):
        with pytest.raises(EngagementLocked) as exc:
            _lock(path).acquire()
        assert exc.value.holder is not None and exc.value.holder.pid == os.getpid()
        assert f"PID {os.getpid()}" in str(exc.value)
    assert path.read_text(encoding="utf-8") == ""  # released cleanly
    with _lock(path) as again:
        assert again.taken_over is None


def test_a_live_holder_on_another_kernel_is_respected_until_its_heartbeat_ages(tmp_path: Path):
    path = tmp_path / "run.lock"
    _foreign(path, age=timedelta(minutes=1))
    with pytest.raises(EngagementLocked) as exc:
        _lock(path).acquire()
    assert exc.value.holder.pid == 4242
    assert path.read_text(encoding="utf-8") != ""  # a refused acquire changes nothing

    _foreign(path, age=timedelta(minutes=11))
    lock = _lock(path)
    stale = lock.acquire()
    try:
        assert stale is not None and stale.holder.pid == 4242
        assert "heartbeat" in stale.reason
        assert LockInfo.model_validate_json(path.read_text(encoding="utf-8")).pid == os.getpid()
    finally:
        lock.release()


def test_unreadable_contents_are_judged_by_age(tmp_path: Path):
    path = tmp_path / "run.lock"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EngagementLocked) as exc:
        _lock(path).acquire()
    assert exc.value.holder is None and "unreadable" in str(exc.value)
    old = time.time() - 3600
    os.utime(path, (old, old))
    lock = _lock(path)
    stale = lock.acquire()
    assert stale is not None and stale.holder is None
    lock.release()


def test_heartbeat_refreshes_the_lock_file(tmp_path: Path):
    path = tmp_path / "run.lock"
    with _lock(path, heartbeat_seconds=0.05):
        old = time.time() - 1000
        os.utime(path, (old, old))
        deadline = time.time() + 5
        while path.stat().st_mtime < old + 500 and time.time() < deadline:
            time.sleep(0.05)
        assert path.stat().st_mtime > old + 500


def test_without_kernel_locks_a_dead_pid_on_this_kernel_is_stale(tmp_path: Path, monkeypatch):
    """Filesystems that refuse flock (some NFS setups) fall back to the PID check."""
    def no_flock(fd, op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(lockmod.fcntl, "flock", no_flock)
    path = tmp_path / "run.lock"
    here = lockmod.current_info("run")

    alive = here.model_copy(update={"pid": os.getppid()})
    path.write_text(alive.model_dump_json(), encoding="utf-8")
    with pytest.raises(EngagementLocked):
        _lock(path).acquire()

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait(timeout=30)
    dead = here.model_copy(update={"pid": child.pid})
    path.write_text(dead.model_dump_json(), encoding="utf-8")
    lock = _lock(path)
    stale = lock.acquire()
    assert stale is not None and stale.holder.pid == child.pid
    lock.release()


# --- after a reboot, and opening the file ----------------------------------------------------


def _left_before_reboot(path: Path, *, hostname: str, age: timedelta) -> None:
    """Lock contents a run on an earlier boot of a Linux kernel left behind (killed, or the
    machine lost power), heartbeat `age` ago."""
    here = lockmod.current_info("run")
    info = here.model_copy(update={"pid": 4242, "hostname": hostname,
                                   "boot_id": "an-earlier-boot"})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(info.model_dump_json(), encoding="utf-8")
    then = time.time() - age.total_seconds()
    os.utime(path, (then, then))


@pytest.mark.skipif(lockmod.current_info("run").boot_id is None, reason="needs a Linux boot_id")
def test_a_lock_left_before_this_machine_rebooted_is_taken_over_at_once(tmp_path: Path,
                                                                         monkeypatch):
    """A scheduled run right after a reboot must not wait out lock_stale_minutes."""
    path = tmp_path / "run.lock"
    monkeypatch.setattr(lockmod, "_boot_time", lambda: time.time() - 60)  # booted a minute ago
    _left_before_reboot(path, hostname=lockmod.socket.gethostname(),
                        age=timedelta(minutes=2))
    lock = _lock(path)
    stale = lock.acquire()
    try:
        assert stale is not None and stale.holder.pid == 4242
        assert "restarted" in stale.reason
    finally:
        lock.release()


@pytest.mark.skipif(lockmod.current_info("run").boot_id is None, reason="needs a Linux boot_id")
def test_a_reboot_does_not_excuse_a_holder_that_beat_since_or_lives_elsewhere(tmp_path: Path,
                                                                             monkeypatch):
    path = tmp_path / "run.lock"
    host = lockmod.socket.gethostname()
    # Same name, but its heartbeat is newer than this boot: a live twin-named machine.
    monkeypatch.setattr(lockmod, "_boot_time", lambda: time.time() - 600)
    _left_before_reboot(path, hostname=host, age=timedelta(minutes=1))
    with pytest.raises(EngagementLocked):
        _lock(path).acquire()
    # Heartbeat before this boot, but another host: it may be live on a kernel we can't see.
    monkeypatch.setattr(lockmod, "_boot_time", lambda: time.time() - 60)
    _left_before_reboot(path, hostname="elsewhere", age=timedelta(minutes=2))
    with pytest.raises(EngagementLocked):
        _lock(path).acquire()
    # No boot time to compare (not Linux, /proc hidden): only the age rule applies.
    monkeypatch.setattr(lockmod, "_boot_time", lambda: None)
    _left_before_reboot(path, hostname=host, age=timedelta(minutes=2))
    with pytest.raises(EngagementLocked):
        _lock(path).acquire()


def test_the_lock_file_honours_the_umask_like_other_engagement_files(tmp_path: Path):
    """A group-shared engagement (umask 002) must stay lockable by the group's other users."""
    path = tmp_path / ".unvarnish" / "run.lock"
    old = os.umask(0o002)
    try:
        with _lock(path):
            pass
    finally:
        os.umask(old)
    assert path.stat().st_mode & 0o777 == 0o664


def test_an_unopenable_lock_file_is_a_clean_error(tmp_path: Path, synthetic_repo: Path,
                                                  monkeypatch):
    eng = _setup(tmp_path, synthetic_repo)
    real_open = os.open

    def refuse(path, *args, **kwargs):
        if str(path).endswith("run.lock"):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(lockmod.os, "open", refuse)
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 2, r.output
    assert "run.lock" in r.output and "Permission denied" in r.output
    assert not isinstance(r.exception, PermissionError)


# --- with UNVAR-17's missing tool.yaml -------------------------------------------------------


def test_a_missing_tool_is_refused_before_the_lock_and_the_others_run_under_it(
        tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert runner.invoke(app, ["add", "other", "--files", str(other),
                               "-e", str(eng)]).exit_code == 0
    (eng / "tools" / "expense-bot" / "tool.yaml").unlink()
    lock_file = _lock_file(eng)
    with holder(lock_file) as proc:
        # Nothing left to run, or nothing ask may read: refused without touching the lock,
        # so the message is the missing tool, not the holder.
        for args in (["run", "expense-bot"], ["ask", "--tool", "expense-bot", "what?"]):
            r = runner.invoke(app, [*args, "-e", str(eng)], env={"COLUMNS": "200"})
            assert r.exit_code == 2, (args, r.output)
            assert "tool.yaml not found" in r.output and f"PID {proc.pid}" not in r.output
        # A run with tools left to run still needs the lock.
        r = runner.invoke(app, ["run", "-e", str(eng)], env={"COLUMNS": "200"})
        assert r.exit_code == 2 and f"PID {proc.pid}" in r.output, r.output
        assert not (eng / "tools" / "other" / "inventory" / "census.json").exists()
    r = runner.invoke(app, ["run", "-e", str(eng)], env={"COLUMNS": "200"})
    assert r.exit_code == 2 and "could not run" in r.output, r.output
    assert (eng / "tools" / "other" / "inventory" / "census.json").exists()
    assert lock_file.read_text(encoding="utf-8") == ""  # released after the partial run
