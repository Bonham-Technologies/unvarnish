from __future__ import annotations

import atexit
import functools
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path


class GitError(RuntimeError):
    pass


class UntrustedRepoError(GitError):
    """Unvarnish could not establish which of the repository's own drivers to disarm, so it
    refuses to run git on it rather than run them."""


# Make output parseable regardless of the operator's ~/.gitconfig.
GIT_BASE_ARGS = [
    "-c", "core.quotepath=off",
    "-c", "diff.noprefix=false",
    "-c", "diff.mnemonicPrefix=false",
    "-c", "log.showSignature=false",
]


GIT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",   # never ask for a username or password on the terminal
    "GIT_ASKPASS": "",            # nor through a GUI helper (a helper the user set is kept)
    "SSH_ASKPASS": "",
    "GCM_INTERACTIVE": "never",   # Git Credential Manager
}
BATCH_MODE = "-o BatchMode=yes"


@functools.lru_cache(maxsize=32)
def _core_ssh_command(config_key: tuple) -> str | None:
    """core.sshCommand from the operator's global or system git configuration, if any.

    Never the repository's own config: an ingested repo is untrusted, and its
    core.sshCommand would otherwise run for every later git call. Cached per configuration
    location (config_key) so each git call does not spawn a second git."""
    scopes = ["--global"] if os.environ.get("GIT_CONFIG_NOSYSTEM") else ["--global", "--system"]
    for scope in scopes:
        try:
            proc = subprocess.run(["git", "config", scope, "--get", "core.sshCommand"],
                                  cwd=tempfile.gettempdir(), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  env={**os.environ, **GIT_ENV}, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.stdout.strip():
            return proc.stdout.strip()
    return None


@functools.lru_cache(maxsize=1)
def _empty_hooks_dir() -> str:
    """An empty directory for core.hooksPath, made once per process."""
    path = tempfile.mkdtemp(prefix="unvarnish-nohooks-")
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path


def _untrusted_repo_config() -> list[tuple[str, str]]:
    """Config that stops an ingested repo from running its own code: its hooks, its
    core.fsmonitor command, ext:: transport URLs (in submodules, for instance), the gpg.program
    a signature check would run, and recursion into submodules, whose own gitdir config
    names drivers repo_drivers() does not read (a recursive checkout runs their filters;
    `diff.submodule=diff` runs their textconv inside `git log -p`)."""
    return [
        ("core.hooksPath", _empty_hooks_dir()),
        ("core.fsmonitor", "false"),
        ("protocol.ext.allow", "never"),
        ("log.showSignature", "false"),
        ("submodule.recurse", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("diff.submodule", "short"),
    ]


def _with_config(env: dict[str, str], pairs: list[tuple[str, str]]) -> None:
    """Append pairs to GIT_CONFIG_COUNT/KEY_n/VALUE_n, keeping any the operator set.
    Command-scope config outranks the repository's own .git/config."""
    try:
        start = max(int(env.get("GIT_CONFIG_COUNT") or 0), 0)
    except ValueError:  # git rejects a bogus count anyway; ours must still be read
        start = 0
    for i, (key, value) in enumerate(pairs, start):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(start + len(pairs))


# A config key that defines a filter or diff driver: section, subsection (the driver's name,
# which may itself contain dots, or be empty: `filter=` names the driver ""), variable.
_DRIVER_KEY = re.compile(r"(filter|diff)\.(.*)\.([^.]+)", re.DOTALL)
MAX_REPO_DRIVERS = 200
MAX_INCLUDED_FILES = 64


def _lookup_env() -> dict[str, str]:
    """The environment of the driver lookup's own git calls. Their messages are parsed (a
    "not a git repository" means no drivers), and git translates them, so they run in the C
    locale."""
    env = {**os.environ, **GIT_ENV, "LC_ALL": "C", "LANGUAGE": ""}
    _with_config(env, _untrusted_repo_config())
    return env


def _read_config(args: Sequence[str], cwd: Path) -> list[tuple[str, str]]:
    """(key, value) pairs from `git config <args> --list -z`. Reading config never runs
    anything from it. Bytes that aren't UTF-8 are kept as surrogate escapes, which turn back
    into the same bytes in argv and the environment: git matches a driver name byte for byte.
    A file git can't read in time, or at all, raises: an empty answer would leave the
    drivers armed for the git call that follows, which has no time limit."""
    env = _lookup_env()
    try:
        proc = subprocess.run(["git", *_safe_args(), "config", *args, "--list", "-z"],
                              cwd=cwd, capture_output=True, env=env, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UntrustedRepoError(f"could not read the repository's config to find its filter "
                                 f"and diff drivers: {exc}") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise UntrustedRepoError(f"could not read the repository's config to find its filter "
                                 f"and diff drivers: {err}")
    entries = proc.stdout.decode("utf-8", "surrogateescape").split("\0")
    return [(key, value) for key, _, value in (e.partition("\n") for e in entries if e)]


def _repo_config_files(repo: Path) -> list[Path]:
    """The repository's own config files: the shared config, and the per-worktree ones. None
    outside a repository; any other failure raises, like _read_config."""
    env = _lookup_env()
    try:
        proc = subprocess.run(
            ["git", *_safe_args(), "rev-parse", "--path-format=absolute", "--git-dir",
             "--git-common-dir"],
            cwd=repo, capture_output=True, text=True, encoding="utf-8",
            errors="surrogateescape", env=env, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UntrustedRepoError(f"could not find the repository's config to read its filter "
                                 f"and diff drivers: {exc}") from exc
    if proc.returncode != 0:
        if "not a git repository" in proc.stderr:
            return []
        raise UntrustedRepoError(f"could not find the repository's config to read its filter "
                                 f"and diff drivers: {proc.stderr.strip()}")
    dirs = [Path(line) for line in proc.stdout.splitlines() if line]
    return [d / name for d in reversed(dirs) for name in ("config", "config.worktree")]


def _include_target(value: str, including: Path) -> Path | None:
    """Where an include.path or includeIf.*.path points, resolved as git does: `~/` from
    HOME, a relative path from the directory of the including file's path as opened, not of
    the file a symlink leads to."""
    if not value or value.startswith("%("):
        return None
    if value.startswith("~"):
        return Path(os.path.expanduser(value))
    path = Path(value)
    return path if path.is_absolute() else including.parent / path


def repo_drivers(repo: Path) -> set[tuple[str, str]]:
    """(kind, name) of every filter and diff driver the repository's own config defines,
    including drivers in files it includes under any condition: an includeIf that is false
    now (onbranch:, gitdir:) can turn true after a checkout. The operator's global and system
    drivers (git-lfs, say) are trusted and not listed. More than MAX_INCLUDED_FILES files is
    refused rather than read in part, since git reads them all."""
    found: set[tuple[str, str]] = set()
    queue = _repo_config_files(repo)
    # A file is read once per directory it is opened from: its relative includes resolve
    # from there, so the same file reached through a symlinked directory can lead elsewhere.
    seen: set[tuple[Path, Path]] = set()
    while queue:
        path = queue.pop(0)
        try:
            key = (path.resolve(), path.parent.resolve())
        except (OSError, RuntimeError):  # a symlink loop: git can't read it either
            continue
        if key in seen or not key[0].is_file():
            continue
        if len(seen) >= MAX_INCLUDED_FILES:
            raise UntrustedRepoError(f"the repository's config includes more than "
                                     f"{MAX_INCLUDED_FILES} files; refusing to run git on it")
        seen.add(key)
        for key, value in _read_config(["--file", str(path), "--no-includes"], repo):
            match = _DRIVER_KEY.fullmatch(key)
            if match:
                found.add((match[1], match[2]))
            elif key == "include.path" or (key.startswith("includeif.")
                                           and key.endswith(".path")):
                target = _include_target(value, path)
                if target is not None:
                    queue.append(target)
    return found


def _driver_overrides(repo: Path | None) -> list[tuple[str, str]]:
    """Command-scope config that disarms the repository's own drivers. An empty filter
    command is skipped (and `required=false` keeps git from failing on that); an empty
    textconv would be run and fail, so textconv becomes `cat`, which passes the content
    through, uncached. A diff driver's `command` runs only for `git diff` or `--ext-diff`, which
    neither Unvarnish nor gitleaks uses."""
    if repo is None:
        return []
    drivers = repo_drivers(repo)
    if len(drivers) > MAX_REPO_DRIVERS:
        raise UntrustedRepoError(f"the repository's config defines {len(drivers)} filter and "
                                 f"diff drivers (more than {MAX_REPO_DRIVERS}); refusing to run "
                                 "git on it")
    pairs: list[tuple[str, str]] = []
    for kind, name in sorted(drivers):
        if kind == "filter":
            pairs += [(f"filter.{name}.{var}", "") for var in ("smudge", "clean", "process")]
            pairs.append((f"filter.{name}.required", "false"))
        else:
            # no textconv cache either: it would write notes refs into the repo it reads
            pairs += [(f"diff.{name}.textconv", "cat"), (f"diff.{name}.cachetextconv", "false")]
    return pairs


def git_env(repo: Path | None = None) -> dict[str, str]:
    """The environment for every git call: an unattended run must fail fast, never prompt,
    and never run code from the repository it reads (hooks, fsmonitor, ext:: transports,
    and, given the repository, the filter and textconv drivers its own config defines).
    The overrides live only in the child's environment, so the operator's own git is
    untouched.

    The user's own SSH and credential setup is kept: BatchMode is appended to their
    GIT_SSH_COMMAND or core.sshCommand, GIT_SSH (a program, no options) is left alone, and a
    GIT_ASKPASS helper they set (a non-interactive token helper in CI) still runs."""
    return _env(_driver_overrides(repo))


def _env(drivers: list[tuple[str, str]]) -> dict[str, str]:
    env = {**os.environ, **GIT_ENV}
    _with_config(env, _untrusted_repo_config() + drivers)
    if os.environ.get("GIT_ASKPASS"):
        env["GIT_ASKPASS"] = os.environ["GIT_ASKPASS"]
    ssh = env.get("GIT_SSH_COMMAND")
    if not ssh and env.get("GIT_SSH"):
        return env
    if not ssh:
        key = tuple(os.environ.get(k) for k in ("HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                                "GIT_CONFIG_NOSYSTEM", "XDG_CONFIG_HOME"))
        ssh = _core_ssh_command(key) or "ssh"
    if "BatchMode" not in ssh:
        ssh = f"{ssh} {BATCH_MODE}"
    env["GIT_SSH_COMMAND"] = ssh
    return env


def _safe_args() -> list[str]:
    """The untrusted-repo settings again as -c, for Unvarnish's own git calls: -c outranks a
    `-c` the operator's environment carries, and git before 2.31 ignores GIT_CONFIG_COUNT."""
    return [arg for key, value in _untrusted_repo_config() for arg in ("-c", f"{key}={value}")]


def _command(args: Sequence[str], cwd: Path) -> tuple[list[str], dict[str, str]]:
    """argv and environment for one of Unvarnish's own git calls in cwd. The repository's
    drivers are read afresh for each call: a checkout can change which includes apply."""
    drivers = _driver_overrides(cwd)
    # also as -c, like _safe_args(); a name with "=" can't be written as -c, and the
    # environment entry still covers it
    args_c = [arg for key, value in drivers if "=" not in key for arg in ("-c", f"{key}={value}")]
    return ["git", *GIT_BASE_ARGS, *_safe_args(), *args_c, *args], _env(drivers)


def git(args: Sequence[str], cwd: Path, check: bool = True) -> str:
    argv, env = _command(args, cwd)
    proc = subprocess.run(
        argv, cwd=cwd, text=True, capture_output=True, encoding="utf-8", errors="replace",
        env=env,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def git_lines(args: Sequence[str], cwd: Path) -> Iterator[str]:
    """Stream stdout lines from a git command without buffering the whole output."""
    argv, env = _command(args, cwd)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as err:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=err,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line.rstrip("\n")
        finally:
            proc.stdout.close()
            rc = proc.wait()
        if rc != 0:
            err.seek(0)
            raise GitError(f"git {' '.join(args)} failed ({rc}): {err.read().strip()}")


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()
