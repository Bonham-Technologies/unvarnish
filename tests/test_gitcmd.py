import inspect
import re
from pathlib import Path

import pytest

from unvarnish.util.gitcmd import GitError, git, git_lines, is_git_repo


def test_git_returns_stdout(synthetic_repo: Path):
    out = git(["rev-list", "--count", "HEAD"], cwd=synthetic_repo)
    assert out.strip() == "4"


def test_git_raises_on_failure(tmp_path: Path):
    with pytest.raises(GitError):
        git(["rev-parse", "HEAD"], cwd=tmp_path)


def test_git_lines_is_lazy(synthetic_repo: Path):
    it = git_lines(["log", "--format=%H"], cwd=synthetic_repo)
    assert inspect.isgenerator(it)
    first = next(it)
    assert re.fullmatch(r"[0-9a-f]{40}", first)
    assert len(list(it)) == 3


def test_git_lines_raises_after_exhaustion_on_error(tmp_path: Path):
    with pytest.raises(GitError):
        list(git_lines(["log"], cwd=tmp_path))


def test_is_git_repo(synthetic_repo: Path, tmp_path: Path):
    assert is_git_repo(synthetic_repo)
    assert not is_git_repo(tmp_path)


# ------------------------------------------------- UNVAR-15: an ingested repo runs no code

def _hostile_repo(root: Path, markers: Path) -> Path:
    """A repo whose own hooks and config would run commands that write marker files."""
    from tests.conftest import _commit, _git

    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("x = 1\n")
    _commit(root, "init", "Alice", "alice@example.com", "2026-01-01T00:00:00Z")
    _git(root, "checkout", "-q", "-b", "feature")
    (root / "planted.txt").write_text("only on feature\n")
    _commit(root, "plant", "Alice", "alice@example.com", "2026-01-02T00:00:00Z")
    _git(root, "checkout", "-q", "main")
    hook = root / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch '{markers / 'HOOK_RAN'}'\n")
    hook.chmod(0o755)
    _git(root, "config", "core.fsmonitor", f"sh -c 'touch {markers / 'FSMON_RAN'}'")
    _git(root, "config", "core.sshCommand", f"sh -c 'touch {markers / 'SSH_RAN'}'")
    # a work tree elsewhere would make the checkout write the branch's files there
    (markers / "home").mkdir()
    _git(root, "config", "core.worktree", str(markers / "home"))
    return root


def test_ingested_repo_hooks_and_fsmonitor_never_run(tmp_path: Path, monkeypatch):
    from unvarnish.engagement import Engagement
    from unvarnish.phases.base import PhaseStatus, build_context
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.ingest import ingest_tool
    from unvarnish.util.gitcmd import _core_ssh_command, git_env

    _core_ssh_command.cache_clear()
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _hostile_repo(tmp_path / "victim", markers)
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")

    meta = ingest_tool(eng, "victim", str(repo), "repo", branch="feature")
    assert meta.branch == "feature"
    ctx = build_context(eng, "victim")
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert sorted(p.name for p in markers.iterdir()) == ["home"]
    assert not any((markers / "home").iterdir())
    assert (eng.tool_paths("victim").source / "planted.txt").exists()

    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.delenv("GIT_SSH", raising=False)
    monkeypatch.chdir(eng.tool_paths("victim").source)
    _core_ssh_command.cache_clear()  # ingest cached it; read it again from here
    assert "touch" not in git_env()["GIT_SSH_COMMAND"]


def test_git_env_disables_hooks_fsmonitor_and_ext_per_subprocess(monkeypatch):
    from unvarnish.util.gitcmd import git_env

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "user.name")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "Operator")
    env = git_env()
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
             for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert pairs["user.name"] == "Operator"  # the operator's own entries are kept
    assert pairs["core.fsmonitor"] == "false"
    assert pairs["protocol.ext.allow"] == "never"
    hooks = Path(pairs["core.hooksPath"])
    assert hooks.is_dir() and not any(hooks.iterdir())
    # the override lives only in the child's environment, so the operator's hooks still
    # work in their own git sessions
    import os
    assert os.environ["GIT_CONFIG_COUNT"] == "1"


def test_gitleaks_children_get_the_safe_git_environment(tmp_path: Path, monkeypatch):
    import subprocess

    from unvarnish.scanners.gitleaks import run_gitleaks

    monkeypatch.delenv("UNVARNISH_DISABLE_GITLEAKS", raising=False)
    seen: list[dict] = []

    def fake_run(cmd, **kwargs):
        seen.append(kwargs.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0, b"[]", b"")

    run_gitleaks(tmp_path, history=True, which=lambda t: "/bin/gitleaks", run=fake_run)
    assert len(seen) == 2
    for env in seen:
        keys = [env.get(f"GIT_CONFIG_KEY_{i}") for i in range(int(env["GIT_CONFIG_COUNT"]))]
        assert {"core.hooksPath", "core.fsmonitor", "protocol.ext.allow"} <= set(keys)


@pytest.mark.parametrize("count", ["-1", "-3", "abc", ""])
def test_git_env_overrides_survive_a_malformed_config_count(monkeypatch, count):
    from unvarnish.util.gitcmd import git_env

    monkeypatch.setenv("GIT_CONFIG_COUNT", count)
    env = git_env()
    keys = [env.get(f"GIT_CONFIG_KEY_{i}") for i in range(int(env["GIT_CONFIG_COUNT"]))]
    assert {"core.hooksPath", "core.fsmonitor", "protocol.ext.allow"} <= set(keys)


def test_git_ignores_a_hooks_path_passed_down_by_the_operators_environment(tmp_path: Path,
                                                                          monkeypatch):
    """Launched from a git alias or hook, Unvarnish inherits GIT_CONFIG_PARAMETERS, which
    outranks GIT_CONFIG_COUNT; its own calls pass the settings as -c too."""
    import shutil

    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _hostile_repo(tmp_path / "victim", markers)
    copy = tmp_path / "copy"
    shutil.copytree(repo, copy, symlinks=True)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.hooksPath'='{copy / '.git' / 'hooks'}'")
    git(["--work-tree", str(copy), "checkout", "--quiet", "feature"], cwd=copy)
    assert not (markers / "HOOK_RAN").exists()
