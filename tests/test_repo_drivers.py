"""UNVAR-26: a vetted repo's own filter and diff drivers never run on the consultant's
machine, whether git runs them for Unvarnish (the ingest checkout) or for gitleaks (its
history scan keeps textconv on)."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from tests.conftest import _commit, _git
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners.gitleaks import run_gitleaks
from unvarnish.scanners.secrets import SecretsScanner
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.util.gitcmd import MAX_INCLUDED_FILES, GitError, git, git_env, repo_drivers


def _touch(marker: Path, then: str) -> str:
    return f"sh -c 'touch {marker}; {then}'"


def _driver_repo(root: Path, markers: Path) -> Path:
    """main and feature branches with .txt history. The repo's own config names a smudge
    and clean filter (applied to every path by .git/info/attributes, nothing committed), and
    a textconv driver for the committed `*.txt diff=conv` that is defined only in a file
    included when HEAD is on feature."""
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".gitattributes").write_text("*.txt diff=conv\n")
    (root / "notes.txt").write_text("one\n")
    _commit(root, "init", "Alice", "alice@example.com", "2026-01-01T00:00:00Z")
    (root / "notes.txt").write_text("two\n")
    _commit(root, "edit", "Alice", "alice@example.com", "2026-01-02T00:00:00Z")
    _git(root, "checkout", "-q", "-b", "feature")
    (root / "planted.txt").write_text("only on feature\n")
    _commit(root, "plant", "Alice", "alice@example.com", "2026-01-03T00:00:00Z")
    _git(root, "checkout", "-q", "main")

    (root / ".git" / "info").mkdir(exist_ok=True)
    (root / ".git" / "info" / "attributes").write_text("* filter=evil\n")
    _git(root, "config", "filter.evil.smudge", _touch(markers / "SMUDGE_RAN", "cat"))
    _git(root, "config", "filter.evil.clean", _touch(markers / "CLEAN_RAN", "cat"))
    _git(root, "config", "filter.evil.required", "true")
    (root / ".git" / "conv.inc").write_text(
        f"[diff \"conv\"]\n\ttextconv = {_touch(markers / 'TEXTCONV_RAN', 'cat \"$0\"')}\n")
    _git(root, "config", "includeIf.onbranch:feature.path", "conv.inc")
    return root


@pytest.fixture
def fake_gitleaks(tmp_path: Path, monkeypatch) -> Path:
    """A gitleaks that, like the real one, runs `git log -p` over the repo's history.
    Returns the file it touches once that log succeeded."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    proof = tmp_path / "gitleaks-read-history"
    script = bin_dir / "gitleaks"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = git ]; then\n'
        '  git -C "$2" log -p -U0 --full-history --all >/dev/null || exit 1\n'
        f"  touch '{proof}'\n"
        "fi\n"
        "echo '[]'\n"
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("UNVARNISH_DISABLE_GITLEAKS", raising=False)
    return proof


def test_add_repo_branch_and_scan_never_run_the_repos_drivers(tmp_path: Path, fake_gitleaks):
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _driver_repo(tmp_path / "victim", markers)
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")

    meta = ingest_tool(eng, "victim", str(repo), "repo", branch="feature")
    assert meta.branch == "feature"
    source = eng.tool_paths("victim").source
    assert (source / "planted.txt").read_text() == "only on feature\n"

    ctx = build_context(eng, "victim")
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert ScanPhase(scanners=[SecretsScanner()]).run(ctx).status == PhaseStatus.ok

    assert fake_gitleaks.exists()  # gitleaks' git log -p ran, and succeeded
    notes = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.notes
    assert not [n for n in notes if "gitleaks" in n and "fail" in n]
    assert sorted(p.name for p in markers.iterdir()) == []


def test_linked_repo_textconv_never_runs_in_the_gitleaks_history_scan(tmp_path: Path,
                                                                      fake_gitleaks):
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _driver_repo(tmp_path / "victim", markers)
    _git(repo, "config", "diff.conv.textconv", _touch(markers / "PLAIN_TEXTCONV_RAN",
                                                      'cat "$0"'))
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")
    ingest_tool(eng, "victim", str(repo), "link")

    tree, history, note = run_gitleaks(repo, history=True)
    assert note is None and fake_gitleaks.exists()
    assert sorted(p.name for p in markers.iterdir()) == []


def _pairs(env: dict[str, str]) -> dict[str, str]:
    return {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(int(env["GIT_CONFIG_COUNT"]))}


def test_drivers_behind_a_conditional_include_are_neutralised(tmp_path: Path, monkeypatch):
    """A name reached only through an includeIf whose condition is false right now (and a
    plain include nested inside it) is still overridden: the condition can turn true
    later, after a checkout moves HEAD."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".git" / "hidden.inc").write_text(
        "[filter \"hidden\"]\n\tsmudge = evil\n[include]\n\tpath = deeper.inc\n")
    (repo / ".git" / "deeper.inc").write_text("[diff \"deep.er\"]\n\ttextconv = evil\n")
    _git(repo, "config", "includeIf.gitdir:/nowhere/at/all/.path", "hidden.inc")
    # the operator's own drivers (git-lfs, say) are trusted and left alone
    global_cfg = tmp_path / "global.gitconfig"
    global_cfg.write_text("[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_cfg))

    pairs = _pairs(git_env(repo))
    assert pairs["filter.hidden.smudge"] == ""
    assert pairs["filter.hidden.clean"] == ""
    assert pairs["filter.hidden.process"] == ""
    assert pairs["filter.hidden.required"] == "false"
    assert pairs["diff.deep.er.textconv"] == "cat"
    assert not any(k.startswith("filter.lfs.") for k in pairs)
    # no repo, no repo drivers; the fixed overrides stay
    assert "core.fsmonitor" in _pairs(git_env())


def _index_digest(gitdir: Path) -> str:
    return hashlib.sha256((gitdir / "index").read_bytes()).hexdigest()


def test_add_repo_of_a_linked_worktree_leaves_the_clients_worktree_alone(tmp_path: Path):
    main = tmp_path / "main"
    main.mkdir()
    _git(main, "init", "-q", "-b", "main")
    (main / "app.py").write_text("x = 1\n")
    _commit(main, "init", "Alice", "alice@example.com", "2026-01-01T00:00:00Z")
    _git(main, "branch", "other")
    worktree = tmp_path / "wt"
    _git(main, "worktree", "add", "-q", "-b", "wtbranch", str(worktree))
    assert (worktree / ".git").is_file()
    wt_gitdir = main / ".git" / "worktrees" / "wt"
    before = _index_digest(wt_gitdir)
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")

    meta = ingest_tool(eng, "victim", str(worktree), "repo", branch="other")
    assert meta.branch == "other"
    assert (eng.tool_paths("victim").source / ".git").is_dir()
    head = subprocess.run(["git", "-C", str(worktree), "rev-parse", "--abbrev-ref", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == "wtbranch"
    assert _index_digest(wt_gitdir) == before

    meta = ingest_tool(eng, "plain", str(worktree), "repo")
    assert meta.branch == "wtbranch"
    assert (eng.tool_paths("plain").source / ".git").is_dir()


def _two_commit_repo(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "f.txt").write_text("one\n")
    _commit(root, "init", "Alice", "alice@example.com", "2026-01-01T00:00:00Z")
    (root / "f.txt").write_text("two\n")
    _commit(root, "edit", "Alice", "alice@example.com", "2026-01-02T00:00:00Z")
    return root


def _driver_script(markers: Path, name: str) -> str:
    """A filter or textconv command that leaves markers/name behind, as an executable file
    (no quoting for git config to strip)."""
    script = markers.parent / f"{name}.sh"
    script.write_text(f'#!/bin/sh\ntouch "{markers / name}"\nif [ -n "$1" ]; then cat "$1"; '
                      "else cat; fi\n")
    script.chmod(0o755)
    return str(script)


def _append_config(repo: Path, text: bytes) -> None:
    with (repo / ".git" / "config").open("ab") as fh:
        fh.write(text)


@pytest.mark.parametrize("name", [b"", b"\xff"], ids=["empty-name", "non-utf8-name"])
def test_drivers_with_unusual_names_are_neutralised(tmp_path: Path, name: bytes):
    """git matches a driver name byte for byte, and `filter=` names the driver called "":
    both must be overridden under exactly that name."""
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _two_commit_repo(tmp_path / "repo")
    smudge = _driver_script(markers, "SMUDGE_RAN").encode()
    textconv = _driver_script(markers, "TEXTCONV_RAN").encode()
    _append_config(repo, b'[filter "' + name + b'"]\n\tsmudge = ' + smudge + b"\n"
                   b'[diff "' + name + b'"]\n\ttextconv = ' + textconv + b"\n")
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "attributes").write_bytes(
        b"* filter=" + name + b" diff=" + name + b"\n")

    (repo / "f.txt").unlink()
    git(["checkout", "--", "f.txt"], cwd=repo)
    subprocess.run(["git", "log", "-p"], cwd=repo, env=git_env(repo), capture_output=True,
                   check=True, timeout=60)
    assert sorted(p.name for p in markers.iterdir()) == []


def test_relative_include_from_a_symlinked_config_resolves_as_git_does(tmp_path: Path):
    """git resolves a relative include against the directory of the config file's path as
    opened (.git/), not of the file a symlink leads to."""
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _two_commit_repo(tmp_path / "repo")
    real = repo / "cfg"
    real.mkdir()
    (repo / ".git" / "config").rename(real / "config")
    (repo / ".git" / "config").symlink_to(Path("..") / "cfg" / "config")
    with (real / "config").open("a") as fh:
        fh.write("[include]\n\tpath = evil.inc\n")
    (real / "evil.inc").write_text("")  # the decoy beside the symlink's target
    (repo / ".git" / "evil.inc").write_text(
        f'[filter "evil"]\n\tsmudge = {_driver_script(markers, "SMUDGE_RAN")}\n')
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "attributes").write_text("* filter=evil\n")

    assert ("filter", "evil") in repo_drivers(repo)
    (repo / "f.txt").unlink()
    git(["checkout", "--", "f.txt"], cwd=repo)
    assert sorted(p.name for p in markers.iterdir()) == []


def test_too_many_included_files_is_refused_not_truncated(tmp_path: Path):
    """git includes every file it is pointed at; stopping the search early would let a
    driver hide behind enough empty includes."""
    repo = _two_commit_repo(tmp_path / "repo")
    lines = []
    for i in range(MAX_INCLUDED_FILES + 5):
        (repo / ".git" / f"{i}.inc").write_text("")
        lines.append(f"\tpath = {i}.inc\n")
    (repo / ".git" / "last.inc").write_text('[filter "evil"]\n\tsmudge = evil\n')
    lines.append("\tpath = last.inc\n")
    with (repo / ".git" / "config").open("a") as fh:
        fh.write("[include]\n" + "".join(lines))

    with pytest.raises(GitError, match="include"):
        git(["rev-parse", "HEAD"], cwd=repo)


def test_one_file_included_from_two_directories_is_followed_from_both(tmp_path: Path):
    """The same file opened as .git/a.inc and as .git/d/a.inc (d a symlink) resolves its own
    relative includes from .git/ and from .git/d/: git reads both."""
    repo = _two_commit_repo(tmp_path / "repo")
    dot_git = repo / ".git"
    (dot_git / "a.inc").write_text("[include]\n\tpath = evil.inc\n")
    (dot_git / "evil.inc").write_text("")
    real_d = tmp_path / "elsewhere"
    real_d.mkdir()
    (real_d / "a.inc").symlink_to(dot_git / "a.inc")
    (real_d / "evil.inc").write_text('[filter "evil"]\n\tsmudge = evil\n')
    (dot_git / "d").symlink_to(real_d)
    with (dot_git / "config").open("a") as fh:
        fh.write("[include]\n\tpath = a.inc\n\tpath = d/a.inc\n")
    assert subprocess.run(["git", "config", "filter.evil.smudge"], cwd=repo,
                          capture_output=True, text=True).stdout.strip() == "evil"

    assert ("filter", "evil") in repo_drivers(repo)


def test_history_scan_writes_no_textconv_cache_into_the_repo(tmp_path: Path):
    """With the repo's own cachetextconv=true, `git log -p` would store notes under
    refs/notes/textconv/ in the repository it reads: for --link, the client's own."""
    repo = _two_commit_repo(tmp_path / "repo")
    _git(repo, "config", "diff.conv.textconv", "false")
    _git(repo, "config", "diff.conv.cachetextconv", "true")
    (repo / ".git" / "info" / "attributes").write_text("* diff=conv\n")

    subprocess.run(["git", "log", "-p"], cwd=repo, env=git_env(repo), capture_output=True,
                   check=True, timeout=60)
    refs = subprocess.run(["git", "for-each-ref", "--format=%(refname)"], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.split()
    assert refs == ["refs/heads/main"]


# ------------------------------------------------- QC: submodules, and the lookup fails closed

def _submodule_repo(tmp_path: Path, markers: Path) -> Path:
    """A superproject with an initialised submodule. The submodule's .gitattributes names a
    filter and a textconv driver, defined only in the submodule's own gitdir config
    (.git/modules/sub/config); the superproject's config asks git to recurse into it."""
    sub = tmp_path / "evilsub"
    sub.mkdir()
    _git(sub, "init", "-q", "-b", "main")
    (sub / ".gitattributes").write_text("*.txt filter=evil diff=conv\n")
    (sub / "s.txt").write_text("A\n")
    _commit(sub, "A", "Alice", "alice@example.com", "2026-01-01T00:00:00Z")
    (sub / "s.txt").write_text("B\n")
    _commit(sub, "B", "Alice", "alice@example.com", "2026-01-02T00:00:00Z")

    sup = tmp_path / "super"
    sup.mkdir()
    _git(sup, "init", "-q", "-b", "main")
    (sup / "app.py").write_text("x = 1\n")
    _commit(sup, "init", "Alice", "alice@example.com", "2026-01-03T00:00:00Z")
    _git(sup, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "sub")
    _git(sup / "sub", "checkout", "-q", "HEAD~1")
    _git(sup, "add", "sub")
    _commit(sup, "sub at A", "Alice", "alice@example.com", "2026-01-04T00:00:00Z")
    _git(sup, "checkout", "-q", "-b", "feature")
    _git(sup / "sub", "checkout", "-q", "main")
    _git(sup, "add", "sub")
    _commit(sup, "sub at B", "Alice", "alice@example.com", "2026-01-05T00:00:00Z")
    _git(sup, "checkout", "-q", "main")
    _git(sup / "sub", "checkout", "-q", "HEAD~1")

    modcfg = sup / ".git" / "modules" / "sub"
    _git(modcfg, "config", "--file", str(modcfg / "config"), "filter.evil.smudge",
         _touch(markers / "SUB_SMUDGE_RAN", "cat"))
    _git(modcfg, "config", "--file", str(modcfg / "config"), "diff.conv.textconv",
         _touch(markers / "SUB_TEXTCONV_RAN", 'cat "$0"'))
    _git(sup, "config", "submodule.recurse", "true")
    _git(sup, "config", "diff.submodule", "diff")
    return sup


def test_a_submodules_own_drivers_never_run(tmp_path: Path, fake_gitleaks):
    markers = tmp_path / "markers"
    markers.mkdir()
    sup = _submodule_repo(tmp_path, markers)
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")

    ingest_tool(eng, "victim", str(sup), "repo", branch="feature")
    assert sorted(p.name for p in markers.iterdir()) == []

    ingest_tool(eng, "linked", str(sup), "link")
    tree, history, note = run_gitleaks(sup, history=True)
    assert note is None and fake_gitleaks.exists()
    assert sorted(p.name for p in markers.iterdir()) == []


def test_a_driver_lookup_that_cannot_finish_refuses_the_git_call(tmp_path: Path,
                                                                 monkeypatch):
    """A config git can't read in time (or at all) must not read as "no drivers": the git
    call that follows has no time limit and would run them."""
    import unvarnish.util.gitcmd as gitcmd

    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _driver_repo(tmp_path / "victim", markers)
    real_run = subprocess.run

    def slow_config(cmd, *args, **kwargs):
        if "config" in cmd and "--file" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout") or 0)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(gitcmd.subprocess, "run", slow_config)
    monkeypatch.delenv("UNVARNISH_DISABLE_GITLEAKS", raising=False)
    with pytest.raises(gitcmd.GitError, match="filter and diff drivers"):
        gitcmd.git(["checkout", "-q", "feature"], cwd=repo)
    tree, history, note = run_gitleaks(repo, history=True, which=lambda t: "/bin/gitleaks",
                                       run=lambda *a, **k: pytest.fail("gitleaks ran"))
    assert note is not None and "not run" in note
    assert sorted(p.name for p in markers.iterdir()) == []


def test_a_refused_repo_says_why_when_it_is_added(tmp_path: Path, monkeypatch):
    import unvarnish.util.gitcmd as gitcmd
    from unvarnish.phases.ingest import IngestError

    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _driver_repo(tmp_path / "victim", markers)
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham")
    monkeypatch.setattr(gitcmd, "MAX_REPO_DRIVERS", 0)
    with pytest.raises(IngestError, match="drivers"):
        ingest_tool(eng, "victim", str(repo), "repo")


def test_gitleaks_log_shows_no_signatures(monkeypatch):
    """log.showSignature in the repo's config would run its gpg.program for gitleaks' own
    `git log`; Unvarnish's calls already pass it as -c."""
    assert _pairs(git_env())["log.showSignature"] == "false"


def test_the_driver_lookup_reads_git_messages_untranslated(tmp_path: Path, monkeypatch):
    """"Not a git repository" is recognised from git's message, which git translates: the
    lookup's children run in the C locale, or a German consultant's URL clone (cwd is not a
    repository) would be refused."""
    import unvarnish.util.gitcmd as gitcmd

    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("LANGUAGE", "de")
    seen: list[dict] = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        if cmd[:1] == ["git"] and ("rev-parse" in cmd or "config" in cmd):
            seen.append(kwargs["env"])
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(gitcmd.subprocess, "run", spy)
    assert gitcmd.repo_drivers(tmp_path) == set()  # not a repository: no drivers, no error
    repo = _two_commit_repo(tmp_path / "repo")
    gitcmd.repo_drivers(repo)
    assert seen and all(env["LC_ALL"] == "C" and env.get("LANGUAGE") == "" for env in seen)
