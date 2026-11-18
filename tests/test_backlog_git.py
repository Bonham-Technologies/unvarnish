"""Known-issues burn-down, task 1: ingest and git history."""
from pathlib import PurePosixPath

import pytest


def test_numstat_renames_count_toward_the_new_path():
    from unvarnish.phases.git import parse_log, rename_target

    assert rename_target("src/{old.py => new.py}") == "src/new.py"
    assert rename_target("{a => b}/x.py") == "b/x.py"
    assert rename_target("src/{ => sub}/x.py") == "src/sub/x.py"
    assert rename_target("old.py => new.py") == "new.py"
    assert rename_target("plain.py") == "plain.py"
    raw = ("\x1eabc\x1fA\x1fa@x.io\x1f2026-01-01T00:00:00+00:00\x1fmsg\x1d\n"
           "3\t1\tsrc/{old.py => new.py}\n")
    assert parse_log(raw)[0].files == [("src/new.py", 4)]


def test_a_git_log_failure_is_not_reported_as_no_commits(tmp_path, monkeypatch):
    import unvarnish.phases.git as gitphase
    from unvarnish.util.gitcmd import GitError

    (tmp_path / ".git").mkdir()

    def boom(args, cwd, check=True):
        raise GitError("git log failed (128): fatal: bad object refs/remotes/origin/x")

    monkeypatch.setattr(gitphase, "git", boom)

    class Ctx:
        source_root, tool = tmp_path, "t"

    stats = gitphase.GitPhase()._compute(Ctx(), 2000)
    assert not stats.available and "no commits" not in stats.reason
    assert "bad object" in stats.reason

    def empty(args, cwd, check=True):
        raise GitError("git log failed (128): fatal: your current branch 'main' does not "
                       "have any commits yet")

    monkeypatch.setattr(gitphase, "git", empty)
    assert gitphase.GitPhase()._compute(Ctx(), 2000).reason == "repository has no commits"


def test_nested_gitignore_files_apply_below_their_directory(tmp_path):
    from unvarnish.analysis.languages import Excluder

    (tmp_path / ".gitignore").write_text("*.log\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / ".gitignore").write_text("generated/\n*.tmp\n")
    ex = Excluder(tmp_path)
    assert ex.reason(PurePosixPath("web/x.tmp")) == "gitignore"
    assert ex.reason(PurePosixPath("web/generated/a.js")) == "gitignore"
    assert ex.reason(PurePosixPath("x.tmp")) is None  # the nested rule stays in web/
    assert ex.reason(PurePosixPath("web/a.log")) == "gitignore"  # root rules still apply


def test_git_output_is_decoded_as_utf8(tmp_path, monkeypatch):
    import subprocess

    import unvarnish.util.gitcmd as gitcmd

    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gitcmd.subprocess, "run", fake_run)
    gitcmd.git(["status"], cwd=tmp_path)
    assert seen.get("encoding") == "utf-8"


@pytest.mark.parametrize("trailer,ai", [
    ("Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", True),
    ("Co-Authored-By: <noreply@anthropic.com>", True),            # email-only
    ("Co-Authored-By: Devin Smith <devin.smith@acme.com>", False),  # a person called Devin
    ("Co-Authored-By: devin-ai-integration[bot] <158243242+devin-ai-integration[bot]@users"
     ".noreply.github.com>", True),
    ("Co-Authored-By: Cline Dupont <cline@acme.fr>", False),
    ("Co-Authored-By: Copilot <copilot@github.com>", True),
])
def test_ai_coauthor_trailers(trailer, ai):
    from unvarnish.phases.git import ai_coauthors

    assert bool(ai_coauthors(f"Fix it\n\n{trailer}\n")) is ai


def test_ai_coauthor_label_uses_the_email_when_there_is_no_name():
    from unvarnish.phases.git import ai_coauthors

    assert ai_coauthors("x\n\nCo-Authored-By: <noreply@anthropic.com>\n") == {
        "noreply@anthropic.com"}
