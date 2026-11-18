from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase, parse_log
from unvarnish.phases.ingest import ingest_tool
from unvarnish.schemas.git import GitStats


def _run(eng: Engagement, name: str) -> GitStats:
    ctx = build_context(eng, name)
    result = GitPhase().run(ctx)
    assert result.status == PhaseStatus.ok, result.message
    return read_artifact(ctx.paths.git, GitStats).data


def test_git_stats_on_synthetic_repo(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    assert stats.available is True
    assert stats.commit_count == 4
    assert stats.active_days == 4
    assert stats.first_commit is not None and stats.first_commit.year == 2026
    assert [a.name for a in stats.authors] == ["Alice", "Bob"]
    assert stats.authors[0].commits == 3
    assert stats.top_author_share is not None and stats.top_author_share > 0.9
    assert stats.bus_factor == 1


def test_large_commits_and_velocity(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    assert stats.large_commit_threshold == 2000
    assert len(stats.large_commits) == 1
    assert stats.large_commits[0].message_head == "generate processing"
    assert stats.large_commits[0].lines_added > 3000
    assert len(stats.weekly_velocity) >= 2
    assert sum(b.commits for b in stats.weekly_velocity) == 4


def test_churn_and_ai_fingerprints(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    churn = {c.path: c for c in stats.churn_hotspots}
    assert churn["app.py"].changes == 2
    assert churn["README.md"].changes == 2
    assert stats.ai_fingerprints.files == ["CLAUDE.md"]
    assert stats.ai_fingerprints.coauthor_trailers == {"Claude": 1}


def test_git_phase_no_repo(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    stats = _run(engagement, "pile")
    assert stats.available is False
    assert stats.reason and ".git" in stats.reason
    assert stats.commit_count == 0


def test_git_phase_empty_repo(engagement: Engagement, tmp_path: Path):
    """A repo with .git but no commits. ingest_tool needs HEAD, so stage it by hand."""
    import shutil
    import subprocess
    from datetime import UTC, datetime

    import yaml

    from unvarnish.schemas.tool import ToolMeta

    repo = tmp_path / "fresh"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    paths = engagement.tool_paths("fresh")
    paths.ensure_dirs()
    shutil.copytree(repo, paths.source, symlinks=True)
    meta = ToolMeta(name="fresh", origin_kind="repo", origin=str(repo),
                    ingested_at=datetime.now(UTC))
    paths.meta_file.write_text(yaml.safe_dump(meta.model_dump(mode="json")))
    engagement.register_tool("fresh")
    stats = _run(engagement, "fresh")
    assert stats.available is False
    assert stats.reason and "no commits" in stats.reason


def test_parse_log_handles_multiline_bodies_and_binary_numstat():
    raw = (
        "\x1e" + "a" * 40 + "\x1fAlice\x1falice@example.com\x1f2026-01-05T10:00:00+00:00\x1f"
        + "subject line\n\nbody with\ttab\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n\x1d\n"
        + "3\t1\tapp.py\n-\t-\timg.png\n"
        + "\x1e" + "b" * 40
        + "\x1fBob\x1fbob@example.com\x1f2026-02-01T10:00:00+00:00\x1fsecond\n\x1d\n"
        + "1\t0\tREADME.md\n"
    )
    commits = parse_log(raw)
    assert len(commits) == 2
    assert commits[0].added == 3 and commits[0].deleted == 1
    assert [f for f, _ in commits[0].files] == ["app.py", "img.png"]
    assert "Co-Authored-By" in commits[0].body
    assert commits[1].author == "Bob"


# --- fixes from the whole-branch review -------------------------------------
from tests.conftest import _commit, _git  # noqa: E402


def test_same_person_with_two_emails_is_one_author(engagement: Engagement, tmp_path: Path):
    repo = tmp_path / "two-emails"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("x = 1\n")
    _commit(repo, "one", "Alice Smith", "alice@work.example", "2026-01-05T10:00:00+00:00")
    (repo / "a.py").write_text("x = 2\n" * 50)
    _commit(repo, "two", "Alice Smith", "123+alice@users.noreply.github.com",
            "2026-01-06T10:00:00+00:00")
    (repo / "b.py").write_text("y = 1\n")
    _commit(repo, "three", "Bob", "bob@example.com", "2026-01-07T10:00:00+00:00")
    ingest_tool(engagement, "two", str(repo), "repo")
    stats = _run(engagement, "two")
    assert [a.name for a in stats.authors] == ["Alice Smith", "Bob"]
    assert stats.authors[0].commits == 2
    assert stats.bus_factor == 1


def test_bots_are_excluded_from_author_shares_and_trailers_count_commits(
    engagement: Engagement, tmp_path: Path
):
    repo = tmp_path / "bots"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("x = 1\n")
    _commit(repo, "human\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"
            "Co-Authored-By: Claude <noreply@anthropic.com>\n",
            "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")
    (repo / "deps.lock").write_text("v" * 5000 + "\n")
    _commit(repo, "bump deps", "dependabot[bot]",
            "49699333+dependabot[bot]@users.noreply.github.com", "2026-01-06T10:00:00+00:00")
    (repo / "b.py").write_text("y = 1\n")
    _commit(repo, "more", "Alice", "alice@example.com", "2026-01-07T10:00:00+00:00")
    ingest_tool(engagement, "bots", str(repo), "repo")
    stats = _run(engagement, "bots")
    assert [a.name for a in stats.authors] == ["Alice"]
    assert [b.name for b in stats.bots] == ["dependabot[bot]"]
    assert stats.top_author_share == 1.0 and stats.bus_factor == 1
    assert stats.ai_fingerprints.coauthor_trailers == {"Claude": 1}
