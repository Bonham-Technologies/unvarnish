import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import (
    IngestError,
    ingest_tool,
    load_tool_meta,
    resolve_source_root,
)

runner = CliRunner()


def test_ingest_local_repo_copies_history(engagement: Engagement, synthetic_repo: Path):
    meta = ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    paths = engagement.tool_paths("expense-bot")
    assert (paths.source / ".git").is_dir()
    assert (paths.source / "app.py").exists()
    assert meta.origin_kind == "repo"
    assert meta.commit and len(meta.commit) == 40
    assert meta.branch == "main"
    assert engagement.tool_names() == ["expense-bot"]
    assert load_tool_meta(paths) == meta


def test_ingest_repo_requires_git_dir(engagement: Engagement, tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.py").write_text("x = 1\n")
    with pytest.raises(IngestError, match="--files"):
        ingest_tool(engagement, "plain", str(plain), "repo")


def test_ingest_files_copies_tree(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "sub").mkdir(parents=True)
    (pile / "sub" / "b.js").write_text("let x = 1;\n")
    meta = ingest_tool(engagement, "pile", str(pile), "files")
    paths = engagement.tool_paths("pile")
    assert (paths.source / "sub" / "b.js").read_text() == "let x = 1;\n"
    assert meta.commit is None
    assert resolve_source_root(engagement, meta) == paths.source


def test_ingest_files_preserves_symlink(engagement: Engagement, tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret outside\n")
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "real.txt").write_text("inside\n")
    os.symlink("../outside.txt", pile / "link.txt")
    os.symlink("nowhere", pile / "broken.txt")
    ingest_tool(engagement, "pile", str(pile), "files")
    src = engagement.tool_paths("pile").source
    assert (src / "link.txt").is_symlink()
    assert os.readlink(src / "link.txt") == "../outside.txt"
    assert os.path.lexists(src / "broken.txt")
    assert (src / "real.txt").read_text() == "inside\n"


def test_ingest_link_records_path_without_copy(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.go").write_text("package main\n")
    meta = ingest_tool(engagement, "linked", str(pile), "link")
    paths = engagement.tool_paths("linked")
    assert not paths.source.exists()
    assert meta.external is True
    assert resolve_source_root(engagement, meta) == pile.resolve()


def test_ingest_link_inside_engagement_is_relative(engagement: Engagement):
    inside = engagement.root / "dropzone" / "thing"
    inside.mkdir(parents=True)
    (inside / "a.rs").write_text("fn main() {}\n")
    meta = ingest_tool(engagement, "thing", str(inside), "link")
    assert meta.external is False
    assert meta.source_path == "dropzone/thing"
    assert resolve_source_root(engagement, meta) == inside


def test_ingest_refuses_duplicate(engagement: Engagement, synthetic_repo: Path):
    ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    with pytest.raises(IngestError, match="already exists"):
        ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")


def test_cli_add(engagement: Engagement, synthetic_repo: Path):
    result = runner.invoke(
        app, ["add", "expense-bot", "--repo", str(synthetic_repo), "-e", str(engagement.root)]
    )
    assert result.exit_code == 0, result.output
    assert (engagement.tool_paths("expense-bot").source / "app.py").exists()


def test_cli_add_requires_exactly_one_origin(engagement: Engagement, tmp_path: Path):
    result = runner.invoke(app, ["add", "x", "-e", str(engagement.root)])
    assert result.exit_code == 2
    both = runner.invoke(
        app, ["add", "x", "--repo", "a", "--files", str(tmp_path), "-e", str(engagement.root)]
    )
    assert both.exit_code == 2


# --- fixes from the whole-branch review -------------------------------------
from unvarnish.phases.ingest import sanitize_origin  # noqa: E402


def test_sanitize_origin_strips_userinfo_and_local_paths():
    assert sanitize_origin("https://x-access-token:ghp_abc123@github.com/o/r.git", "repo") == (
        "https://github.com/o/r.git"
    )
    assert sanitize_origin("git@github.com:o/r.git", "repo") == "git@github.com:o/r.git"
    assert sanitize_origin("/Users/me/clients/acme/bot", "repo") == "bot"
    assert sanitize_origin("/Users/me/clients/acme/pile", "files") == "pile"


def test_local_origin_not_stored_absolute(engagement: Engagement, synthetic_repo: Path):
    meta = ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    assert not meta.origin.startswith("/")
    assert str(synthetic_repo) not in engagement.tool_paths("expense-bot").meta_file.read_text()


def test_failed_clone_leaves_no_tool_dir_and_hides_credentials(
    engagement: Engagement, synthetic_repo: Path
):
    bad = "https://user:supersecrettoken@127.0.0.1:9/nowhere.git"
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "ghost", bad, "repo")
    assert "supersecrettoken" not in str(exc.value)
    assert not engagement.tool_paths("ghost").root.exists()
    assert "ghost" not in engagement.tool_names()
    # retry with a good origin under the same name succeeds
    ingest_tool(engagement, "ghost", str(synthetic_repo), "repo")
    assert (engagement.tool_paths("ghost").source / "app.py").exists()


def test_ingest_empty_local_repo_raises_ingest_error(engagement: Engagement, tmp_path: Path):
    import subprocess

    repo = tmp_path / "fresh"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    with pytest.raises(IngestError, match="no commits"):
        ingest_tool(engagement, "fresh", str(repo), "repo")
    assert not engagement.tool_paths("fresh").root.exists()


def test_bad_tool_name_rejected_before_touching_disk(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    with pytest.raises(ValueError):
        ingest_tool(engagement, "../escaped", str(pile), "files")
    assert not (engagement.root / "escaped").exists()
    assert not (engagement.tools_dir / "..").resolve().joinpath("escaped").exists()


def _plain_git(cwd: Path, *args: str) -> None:
    import subprocess
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   cwd=cwd, check=True, capture_output=True)


def _repo_with_dependency_dirs(tmp_path: Path) -> Path:
    repo = tmp_path / "jsapp"
    repo.mkdir()
    _plain_git(repo, "init", "-q", "-b", "main")
    (repo / ".gitignore").write_text(".venv/\nnode_modules/\n.env\n__pycache__/\ndist/\n")
    (repo / "app.py").write_text("x = 1\n")
    (repo / "vendor").mkdir()
    (repo / "vendor" / "lib.go").write_text("package lib\n")  # committed: must stay
    (repo / "tests" / "build").mkdir(parents=True)
    (repo / "tests" / "build" / "fixture.py").write_text("y = 2\n")
    _plain_git(repo, "add", "-A")
    _plain_git(repo, "commit", "-q", "-m", "init")
    (repo / ".venv" / "lib").mkdir(parents=True)
    (repo / ".venv" / "lib" / "x.py").write_text("v = 1\n")
    (repo / "node_modules" / "a").mkdir(parents=True)
    (repo / "node_modules" / "a" / "a.js").write_text("let a = 1;\n")
    (repo / "src" / "__pycache__").mkdir(parents=True)
    (repo / "src" / "__pycache__" / "m.pyc").write_bytes(b"\0")
    (repo / "dist").mkdir()
    (repo / "dist" / "bundle.js").write_text("b\n")
    (repo / ".env").write_text("SECRET=1\n")
    (repo / "notes.txt").write_text("untracked, not a dependency dir\n")
    return repo


def test_local_repo_skips_dependency_dirs_keeps_env(engagement: Engagement, tmp_path: Path):
    repo = _repo_with_dependency_dirs(tmp_path)
    meta = ingest_tool(engagement, "jsapp", str(repo), "repo")
    src = engagement.tool_paths("jsapp").source
    for gone in (".venv", "node_modules", "src/__pycache__", "dist"):
        assert not (src / gone).exists(), gone
    assert (src / ".env").read_text() == "SECRET=1\n"  # gitignored, still scanned
    assert (src / "notes.txt").exists() and (src / "app.py").exists()
    assert (src / "vendor" / "lib.go").exists()  # tracked dependency code is still copied
    assert (src / "tests" / "build" / "fixture.py").exists()
    assert (src / ".git").is_dir()
    assert sorted(meta.skipped_at_ingest) == [".venv", "dist", "node_modules", "src/__pycache__"]
    assert load_tool_meta(engagement.tool_paths("jsapp")) == meta


def test_local_repo_branch_checkout_after_skipping(engagement: Engagement, tmp_path: Path):
    repo = _repo_with_dependency_dirs(tmp_path)
    _plain_git(repo, "checkout", "-q", "-b", "other")
    (repo / "other.py").write_text("o = 1\n")
    _plain_git(repo, "add", "other.py")
    _plain_git(repo, "commit", "-q", "-m", "other")
    _plain_git(repo, "checkout", "-q", "main")
    meta = ingest_tool(engagement, "jsapp", str(repo), "repo", branch="other")
    src = engagement.tool_paths("jsapp").source
    assert meta.branch == "other" and (src / "other.py").exists()
    assert not (src / "node_modules").exists()


def test_dependency_dir_rule_matches_inventory():
    from pathlib import PurePosixPath

    from unvarnish.analysis.languages import is_dependency_or_build_dir
    yes = ["node_modules", "a/.venv", "venv", "x/__pycache__", "dist", "dist-prod", "htmlcov"]
    no = ["src", "tests/build", "bin", "app"]
    assert all(is_dependency_or_build_dir(PurePosixPath(p)) for p in yes)
    assert not any(is_dependency_or_build_dir(PurePosixPath(p)) for p in no)


def test_local_repo_keeps_committed_dependency_dirs_inside_a_submodule(
        engagement: Engagement, tmp_path: Path):
    # ls-files lists a submodule only as its gitlink, so a vendor/ the submodule commits
    # would look untracked; it must still be copied (and its untracked node_modules too).
    sub = tmp_path / "lib"
    sub.mkdir()
    _plain_git(sub, "init", "-q", "-b", "main")
    (sub / "vendor").mkdir()
    (sub / "vendor" / "dep.go").write_text("package dep\n")
    _plain_git(sub, "add", "-A")
    _plain_git(sub, "commit", "-q", "-m", "lib")
    sup = _repo_with_dependency_dirs(tmp_path)
    _plain_git(sup, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub),
               "libs/lib")
    _plain_git(sup, "commit", "-q", "-m", "add lib")
    meta = ingest_tool(engagement, "jsapp", str(sup), "repo")
    src = engagement.tool_paths("jsapp").source
    assert (src / "libs" / "lib" / "vendor" / "dep.go").exists()
    assert not (src / "node_modules").exists()  # the superproject's own still skipped
    assert not any(p.startswith("libs/") for p in meta.skipped_at_ingest)


def test_local_repo_copies_everything_when_the_index_cannot_be_read(
        engagement: Engagement, tmp_path: Path, monkeypatch):
    import unvarnish.phases.ingest as ingest_mod
    from unvarnish.util.gitcmd import GitError

    real_git = ingest_mod.git

    def flaky_git(args, cwd, check=True):
        if args[:1] == ["ls-files"]:
            raise GitError("dubious ownership")
        return real_git(args, cwd=cwd, check=check)

    monkeypatch.setattr(ingest_mod, "git", flaky_git)
    repo = _repo_with_dependency_dirs(tmp_path)
    meta = ingest_tool(engagement, "jsapp", str(repo), "repo")
    src = engagement.tool_paths("jsapp").source
    assert (src / "node_modules" / "a" / "a.js").exists()
    assert meta.skipped_at_ingest == []


def test_linked_worktree_skips_dependency_dirs_and_stays_clean(
        engagement: Engagement, tmp_path: Path):
    import subprocess
    main = _repo_with_dependency_dirs(tmp_path)
    wt = tmp_path / "wt"
    _plain_git(main, "worktree", "add", "-q", "-b", "feat", str(wt))
    (wt / "node_modules" / "x").mkdir(parents=True)
    (wt / "node_modules" / "x" / "i.js").write_text("1\n")
    (wt / "real").mkdir()
    (wt / "real" / "f.txt").write_text("1\n")
    (wt / "build").symlink_to("real")  # an untracked symlink named like build output
    meta = ingest_tool(engagement, "jsapp", str(wt), "repo", branch="main")
    src = engagement.tool_paths("jsapp").source
    assert (src / ".git").is_dir() and meta.branch == "main"
    assert not (src / "node_modules").exists() and (src / "vendor" / "lib.go").exists()
    assert meta.skipped_at_ingest == ["build", "node_modules"]
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=src,
                            capture_output=True, text=True, check=True).stdout
    assert status == ""


def test_ingest_repo_missing_path_says_it_does_not_exist(engagement: Engagement, tmp_path: Path):
    missing = tmp_path / "nope"
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "nope", str(missing), "repo")
    assert str(exc.value) == f"{missing.resolve()} does not exist"
    assert "--files" not in str(exc.value)


def test_ingest_repo_relative_missing_path_names_the_resolved_path(
    engagement: Engagement, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "nope", "../nope", "repo")
    assert str(exc.value) == f"{(tmp_path.parent / 'nope').resolve()} does not exist"


def test_ingest_repo_folder_without_git_points_to_files(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "pile", str(pile), "repo")
    assert str(exc.value) == "pile has no .git directory; use --files for a loose file pile"
    assert not (engagement.root / "tools" / "pile").exists()


def test_ingest_repo_file_path_is_not_a_folder(engagement: Engagement, tmp_path: Path):
    afile = tmp_path / "a.py"
    afile.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "a", str(afile), "repo")
    assert str(exc.value) == f"{afile.resolve()} is not a folder"


def test_cli_add_missing_repo_prints_the_whole_path_on_one_line(
    engagement: Engagement, tmp_path: Path
):
    missing = tmp_path / ("a-long-folder-name-" * 6) / "nope"
    result = runner.invoke(
        app, ["add", "nope", "--repo", str(missing), "-e", str(engagement.root)]
    )
    assert result.exit_code == 2
    assert f"error: {missing.resolve()} does not exist" in result.output


@pytest.mark.parametrize("kind", ["files", "link"])
def test_ingest_files_and_link_missing_path_says_it_does_not_exist(
    engagement: Engagement, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
):
    # UNVAR-71: these said "<last segment> is not a directory" for a path that isn't there.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "nope", "../nope", kind)
    assert str(exc.value) == f"{(tmp_path.parent / 'nope').resolve()} does not exist"
    assert not (engagement.root / "tools" / "nope").exists()


@pytest.mark.parametrize("kind", ["files", "link"])
def test_ingest_files_and_link_file_path_is_not_a_folder(
    engagement: Engagement, tmp_path: Path, kind: str
):
    afile = tmp_path / "a.py"
    afile.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(IngestError) as exc:
        ingest_tool(engagement, "a", str(afile), kind)
    assert str(exc.value) == f"{afile.resolve()} is not a folder"


@pytest.mark.parametrize("flags", [["--files"], ["--link", "--files"]])
def test_cli_add_missing_files_prints_the_whole_path_on_one_line(
    engagement: Engagement, tmp_path: Path, flags: list[str]
):
    missing = tmp_path / ("a-long-folder-name-" * 6) / "nope"
    result = runner.invoke(
        app, ["add", "nope", *flags, str(missing), "-e", str(engagement.root)]
    )
    assert result.exit_code == 2
    assert f"error: {missing.resolve()} does not exist" in result.output


# --- `add --link PATH` (UNVAR-86) ---------------------------------------------------------


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_cli_add_link_with_a_path_names_the_right_form(engagement: Engagement, tmp_path: Path):
    result = runner.invoke(app, ["add", "z", "--link", str(tmp_path), "-e",
                                 str(engagement.root)])
    assert result.exit_code == 2
    out = _flat(result.output)
    assert "unexpected extra argument" not in out.lower()
    assert "add z --link --repo PATH" in out
    assert "--files" in out
    assert not engagement.tool_names()


def test_cli_add_stray_argument_without_link_points_at_repo_or_files(
        engagement: Engagement, tmp_path: Path):
    result = runner.invoke(app, ["add", "z", str(tmp_path), "-e", str(engagement.root)])
    assert result.exit_code == 2
    out = _flat(result.output)
    assert str(tmp_path) in out
    assert "--repo" in out and "--files" in out


def test_cli_add_stray_argument_after_a_source_is_named_as_such(engagement: Engagement,
                                                                 tmp_path: Path):
    """--link used correctly: the stray argument is the problem, not --link."""
    result = runner.invoke(app, ["add", "z", "--link", "--repo", str(tmp_path), "extra",
                                 "-e", str(engagement.root)])
    assert result.exit_code == 2
    out = _flat(result.output)
    assert "unexpected argument extra" in out
    assert "--link takes no path" not in out and "name the source" not in out
    assert not engagement.tool_names()
