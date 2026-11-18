from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

import yaml

from unvarnish.analysis.languages import is_dependency_or_build_dir
from unvarnish.engagement import TOOL_NAME_RE, Engagement, ToolPaths
from unvarnish.schemas.tool import OriginKind, ToolMeta
from unvarnish.util.gitcmd import GitError, UntrustedRepoError, git, is_git_repo


class IngestError(Exception):
    pass


def _is_url(origin: str) -> bool:
    return "://" in origin or origin.startswith("git@")


def sanitize_origin(origin: str, kind: OriginKind) -> str:
    """What gets stored and shown: no credentials, no consultant filesystem paths."""
    if "://" in origin:
        parts = urlsplit(origin)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    if origin.startswith("git@"):
        return origin
    return Path(origin).name or origin


def _scrub(text: str, origin: str, display: str) -> str:
    text = text.replace(origin, display)
    if "://" in origin:
        parts = urlsplit(origin)
        if parts.password:
            text = text.replace(parts.password, "***")
        if parts.username:
            text = text.replace(f"{parts.username}:", "***:")
    return text


def ingest_tool(
    eng: Engagement,
    name: str,
    origin: str,
    kind: OriginKind,
    branch: str | None = None,
) -> ToolMeta:
    if not TOOL_NAME_RE.match(name):
        raise ValueError(
            f"tool name {name!r} must match {TOOL_NAME_RE.pattern} (lowercase, digits, - and _)"
        )
    paths = eng.tool_paths(name)
    if paths.root.exists() and any(paths.root.iterdir()):
        raise IngestError(f"tool {name!r} already exists at {paths.root}")

    display = sanitize_origin(origin, kind)
    staging_root = eng.tools_dir / f".staging-{name}"
    shutil.rmtree(staging_root, ignore_errors=True)
    staging = ToolPaths(staging_root)
    staging.ensure_dirs()
    meta = ToolMeta(name=name, origin_kind=kind, origin=display, ingested_at=datetime.now(UTC))

    try:
        if kind == "repo":
            try:
                _ingest_repo(origin, display, branch, staging, meta)
            except UntrustedRepoError as exc:  # say why, not what failed as a result
                raise IngestError(f"{display}: {_scrub(str(exc), origin, display)}") from exc
        elif kind == "files":
            src = Path(origin)
            if not src.is_dir():
                raise IngestError(f"{display} is not a directory")
            shutil.copytree(src, staging.source, symlinks=True)
        elif kind == "link":
            target = Path(origin).resolve()
            if not target.is_dir():
                raise IngestError(f"{display} is not a directory")
            rel = os.path.relpath(target, eng.root)
            if rel.startswith(".."):
                meta.source_path = str(target)
                meta.external = True
            else:
                meta.source_path = Path(rel).as_posix()
                meta.external = False
        staging.meta_file.write_text(
            yaml.safe_dump(meta.model_dump(mode="json"), sort_keys=False)
        , encoding="utf-8")
    except BaseException:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise

    if paths.root.exists():
        paths.root.rmdir()  # empty, checked above
    staging_root.rename(paths.root)
    eng.register_tool(name)
    return meta


def _ingest_repo(
    origin: str, display: str, branch: str | None, staging: ToolPaths, meta: ToolMeta
) -> None:
    if _is_url(origin):
        args = ["clone", "--quiet"]
        if branch:
            args += ["--branch", branch]
        try:
            git([*args, origin, str(staging.source)], cwd=staging.root)
        except UntrustedRepoError:
            raise
        except GitError as exc:
            detail = _scrub(str(exc), origin, display)
            raise IngestError(f"clone of {display} failed: {detail}") from exc
    else:
        src = Path(origin)
        if not src.exists():
            raise IngestError(f"{src.resolve()} does not exist")
        if not src.is_dir():
            raise IngestError(f"{src.resolve()} is not a folder")
        if not is_git_repo(src):
            raise IngestError(
                f"{display} has no .git directory; use --files for a loose file pile"
            )
        meta.skipped_at_ingest = _copy_local_repo(src, display, staging.source)
        if branch:
            try:
                # --work-tree outranks a core.worktree in the copied config, which would
                # otherwise make the checkout write the branch's files anywhere on disk.
                git(["--work-tree", str(staging.source), "checkout", "--quiet", branch],
                    cwd=staging.source)
            except UntrustedRepoError:
                raise
            except GitError as exc:
                raise IngestError(_scrub(str(exc), origin, display)) from exc
    try:
        meta.commit = git(["rev-parse", "HEAD"], cwd=staging.source).strip()
        meta.branch = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=staging.source).strip()
    except UntrustedRepoError:
        raise
    except GitError as exc:
        raise IngestError(f"{display} has no commits (HEAD is unborn)") from exc


def _tracked_dirs(src: Path) -> tuple[set[str], set[str]] | None:
    """Every directory (posix, relative to `src`) that holds a tracked file or submodule, and
    the submodule paths themselves, or None when the index can't be read (then nothing is
    skipped). The index lists a submodule only as its gitlink, so what the submodule tracks
    is unknown here and nothing under one is skipped."""
    try:
        out = git(["ls-files", "-s", "-z"], cwd=src)
    except UntrustedRepoError:
        raise
    except GitError:
        return None
    dirs: set[str] = set()
    gitlinks: set[str] = set()
    for entry in filter(None, out.split("\0")):
        info, _, path = entry.partition("\t")
        if info.startswith("160000 "):
            gitlinks.add(path)
        parts = PurePosixPath(path).parts
        dirs.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    return dirs, gitlinks


def _dependency_dir_filter(src: Path, skipped: list[str]) -> Callable[[str, list[str]], set[str]]:
    """A copytree `ignore` that leaves out the untracked directories the inventory would
    exclude anyway as dependencies or build output (.venv, node_modules, dist ...), recording
    each in `skipped`. Tracked ones (a committed vendor/) and every other gitignored file
    (.env) are still copied, so scanners and the vendored-code finding see them (UNVAR-8)."""
    top = src.resolve()
    index = _tracked_dirs(src)
    tracked, gitlinks = index if index is not None else (set(), set())

    def ignore(directory: str, names: list[str]) -> set[str]:
        if index is None:
            return set()
        rel = Path(directory).resolve().relative_to(top)
        if rel.parts[:1] == (".git",) or any(
                "/".join(rel.parts[:i]) in gitlinks for i in range(1, len(rel.parts) + 1)):
            return set()
        out = set()
        for name in names:
            relpath = PurePosixPath(rel.as_posix(), name) if rel.parts else PurePosixPath(name)
            if (name != ".git" and relpath.as_posix() not in tracked
                    and (Path(directory) / name).is_dir()
                    and is_dependency_or_build_dir(relpath)):
                out.add(name)
                skipped.append(relpath.as_posix())
        return out

    return ignore


def _copy_local_repo(src: Path, display: str, dest: Path) -> list[str]:
    """Copy a local repo so that every later git call works on Unvarnish's own copy, and
    return the dependency and build directories it left out (see _dependency_dir_filter).

    A `.git` that is a file (a linked worktree, or a submodule checkout) or a symlink points
    at the client's real git directory; copied as is, the copy's checkout would move the
    HEAD and index of the client's own worktree. Such a repo is copied with its git
    directory made real: the shared directory, then the worktree's own HEAD and index."""
    skipped: list[str] = []
    skip_deps = _dependency_dir_filter(src, skipped)
    dot_git = src / ".git"
    if dot_git.is_dir() and not dot_git.is_symlink():
        shutil.copytree(src, dest, symlinks=True, ignore=skip_deps)
    else:
        try:
            out = git(["rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"],
                      cwd=src).splitlines()
            git_dir, common_dir = Path(out[0]), Path(out[1])
        except UntrustedRepoError:
            raise
        except (GitError, IndexError) as exc:
            raise IngestError(f"{display}: its .git points at a git directory that can't be "
                              "read") from exc
        top = src.resolve()
        shutil.copytree(src, dest, symlinks=True,
                        ignore=lambda d, names: (skip_deps(d, names)
                                                 | ({".git"} if Path(d).resolve() == top
                                                    else set())))
        linked = git_dir.resolve() != common_dir.resolve()
        shutil.copytree(common_dir, dest / ".git", symlinks=True,
                        ignore=lambda d, names: (["worktrees"] if linked and Path(d) == common_dir
                                                 else []))
        for name in ("HEAD", "index") if linked else ():
            if (git_dir / name).is_file():
                shutil.copy2(git_dir / name, dest / ".git" / name)
    # A copied core.worktree (a submodule's gitdir always has one) points at the client's
    # files; the copy's work tree is the copy itself. Only .git/config is cleaned: one set in
    # config.worktree or an included file stays, and the checkout's --work-tree outranks it.
    git(["config", "--file", str(dest / ".git" / "config"), "--unset-all", "core.worktree"],
        cwd=dest, check=False)
    return sorted(skipped)


def load_tool_meta(paths: ToolPaths) -> ToolMeta:
    if not paths.meta_file.exists():
        raise IngestError(f"{paths.meta_file} missing; was the tool added?")
    return ToolMeta.model_validate(yaml.safe_load(paths.meta_file.read_text(encoding="utf-8")))


def resolve_source_root(eng: Engagement, meta: ToolMeta) -> Path:
    if meta.origin_kind == "link":
        assert meta.source_path is not None
        return Path(meta.source_path) if meta.external else eng.root / meta.source_path
    return eng.tool_paths(meta.name).source
