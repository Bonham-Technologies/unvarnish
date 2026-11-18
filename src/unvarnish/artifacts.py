from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class ArtifactMeta(BaseModel):
    schema_version: int
    produced_by: str
    produced_at: datetime
    inputs_hash: str


class Artifact[T: BaseModel](BaseModel):
    meta: ArtifactMeta
    data: T


def write_artifact(
    path: Path,
    data: BaseModel,
    *,
    produced_by: str,
    inputs_hash: str,
    schema_version: int = 1,
) -> None:
    """Write `data` wrapped in the artifact envelope, atomically."""
    meta = ArtifactMeta(
        schema_version=schema_version,
        produced_by=produced_by,
        produced_at=datetime.now(UTC),
        inputs_hash=inputs_hash,
    )
    payload = {"meta": meta.model_dump(mode="json"), "data": data.model_dump(mode="json")}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)


def read_artifact[T: BaseModel](path: Path, model: type[T]) -> Artifact[T]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return Artifact[model].model_validate(raw)  # type: ignore[valid-type]


def hash_inputs(parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


# Phases whose recorded inputs hash covers file timestamps (a stat walk of the source), not
# content. Their artifacts count by data alone, so a touch that changes nothing stops there.
STAT_HASHED_PRODUCERS = frozenset({"inventory"})


def content_bytes(path: Path) -> bytes:
    """What a file contributes to a freshness hash. For an artifact, its schema version, data
    and recorded inputs hash in canonical form, without `meta.produced_at`, which changes on
    every write: hashing the whole file made an unchanged rewrite (an inventory rerun after a
    touch or a checkout) stale every phase downstream (UNVAR-34). The inputs hash stays,
    because a phase's data does not always show what it read: a split of edited source can
    cut the same byte ranges, and extract must still rerun. Every inputs hash but the
    inventory's is built from content, so it is stable across reruns; the inventory's holds
    mtimes and is left out (its census carries a content digest instead).
    Anything else, or JSON that is not an artifact, is its bytes."""
    raw = path.read_bytes()
    if path.suffix != ".json":
        return raw
    try:
        doc = json.loads(raw)
        meta = doc["meta"]
        content = {"data": doc["data"], "schema_version": meta["schema_version"]}
        if meta.get("produced_by") not in STAT_HASHED_PRODUCERS:
            content["inputs_hash"] = meta["inputs_hash"]
    except (ValueError, KeyError, TypeError, AttributeError):
        return raw
    return b"artifact\0" + json.dumps(content, sort_keys=True, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")


def hash_files(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths, key=lambda x: str(x)):
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(content_bytes(p) if p.is_file() else b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


def digest_file(path: Path, chunk: int = 1 << 20) -> str:
    """sha256 of a file's bytes, read in chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def walk_files(root: Path) -> tuple[list[tuple[Path, str]], int]:
    """Regular files under root as (path, posix relpath), sorted. Skips .git.

    Never follows symlinks; returns how many symlinks (files or dirs) were skipped.
    """
    files: list[tuple[Path, str]] = []
    symlinks = 0
    if not root.exists():
        return files, symlinks
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            if d == ".git":
                continue
            if (here / d).is_symlink():
                symlinks += 1
                continue
            kept.append(d)
        dirnames[:] = kept
        for fn in sorted(filenames):
            p = here / fn
            if p.is_symlink():
                symlinks += 1
                continue
            if p.is_file():
                files.append((p, p.relative_to(root).as_posix()))
    files.sort(key=lambda t: t[1])
    return files, symlinks


def hash_tree(root: Path) -> str:
    """Fast stat-based hash of a source tree: relative path, size, mtime. Skips .git."""
    h = hashlib.sha256()
    if not root.exists():
        return hash_inputs(["<missing-root>"])
    files, _ = walk_files(root)
    for p, rel in files:
        st = p.stat()
        h.update(f"{rel}|{st.st_size}|{st.st_mtime_ns}".encode())
        h.update(b"\0")
    return h.hexdigest()
