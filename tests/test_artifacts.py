import json
import os
from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import (
    hash_files,
    hash_inputs,
    hash_tree,
    read_artifact,
    walk_files,
    write_artifact,
)


class Thing(BaseModel):
    name: str
    count: int


def test_write_and_read_round_trip(tmp_path: Path):
    target = tmp_path / "out" / "thing.json"
    write_artifact(target, Thing(name="a", count=2), produced_by="test", inputs_hash="abc")
    art = read_artifact(target, Thing)
    assert art.data == Thing(name="a", count=2)
    assert art.meta.produced_by == "test"
    assert art.meta.inputs_hash == "abc"
    assert art.meta.schema_version == 1
    assert not target.with_suffix(".json.tmp").exists()


def test_written_json_has_envelope(tmp_path: Path):
    target = tmp_path / "thing.json"
    write_artifact(target, Thing(name="a", count=1), produced_by="p", inputs_hash="h")
    raw = json.loads(target.read_text())
    assert set(raw) == {"meta", "data"}
    assert set(raw["meta"]) == {"schema_version", "produced_by", "produced_at", "inputs_hash"}


def test_hash_inputs_is_order_sensitive_and_stable():
    assert hash_inputs(["a", "b"]) == hash_inputs(["a", "b"])
    assert hash_inputs(["a", "b"]) != hash_inputs(["b", "a"])
    assert hash_inputs(["ab"]) != hash_inputs(["a", "b"])


def test_hash_files_changes_with_content_and_tolerates_missing(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text("one")
    h1 = hash_files([f])
    f.write_text("two")
    h2 = hash_files([f])
    assert h1 != h2
    assert hash_files([tmp_path / "missing"]) == hash_files([tmp_path / "missing"])


def test_hash_tree_ignores_git_and_tracks_mtime(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    src = tmp_path / "a.py"
    src.write_text("x = 1")
    h1 = hash_tree(tmp_path)
    (tmp_path / ".git" / "HEAD").write_text("other")
    assert hash_tree(tmp_path) == h1
    os.utime(src, ns=(1, 1))
    assert hash_tree(tmp_path) != h1


def test_walk_files_skips_symlinks_and_git(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("b")
    (tmp_path / "a.py").write_text("a")
    os.symlink("a.py", tmp_path / "link.py")
    os.symlink("sub", tmp_path / "linkdir")
    files, symlinks = walk_files(tmp_path)
    assert [rel for _, rel in files] == ["a.py", "sub/b.py"]
    assert symlinks == 2
