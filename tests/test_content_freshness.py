"""UNVAR-34: freshness follows content, so touching a file reruns inventory and nothing else."""
import json
import os

from pydantic import BaseModel
from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.artifacts import hash_files, write_artifact
from unvarnish.cli import app
from unvarnish.config import EngagementConfig

runner = CliRunner()

DOWNSTREAM = ["git", "scan", "split", "extract", "rollup_modules", "rollup_tool", "verify",
              "render"]


class _Data(BaseModel):
    value: int


def test_rewriting_identical_data_keeps_the_hash(tmp_path):
    a = tmp_path / "a.json"
    write_artifact(a, _Data(value=1), produced_by="x", inputs_hash="one")
    before = hash_files([a])
    raw = json.loads(a.read_text(encoding="utf-8"))
    raw["meta"]["produced_at"] = "2001-01-01T00:00:00Z"
    a.write_text(json.dumps(raw), encoding="utf-8")  # also unsorted, unindented
    assert hash_files([a]) == before
    write_artifact(a, _Data(value=2), produced_by="x", inputs_hash="one")
    assert hash_files([a]) != before


def test_the_recorded_inputs_hash_counts_except_for_the_inventorys(tmp_path):
    """A phase's inputs hash folds in its own inputs' content, so it changes when anything the
    phase read changed, even when its data did not: a split that cuts the same byte ranges
    from edited source must still make extract rerun. The inventory's inputs hash holds file
    timestamps, so its artifacts count by data alone."""
    a = tmp_path / "a.json"
    write_artifact(a, _Data(value=1), produced_by="split", inputs_hash="one")
    before = hash_files([a])
    write_artifact(a, _Data(value=1), produced_by="split", inputs_hash="two")
    assert hash_files([a]) != before
    write_artifact(a, _Data(value=1), produced_by="inventory", inputs_hash="one")
    before = hash_files([a])
    write_artifact(a, _Data(value=1), produced_by="inventory", inputs_hash="two")
    assert hash_files([a]) == before


def test_non_artifacts_and_unparsable_json_hash_their_bytes(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text("# one\n", encoding="utf-8")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    plain = tmp_path / "plain.json"
    plain.write_text('{"a": 1}', encoding="utf-8")
    before = hash_files([doc, broken, plain])
    doc.write_text("# one\n\n", encoding="utf-8")
    assert hash_files([doc, broken, plain]) != before
    before = hash_files([doc, broken, plain])
    broken.write_text("{not json!", encoding="utf-8")
    assert hash_files([doc, broken, plain]) != before
    before = hash_files([doc, broken, plain])
    plain.write_text('{"a": 1}\n', encoding="utf-8")
    assert hash_files([doc, broken, plain]) != before


def _configure(eng, fake):
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(),
                                                  **model_config(fake)})
    eng.save_config()


def _statuses(paths) -> dict[str, tuple[str, str | None]]:
    raw = json.loads(paths.run_record.read_text(encoding="utf-8"))
    return {r["phase"]: (r["status"], r["message"]) for r in raw["data"]["results"]}


def test_touching_a_source_file_reruns_inventory_and_nothing_else(ingested, fake_llm):
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    paths = eng.tool_paths(tool)
    requests = len(fake_llm.requests)
    docs = {p: p.read_bytes() for p in paths.docs.glob("*.md")}
    assert docs

    st = (paths.source / "app.py").stat()
    os.utime(paths.source / "app.py", ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    statuses = _statuses(paths)
    assert statuses["inventory"][0] == "ok"
    for phase in DOWNSTREAM:
        assert statuses[phase] == ("skipped", "fresh"), (phase, statuses[phase])
    assert len(fake_llm.requests) == requests
    assert {p: p.read_bytes() for p in paths.docs.glob("*.md")} == docs


def test_a_same_size_edit_still_reruns_what_reads_the_source(ingested, fake_llm):
    """Size, line count and metrics stay the same; the census's content digest does not."""
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    paths = eng.tool_paths(tool)
    requests = len(fake_llm.requests)
    census = json.loads(paths.census.read_text(encoding="utf-8"))["data"]
    target = paths.source / "app.py"
    text = target.read_text(encoding="utf-8")
    i = next(i for i, c in enumerate(text) if c.isalpha() and c.islower())
    target.write_text(text[:i] + text[i].upper() + text[i + 1:], encoding="utf-8")
    st = target.stat()
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    after = json.loads(paths.census.read_text(encoding="utf-8"))["data"]
    assert after["files"] == census["files"]  # nothing the census measures moved
    statuses = _statuses(paths)
    for phase in ("inventory", "scan", "split"):
        assert statuses[phase][0] == "ok", (phase, statuses[phase])
    # The units index comes out the same (same byte ranges), but the unit's source did not:
    # extract must rerun and re-extract it, and everything that reads the units after it.
    for phase in ("extract", "rollup_modules", "rollup_tool", "verify", "render"):
        assert statuses[phase][0] == "ok", (phase, statuses[phase])
    assert len(fake_llm.requests) > requests


def test_a_census_from_before_the_digest_reruns_the_inventory_once(ingested, fake_llm):
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    paths = eng.tool_paths(tool)
    raw = json.loads(paths.census.read_text(encoding="utf-8"))
    del raw["data"]["content_digest"]  # as an earlier version wrote it, same inputs hash
    paths.census.write_text(json.dumps(raw), encoding="utf-8")

    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    assert _statuses(paths)["inventory"][0] == "ok"
    assert json.loads(paths.census.read_text(encoding="utf-8"))["data"]["content_digest"]
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    assert all(s == ("skipped", "fresh") for s in _statuses(paths).values())
