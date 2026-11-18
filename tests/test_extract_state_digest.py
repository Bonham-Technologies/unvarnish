"""UNVAR-47: the extract state shows what its units were extracted with, so rollups never stay
fresh on another effort's extractions while one unit keeps failing."""
import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import fill_schema, request_schema
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.schemas.analysis import ExtractState

runner = CliRunner()

FAILING = "File: static/index.html\\nUnit: script_block render"  # this unit never parses
BROKEN = "not json at all"
LATER = ("rollup_modules", "rollup_tool", "verify", "render")
ANSWER_FAILING = {"on": False}  # let the failing unit succeed, as a model might on another effort


def _configure(eng, fake, effort: str) -> None:
    cfg = model_config(fake)
    cfg["models"]["phases"] = {"extract": {"backend": "fake", "model": "fake-model",
                                           "effort": effort}}
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **cfg})
    eng.save_config()


def _reply(body: dict) -> str:
    text = json.dumps(body.get("messages", []))
    schema = request_schema(body)
    failing = FAILING in text and not ANSWER_FAILING["on"]
    if failing or "Malformed output:\\n" + BROKEN in text:  # the repair call too
        return BROKEN
    if schema:
        return json.dumps(fill_schema(schema))
    return "Model-written paragraph."


def _always(fake) -> None:
    fake._next = lambda: _reply  # every request answered by _reply, never from the queue


def _statuses(paths) -> dict[str, tuple[str, str | None]]:
    raw = json.loads(paths.run_record.read_text(encoding="utf-8"))
    return {r["phase"]: (r["status"], r["message"]) for r in raw["data"]["results"]}


def _run(eng, fake, effort: str):
    _configure(eng, fake, effort)
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code in (0, 1), r.output
    return r


def test_reverting_the_effort_with_a_failing_unit_reruns_the_rollups(ingested, fake_llm):
    eng, tool = ingested
    _always(fake_llm)
    paths = eng.tool_paths(tool)

    _run(eng, fake_llm, "low")                             # A
    state = read_artifact(paths.extract_state, ExtractState)
    assert state.data.units_failed > 0 and state.meta.inputs_hash == ""
    _run(eng, fake_llm, "high")                            # B
    _run(eng, fake_llm, "high")                            # B again: zero usage
    assert read_artifact(paths.extract_state, ExtractState).data.usage.total() == 0
    _run(eng, fake_llm, "low")                             # back to A, from the response cache
    assert read_artifact(paths.extract_state, ExtractState).data.usage.total() == 0

    statuses = _statuses(paths)
    assert statuses["extract"][0] != "skipped", statuses["extract"]
    for phase in LATER:
        assert statuses[phase] != ("skipped", "fresh"), (phase, statuses[phase])

    _run(eng, fake_llm, "low")                             # nothing changed
    statuses = _statuses(paths)
    for phase in LATER:
        assert statuses[phase] == ("skipped", "fresh"), (phase, statuses[phase])


def test_the_digest_follows_the_units_inputs(ingested, fake_llm):
    eng, tool = ingested
    _always(fake_llm)
    paths = eng.tool_paths(tool)
    _run(eng, fake_llm, "low")
    a = read_artifact(paths.extract_state, ExtractState).data.units_digest
    _run(eng, fake_llm, "high")
    b = read_artifact(paths.extract_state, ExtractState).data.units_digest
    _run(eng, fake_llm, "low")
    assert a and b and a != b
    assert read_artifact(paths.extract_state, ExtractState).data.units_digest == a


def test_an_extract_state_from_before_the_digest_still_loads(ingested, fake_llm):
    eng, tool = ingested
    fake_llm.autofill = True
    _configure(eng, fake_llm, "low")
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    paths = eng.tool_paths(tool)
    raw = json.loads(paths.extract_state.read_text(encoding="utf-8"))
    del raw["data"]["units_digest"]  # as an earlier version wrote it
    paths.extract_state.write_text(json.dumps(raw), encoding="utf-8")
    assert read_artifact(paths.extract_state, ExtractState).data.units_digest == ""
    # A complete extract keeps its recorded hash, so extract stays fresh and keeps the old
    # state; the rollups downstream rerun at most once (from the module cache), then settle.
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    assert _statuses(paths)["extract"] == ("skipped", "fresh")
    assert "units_digest" not in json.loads(paths.extract_state.read_text(encoding="utf-8"))["data"]
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    assert all(s == ("skipped", "fresh") for s in _statuses(paths).values())


def test_an_incomplete_state_from_before_the_digest_reruns_the_rollups_once(ingested, fake_llm):
    """With a unit still failing, extract reruns every run and rewrites its state: the first
    run after the upgrade adds the digest, which reruns the rollups once."""
    eng, tool = ingested
    _always(fake_llm)
    paths = eng.tool_paths(tool)
    _run(eng, fake_llm, "low")
    raw = json.loads(paths.extract_state.read_text(encoding="utf-8"))
    del raw["data"]["units_digest"]
    paths.extract_state.write_text(json.dumps(raw), encoding="utf-8")
    _run(eng, fake_llm, "low")
    assert _statuses(paths)["rollup_modules"][0] == "ok"
    _run(eng, fake_llm, "low")
    statuses = _statuses(paths)
    for phase in LATER:
        assert statuses[phase] == ("skipped", "fresh"), (phase, statuses[phase])


def test_a_failed_units_stale_artifact_enters_the_digest(ingested, fake_llm):
    """A run that extracts the failing unit but stops before the rollups (an interrupt, a
    budget stop, `--phase extract`) leaves it an artifact the rollups read. Reverting then
    fails the unit again, from the response cache: the state must still differ."""
    eng, tool = ingested
    _always(fake_llm)
    paths = eng.tool_paths(tool)
    _run(eng, fake_llm, "low")
    _run(eng, fake_llm, "low")                             # zero usage
    _run(eng, fake_llm, "low")                             # rollups settled
    assert _statuses(paths)["rollup_modules"] == ("skipped", "fresh")
    ANSWER_FAILING["on"] = True
    try:
        _configure(eng, fake_llm, "high")
        r = runner.invoke(app, ["run", "-e", str(eng.root), "--phase", "extract"])
        assert r.exit_code == 0, r.output
        assert read_artifact(paths.extract_state, ExtractState).data.units_failed == 0
    finally:
        ANSWER_FAILING["on"] = False
    _run(eng, fake_llm, "low")                             # the unit fails again
    state = read_artifact(paths.extract_state, ExtractState)
    assert state.data.units_failed > 0 and state.data.usage.total() == 0
    assert _statuses(paths)["rollup_modules"] != ("skipped", "fresh")
