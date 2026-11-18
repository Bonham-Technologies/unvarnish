import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import fill_schema, request_schema
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.model.estimate import (
    estimate_render,
    estimate_rollup_tool,
    estimate_verify,
)
from unvarnish.model.structured import strict_schema
from unvarnish.phases import default_phases
from unvarnish.phases.base import RunRecord
from unvarnish.schemas.analysis import ExtractState, Failures, UnitExtraction
from unvarnish.schemas.rollup import ModulesIndex
from unvarnish.schemas.toolmodel import ToolRollup
from unvarnish.schemas.verify import Verdict

runner = CliRunner()


def test_default_phase_order():
    assert [p.name for p in default_phases()] == [
        "inventory", "git", "scan", "split", "extract", "rollup_modules", "rollup_tool",
        "verify", "render"]


def test_fill_schema_produces_valid_instances():
    for cls in (UnitExtraction, ToolRollup, Verdict):
        filled = fill_schema(strict_schema(cls))
        cls.model_validate(filled)
    assert fill_schema({"type": "string", "enum": ["a", "b"]}) == "a"
    assert fill_schema({"anyOf": [{"type": "string"}, {"type": "null"}]}) == "stub"


def test_estimates_scale_with_inputs():
    assert estimate_rollup_tool(10, 40_000).total() < estimate_rollup_tool(2000, 40_000).total()
    assert estimate_verify(0).total() == 0 and estimate_verify(3).total() > 0
    assert estimate_render(5).total() > 0
    assert estimate_render(0).total() == 0


def test_render_estimate_counts_only_the_tool_documents_blocks():
    from unvarnish.model.estimate import tool_prose_block_count
    from unvarnish.render.markdown import make_env, prose_block_names
    from unvarnish.render.prose import BLOCKS

    env = make_env()
    comparison = set(prose_block_names(env, "comparison.md.j2"))
    assert comparison and len(BLOCKS) == 5 + len(comparison)  # the old, overstated count
    assert tool_prose_block_count(env) == 5


def test_dry_run_render_estimate_reads_the_tool_templates(ingested):
    from unvarnish.model.estimate import estimate_plan, estimate_render
    from unvarnish.phases.base import build_context

    eng, name = ingested
    usage, note = estimate_plan(build_context(eng, name), ["render"])["render"]
    assert note == "5 prose blocks" and usage == estimate_render(5)
    tdir = eng.root / "templates"  # an override with fewer blocks is estimated as it renders
    tdir.mkdir()
    (tdir / "findings.md.j2").write_text("CUSTOM {{ tool.name }}\n", encoding="utf-8")
    assert estimate_plan(build_context(eng, name), ["render"])["render"][1] == "4 prose blocks"


def _configure(eng, fake):
    conf = model_config(fake)
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **conf})
    eng.save_config()


def test_dry_run_estimates_every_model_phase(ingested, fake_llm):
    eng, _ = ingested
    _configure(eng, fake_llm)
    out = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    for phase in ("extract", "rollup_modules", "rollup_tool", "verify", "render"):
        assert phase in out.output
    assert out.output.count("estimate") >= 5


def test_full_run_through_cli_with_autofill(ingested, fake_llm):
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    out = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    docs = eng.tool_paths(tool).docs
    assert {p.name for p in docs.glob("*.md")} == {"findings.md", "architecture.md",
                                                   "requirements.md"}
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert status.exit_code == 0, status.output
    assert "modules" in status.output and "3 docs" in status.output
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    for phase in ("extract", "rollup_modules", "rollup_tool", "render"):
        assert phase in cost.output
    tool_json = json.loads((eng.tool_paths(tool).analysis / "tool.json").read_text())
    assert tool_json["data"]["purpose"] == "stub"


def _replies(broken: dict):
    """Schema-filled replies, except malformed JSON for README.md's extraction while
    broken["on"] is set: both attempts and the repair call, so the unit is recorded as
    failed."""
    extraction_schema = strict_schema(UnitExtraction)
    bad = "not json at all"

    def reply(body):
        schema = request_schema(body)
        first = body["messages"][0]["content"]
        if (broken["on"] and schema == extraction_schema
                and ("File: README.md" in first or f"Malformed output:\n{bad}" in first)):
            return bad
        return json.dumps(fill_schema(schema)) if schema else "Model-written paragraph."

    return reply


def _extract_message(paths) -> str:
    record = read_artifact(paths.run_record, RunRecord).data
    return next(r.message for r in record.results if r.phase == "extract")


def _is_extraction(body) -> bool:
    return request_schema(body) == strict_schema(UnitExtraction)


def test_a_failed_unit_is_retried_by_a_plain_rerun(ingested, fake_llm):
    """UNVAR-29: a unit that failed extraction keeps extract stale, so the next `run` (no
    --force) retries only that unit, clears its failure and refreshes the downstream phases."""
    eng, tool = ingested
    _configure(eng, fake_llm)
    broken = {"on": True}
    fake_llm.script(*([_replies(broken)] * 500))
    first = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert first.exit_code == 1, first.output
    paths = eng.tool_paths(tool)
    assert "1 failed; rerun to retry" in _extract_message(paths)
    state = read_artifact(paths.extract_state, ExtractState).data
    assert state.units_failed == 1 and state.units_done == state.units_total - 1
    assert [f.path for f in read_artifact(paths.failures, Failures).data.items
            if f.phase == "extract"] == ["README.md"]
    assert "README.md" in read_artifact(paths.modules_index, ModulesIndex).data.skipped

    broken["on"] = False
    n = len(fake_llm.requests)
    second = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert second.exit_code == 0, second.output
    retried = [q for q in fake_llm.requests[n:] if _is_extraction(q)]
    assert len(retried) == 1 and "File: README.md" in retried[0]["messages"][0]["content"]
    state = read_artifact(paths.extract_state, ExtractState).data
    assert state.units_failed == 0 and state.units_done == state.units_total
    assert not [f for f in read_artifact(paths.failures, Failures).data.items
                if f.phase == "extract"]
    modules = read_artifact(paths.modules_index, ModulesIndex).data  # downstream reran
    assert "README.md" in {d.path for d in modules.modules}
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert f"{state.units_total}/{state.units_total} units" in status.output

    n = len(fake_llm.requests)
    third = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert third.exit_code == 0, third.output
    assert len(fake_llm.requests) == n  # nothing left to retry: every phase is fresh


def test_a_unit_that_keeps_failing_is_retried_without_redoing_the_rest(ingested, fake_llm):
    """A permanently failing unit is re-attempted on each run, which is what the docs
    promise. The later phases rerun on the rewritten state, but their requests are unchanged,
    so the response cache answers them: only the failing unit reaches the model again."""
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.script(*([_replies({"on": True})] * 500))
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 1
    n = len(fake_llm.requests)
    again = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert again.exit_code == 1, again.output
    new = fake_llm.requests[n:]
    assert new and all(_is_extraction(q) for q in new)
    assert "1 failed; rerun to retry" in _extract_message(eng.tool_paths(tool))
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert "(1 failed)" in status.output
