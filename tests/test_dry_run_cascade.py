"""UNVAR-30: `run --dry-run` plans every phase a stale phase feeds, with model estimates."""
import json
import re

from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.phases.base import _recorded_hash
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()
ENV = {"COLUMNS": "250"}


def _configure(eng, fake):
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(),
                                                  **model_config(fake)})
    eng.save_config()


def _planned(output: str) -> list[str]:
    return re.findall(r"│\s*(\w+)\s*│\s*would run", output)


def _unit_hashes(unit_dir) -> dict[str, str | None]:
    return {p.stem: _recorded_hash(p) for p in unit_dir.glob("*.json")}


def test_dry_run_after_a_source_edit_lists_every_downstream_phase(ingested, fake_llm):
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0

    fresh = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert fresh.exit_code == 0, fresh.output
    assert _planned(fresh.output) == []
    assert "estimate" not in fresh.output

    paths = eng.tool_paths(tool)
    with (paths.source / "app.py").open("a", encoding="utf-8") as fh:
        fh.write("\n\ndef added():\n    return 42\n")

    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert dry.exit_code == 0, dry.output
    # git reads the repository's history, not the working tree, so an edit leaves it fresh.
    assert _planned(dry.output) == ["inventory", "scan", "split", "extract", "rollup_modules",
                                    "rollup_tool", "verify", "render"]
    m = re.search(r"│\s*extract\s*│\s*estimate\s*│\s*≈ [\d,]+ tokens.*?(\d+) of (\d+) units new "
                  r"or changed", dry.output)
    assert m, dry.output
    changed, total = int(m.group(1)), int(m.group(2))
    assert 0 < changed < total
    for phase in ("rollup_modules", "rollup_tool", "verify", "render"):
        assert re.search(rf"│\s*{phase}\s*│\s*estimate\s*│\s*≈", dry.output), phase

    # The dry run changed nothing, and its count matches what the real run re-extracts.
    before = _unit_hashes(paths.unit_dir)
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    after = _unit_hashes(paths.unit_dir)
    assert sum(1 for uid, h in after.items() if before.get(uid) != h) == changed


def _changed(raw: bytes) -> bytes:
    """The file with its content changed: an artifact's data, since freshness hashes cover an
    artifact's data and not its meta (UNVAR-34); any other file's bytes."""
    try:
        doc = json.loads(raw)
        doc["data"]["__probe__"] = True
    except (ValueError, KeyError, TypeError):
        return raw + b"\n"
    return json.dumps(doc).encode("utf-8")


def test_declared_dependencies_match_what_each_inputs_hash_reads(ingested, fake_llm):
    """Each phase's `depends_on` names exactly the phases whose artifacts change its hash."""
    from unvarnish.phases import default_phases
    from unvarnish.phases.base import build_context

    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    ctx = build_context(eng, tool)
    phases = default_phases()
    for reader in phases:
        derived = set()
        for producer in phases:
            if producer is reader:
                continue
            outputs = [p for p in producer.outputs(ctx) if p.exists()]
            saved = {p: p.read_bytes() for p in outputs}
            before = reader.inputs_hash(ctx)
            try:
                for p in outputs:
                    p.write_bytes(_changed(saved[p]))
                if reader.inputs_hash(ctx) != before:
                    derived.add(producer.name)
            finally:
                for p, data in saved.items():
                    p.write_bytes(data)
        assert derived == set(reader.depends_on), reader.name


def test_dry_run_after_a_model_change_prices_every_unit_from_the_recorded_split(
        ingested, fake_llm):
    """Split stays fresh, so the estimate reads its recorded index; every unit's hash names
    the old model, so every unit is priced."""
    eng, _ = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    eng.config = EngagementConfig.model_validate(
        {**eng.config.model_dump(), **model_config(fake_llm, model="other-model")})
    eng.save_config()

    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert dry.exit_code == 0, dry.output
    planned = _planned(dry.output)
    assert planned[0] == "extract" and "split" not in planned
    m = re.search(r"│\s*extract\s*│\s*estimate\s*│.*?(\d+) of (\d+) units new or changed",
                  dry.output)
    assert m, dry.output
    assert m.group(1) == m.group(2) != "0"


def test_dry_run_after_a_unit_size_change_splits_the_recorded_census_in_memory(
        ingested, fake_llm):
    """Inventory stays fresh, so the in-memory split reads the recorded census."""
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    index = eng.tool_paths(tool).units_index
    recorded = index.read_bytes()
    eng.config = EngagementConfig.model_validate(
        {**eng.config.model_dump(), "pipeline": {**eng.config.pipeline.model_dump(),
                                                 "unit_tokens": 40}})
    eng.save_config()

    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert dry.exit_code == 0, dry.output
    planned = _planned(dry.output)
    assert planned[0] == "split" and "inventory" not in planned
    m = re.search(r"│\s*extract\s*│\s*estimate\s*│.*?(\d+) of (\d+) units new or changed",
                  dry.output)
    assert m, dry.output
    assert int(m.group(1)) > 0
    assert index.read_bytes() == recorded  # the in-memory split wrote nothing


def test_in_memory_census_honours_the_git_index_like_the_real_inventory(tmp_path):
    # UNVAR-28 x UNVAR-30: the dry run's census must exclude exactly what inventory excludes,
    # or the extract estimate counts units the real run never splits.
    from unvarnish.phases.inventory import census_files

    (tmp_path / ".gitignore").write_text("config.json\n", encoding="utf-8")
    (tmp_path / "config.json").write_text('{"db": "prod"}\n', encoding="utf-8")
    by_path = {r.path: r for r in census_files(tmp_path)}
    assert by_path["config.json"].exclusion_reason == "gitignore"
    by_path = {r.path: r for r in census_files(tmp_path, {"config.json"})}
    assert by_path["config.json"].excluded is False


def test_dry_run_with_nothing_stale_says_so_instead_of_an_empty_table(ingested, fake_llm):
    """UNVAR-61: an empty plan prints one sentence, not a table with no rows."""
    eng, _tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0

    fresh = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert fresh.exit_code == 0, fresh.output
    assert "Nothing to run: every phase is fresh." in fresh.output
    assert "dry run" not in fresh.output
    assert "│" not in fresh.output


def test_dry_run_with_one_fresh_phase_names_that_phase_not_every_phase(ingested, fake_llm):
    """UNVAR-61: `--phase` checks one phase, so the message must not claim every phase."""
    eng, _tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0

    fresh = runner.invoke(app, ["run", "--dry-run", "--phase", "verify", "-e", str(eng.root)],
                          env=ENV)
    assert fresh.exit_code == 0, fresh.output
    assert "Nothing to run: the verify phase is fresh." in fresh.output
    assert "every phase" not in fresh.output


def test_dry_run_with_a_missing_tool_does_not_call_everything_fresh(
        ingested, fake_llm, synthetic_repo):
    """UNVAR-61: a missing tool's phases are not fresh; the message covers only the others."""
    eng, _tool = ingested
    ingest_tool(eng, "gone", str(synthetic_repo), "repo")
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    (eng.root / "tools" / "gone" / "tool.yaml").unlink()

    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)], env=ENV)
    assert dry.exit_code == 2, dry.output
    assert "Nothing to run for the other tools: every phase is fresh." in dry.output
    assert "could not run" in dry.output
