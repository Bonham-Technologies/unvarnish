from unvarnish.artifacts import read_artifact
from unvarnish.config import EngagementConfig
from unvarnish.phases.base import PhaseStatus, build_context, is_fresh
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.split import SplitPhase, resolve_unit_tokens
from unvarnish.schemas.analysis import UnitKind, UnitsIndex


def _split(eng, name):
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    r = SplitPhase().run(ctx)
    assert r.status == PhaseStatus.ok, r.message
    return read_artifact(ctx.paths.units_index, UnitsIndex).data, ctx


def test_split_synthetic_repo(ingested):
    idx, ctx = _split(*ingested)
    paths = {u.path for u in idx.units}
    assert "app.py" in paths and "static/index.html" in paths and "README.md" in paths
    assert not any(p.startswith("node_modules/") for p in paths)
    app_units = idx.modules["app.py"]
    assert len(app_units) >= 2  # the 3000-line function is bigger than one unit
    by_id = {u.id: u for u in idx.units}
    assert all(by_id[i].path == "app.py" for i in app_units)
    html_kinds = {by_id[i].kind for i in idx.modules["static/index.html"]}
    assert UnitKind.script_block in html_kinds and UnitKind.style_block in html_kinds
    minified = next(u for u in idx.units if u.path == "static/app.min.js")
    assert minified.generated is True
    assert idx.unit_tokens == 8000
    assert len({u.id for u in idx.units}) == len(idx.units)


def test_split_is_fresh_until_inputs_change(ingested):
    idx, ctx = _split(*ingested)
    assert is_fresh(SplitPhase(), ctx)
    ctx.engagement.config.pipeline.unit_tokens = 500
    assert not is_fresh(SplitPhase(), ctx)


def test_resolve_unit_tokens_prefers_backend_override():
    cfg = EngagementConfig.model_validate({
        "pipeline": {"unit_tokens": 8000},
        "backends": {"small": {"type": "openai_compatible", "base_url": "http://x",
                               "unit_tokens": 3000}},
        "models": {"default": {"backend": "small", "model": "m"}},
    })
    assert resolve_unit_tokens(cfg) == 3000
    assert resolve_unit_tokens(EngagementConfig()) == 8000


def test_split_skips_huge_files(engagement, tmp_path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "huge.py").write_bytes(b"x = 1\n" * 1_000_000)  # 6 MB
    (pile / "ok.py").write_text("y = 2\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    idx, _ = _split(engagement, "pile")
    assert [u.path for u in idx.units] == ["ok.py"]
    assert idx.skipped[0].path == "huge.py" and "5,000,000" in idx.skipped[0].reason
