import json

from tests.stub_backend import StubBackend
from tests.test_rollup_modules import MODULE, UNIT, _extracted
from unvarnish.artifacts import read_artifact
from unvarnish.config import EngagementConfig
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseStatus, build_context, is_fresh
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import (
    RollupToolPhase,
    common_prefix,
    partition_digests,
    to_tool_findings,
)
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.rollup import ModuleDigest
from unvarnish.schemas.toolmodel import (
    RequirementsInventory,
    ToolCandidateFinding,
    ToolModel,
)

TOOL = json.dumps({
    "purpose": "Tracks expenses.",
    "actors": [{"name": "admin", "description": "finance staff"}],
    "entry_points": [{"name": "main", "kind": "cli", "module": "app.py", "description": "entry"}],
    "data_stores": [{"name": "expenses db", "kind": "db", "description": "postgres",
                     "modules": ["app.py"]}],
    "external_systems": [{"name": "AWS", "kind": "storage", "direction": "outbound",
                          "description": "S3", "modules": ["app.py"]}],
    "internal_stack": ["python"],
    "module_map": [{"path": "app.py", "role": "entry point", "depends_on": ["README.md"]},
                   {"path": "ghost.py", "role": "does not exist", "depends_on": []}],
    "data_flows": [{"source": "admin", "target": "expenses db", "data": "expense rows",
                    "via": "cli"}],
    "deployment_assumptions": ["runs on a laptop"],
    "capabilities": [
        {"actor": "admin", "action": "export", "object": "report", "description": "d",
         "implementing_modules": ["app.py"], "data_touched": ["expenses db"],
         "implicit": False},
        {"actor": "admin", "action": "bypass", "object": "approval", "description": "d",
         "implementing_modules": ["nowhere.py"], "data_touched": [], "implicit": True},
    ],
    "business_rules": [{"description": "limit 500", "module": "app.py", "kind": "threshold"}],
    "open_questions": ["who owns it?"],
    "candidate_findings": [
        {"category": "security", "severity": "high", "title": "No auth anywhere",
         "summary": "s", "impact": "i", "remediation": "r", "paths": ["app.py"],
         "confidence": 0.9},
        {"category": "security", "severity": "high", "title": "Phantom",
         "summary": "s", "impact": "i", "remediation": "r", "paths": ["nope.py"],
         "confidence": 0.9},
    ],
    "confidence": 0.8,
})
DIRECTORY = json.dumps({
    "summary": "Part.", "responsibilities": ["r"], "entry_points": [], "data_stores": [],
    "external_systems": [{"name": "Stripe", "kind": "payment", "direction": "outbound",
                          "description": "charges", "modules": []}],
    "notable_modules": [{"path": "app.py", "role": "entry", "depends_on": []}],
    "risks": [], "candidate_findings": [],
})


def _digest(path: str) -> ModuleDigest:
    return ModuleDigest(id="x", path=path, units=1, lines=10, summary="s" * 100)


def test_common_prefix():
    assert common_prefix(["apps/a/x.ts", "apps/a/y.ts"]) == "apps/a"
    assert common_prefix(["apps/a/x.ts", "apps/b/y.ts"]) == "apps"
    assert common_prefix(["x.ts", "apps/a.ts"]) == ""
    assert common_prefix(["apps/a/x.ts"]) == "apps/a"


def test_partition_digests():
    digests = [_digest(f"apps/{'ab'[i % 2]}/m{i}.py") for i in range(10)]
    assert partition_digests(digests, 10**6) == []
    chunks = partition_digests(digests, 120)
    assert len(chunks) > 1
    covered = [d.path for _, ch in chunks for d in ch]
    assert covered == sorted(d.path for d in digests)
    assert all(prefix.startswith("apps") for prefix, _ in chunks)


def test_to_tool_findings_drops_unknown_paths():
    cands = [ToolCandidateFinding(category="security", severity="high", title="a", summary="s",
                                  impact="i", remediation="r", paths=["a.py", "zzz.py"],
                                  confidence=0.5),
             ToolCandidateFinding(category="security", severity="high", title="b", summary="s",
                                  impact="i", remediation="r", paths=["zzz.py"], confidence=0.5)]
    findings, dropped = to_tool_findings(cands, {"a.py"}, "t", "m")
    assert [f.title for f in findings] == ["a"] and dropped == 1
    assert [e.path for e in findings[0].evidence] == ["a.py"]


def _rolled(engagement, tool, stub, budget=None):
    ctx = _extracted(engagement, tool, stub, budget=budget)
    assert RollupModulesPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    return ctx


def test_rollup_tool_single_pass(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": UNIT, "ModuleRollup": MODULE, "ToolRollup": TOOL})
    ctx = _rolled(eng, tool, stub)
    res = RollupToolPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    assert stub.count("DirectoryRollup") == 0 and stub.count("ToolRollup") == 1
    tm = read_artifact(ctx.paths.tool_model, ToolModel).data
    assert tm.purpose == "Tracks expenses." and not tm.hierarchical and tm.chunks == 0
    assert [m.path for m in tm.module_map] == ["app.py"]  # ghost.py dropped
    assert [f.title for f in tm.findings] == ["No auth anywhere"] and tm.dropped_findings == 1
    export, bypass = tm.capabilities
    assert export.id and export.evidence[0].path == "app.py"
    assert bypass.implicit and bypass.evidence == []
    inv = read_artifact(ctx.paths.capabilities, RequirementsInventory).data
    row = next(r for r in inv.data_inventory if r.name == "expenses db")
    assert row.used_by == [export.id]
    assert [r.name for r in inv.data_inventory] == ["expenses db", "AWS"]
    assert is_fresh(RollupToolPhase(backend=stub), ctx)


def test_rollup_tool_hierarchical_when_over_budget(ingested):
    eng, tool = ingested
    eng.config = EngagementConfig.model_validate({
        **eng.config.model_dump(), "pipeline": {"rollup_input_tokens": 1}})
    eng.save_config()
    stub = StubBackend({"UnitExtraction": UNIT, "ModuleRollup": MODULE, "ToolRollup": TOOL,
                        "DirectoryRollup": DIRECTORY})
    ctx = _rolled(eng, tool, stub)
    res = RollupToolPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    n_modules = len(json.loads(ctx.paths.modules_index.read_text())["data"]["modules"])
    assert stub.count("DirectoryRollup") == n_modules  # one digest per chunk at budget 1
    tm = read_artifact(ctx.paths.tool_model, ToolModel).data
    assert tm.hierarchical and tm.chunks == n_modules and tm.modules_covered == n_modules
    assert "Stripe" in [s.name for s in tm.external_systems]  # merged from chunks
    tool_req = next(r for r in stub.requests if r.schema_name == "ToolRollup")
    assert "directory chunk" in tool_req.messages[0].content


def test_rollup_tool_failure_is_recorded(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": UNIT, "ModuleRollup": MODULE, "ToolRollup": "nope"})
    ctx = _rolled(eng, tool, stub)
    res = RollupToolPhase(backend=stub).run(ctx)
    # one failed call never kills the run: the phase completes with a recorded failure and
    # no tool.json, so render still produces findings.md
    assert res.status == PhaseStatus.ok and res.failures and not ctx.paths.tool_model.exists()
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert any(f.phase == "rollup_tool" for f in items)


def test_rollup_tool_budget_stop(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": UNIT, "ModuleRollup": MODULE, "ToolRollup": TOOL})
    ctx = _rolled(eng, tool, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ctx = build_context(eng, tool, budget=tracker)
    assert RollupToolPhase(backend=stub).run(ctx).status == PhaseStatus.stopped
    assert stub.count("ToolRollup") == 0 and not ctx.paths.tool_model.exists()
