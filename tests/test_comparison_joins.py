import json

from unvarnish.analysis.comparison import (
    build_matrix,
    capability_label,
    integration_map,
    normalise_name,
    risk_row,
    tool_summary,
)
from unvarnish.engagement import Engagement
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    CapabilityRef,
    Consolidation,
    NormalisedCapability,
)
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Evidence
from unvarnish.schemas.toolmodel import (
    Actor,
    Capability,
    DataStore,
    ExternalSystem,
    ToolModel,
    capability_id,
)


def _cap(tool: str, actor: str, action: str, obj: str) -> Capability:
    return Capability(id=capability_id(tool, actor, action, obj), tool=tool, actor=actor,
                      action=action, object=obj, description="d",
                      implementing_modules=["a.py"], evidence=[Evidence(path="a.py")])


def _tm(tool: str, stores=(), externals=(), caps=()) -> ToolModel:
    return ToolModel(
        tool=tool, purpose=f"{tool} purpose", actors=[Actor(name="admin", description="d")],
        entry_points=[], data_stores=list(stores), external_systems=list(externals),
        internal_stack=[], module_map=[], data_flows=[], deployment_assumptions=[],
        capabilities=list(caps), business_rules=[], open_questions=[], confidence=0.5,
        backend="b", model="m", usage=Usage(), prompt_version="v",
    )


def test_schemas_are_strict_and_paths_exist(tmp_path):
    for cls in (CapabilityNormalisation, Consolidation):
        s = strict_schema(cls)
        assert s["additionalProperties"] is False and '"minItems"' not in json.dumps(s)
    eng = Engagement.create(tmp_path / "e")
    assert eng.comparison_file == eng.root / "comparison" / "comparison.json"
    assert eng.comparison_doc == eng.root / "comparison" / "comparison.md"
    assert eng.comparison_render_state == eng.root / "comparison" / "render-state.json"
    assert eng.comparison_failures == eng.root / "comparison" / "failures.json"


def test_normalise_name_and_label():
    assert normalise_name("  Expenses  DB ") == "expenses db"
    assert normalise_name("Stripe.") == "stripe"
    assert capability_label(_cap("t", "Admin", "export", "report")) == "Admin can export report"


def test_build_matrix_maps_members_per_tool():
    a = _cap("alpha", "admin", "export", "report")
    b = _cap("beta", "finance", "download", "statement")
    c = _cap("beta", "admin", "approve", "expense")
    norm = CapabilityNormalisation(capabilities=[NormalisedCapability(
        name="Export reports", description="Get data out", actor="staff",
        members=[CapabilityRef(tool="alpha", capability_id=a.id),
                 CapabilityRef(tool="beta", capability_id=b.id)])])
    rows, unmapped, dropped = build_matrix(norm, {"alpha": [a], "beta": [b, c]})
    assert [r.name for r in rows] == ["Export reports", "admin can approve expense"]
    first = rows[0]
    assert first.tools_covering == 2 and not first.unmapped
    assert {cell.tool: cell.labels for cell in first.cells} == {
        "alpha": ["admin can export report"], "beta": ["finance can download statement"]}
    assert rows[1].unmapped and rows[1].tools_covering == 1
    assert unmapped == 1 and dropped == 0


def test_build_matrix_drops_unknown_and_appends_unmapped():
    a = _cap("alpha", "admin", "export", "report")
    norm = CapabilityNormalisation(capabilities=[
        NormalisedCapability(name="Ghost", description="d", actor="x", members=[
            CapabilityRef(tool="alpha", capability_id="nope"),
            CapabilityRef(tool="gamma", capability_id=a.id)]),
    ])
    rows, unmapped, dropped = build_matrix(norm, {"alpha": [a]})
    assert dropped == 2 and unmapped == 1
    assert [r.name for r in rows] == ["admin can export report"]  # empty group dropped
    assert all(len(r.cells) == 1 for r in rows)  # one cell per tool, always


def test_build_matrix_without_normalisation_is_per_tool_rows():
    a = _cap("alpha", "admin", "export", "report")
    rows, unmapped, dropped = build_matrix(None, {"alpha": [a]})
    assert len(rows) == 1 and rows[0].unmapped and unmapped == 1 and dropped == 0


def test_integration_map_merges_case_and_spacing():
    alpha = _tm("alpha", stores=[DataStore(name="Expenses DB", kind="db", description="pg")],
                externals=[ExternalSystem(name="Stripe", kind="payment", direction="outbound",
                                          description="charges")])
    beta = _tm("beta", stores=[DataStore(name="expenses  db", kind="db", description="same")],
               externals=[ExternalSystem(name="Slack", kind="http", direction="both",
                                         description="alerts")])
    rows = integration_map({"alpha": alpha, "beta": beta})
    by_name = {r.name: r for r in rows}
    assert set(by_name) == {"Expenses DB", "Stripe", "Slack"}
    assert by_name["Expenses DB"].tools == ["alpha", "beta"]
    assert by_name["Expenses DB"].category == "data_store"
    assert by_name["Stripe"].entries[0].direction == "outbound"
    assert rows[0].name == "Expenses DB"  # shared systems first, then by name


def test_risk_row_and_tool_summary(ingested):
    from unvarnish.artifacts import read_artifact
    from unvarnish.phases.base import PhaseRunner, build_context
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.schemas.git import GitStats
    from unvarnish.schemas.inventory import Census, Dependencies, Metrics
    from unvarnish.schemas.scan import ScannerFindings

    eng, tool = ingested
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx)
    p = ctx.paths
    census = read_artifact(p.census, Census).data
    row = risk_row(tool, census, read_artifact(p.metrics, Metrics).data,
                   read_artifact(p.git, GitStats).data,
                   read_artifact(p.scanner_findings, ScannerFindings).data, None,
                   read_artifact(p.dependencies, Dependencies).data)
    assert row.tool == tool and not row.model_analysed
    assert row.source_lines > 3000 and row.largest_file_lines > 3000
    assert row.secrets_history == 2 and row.secrets_current == 0
    assert row.bus_factor == 1 and row.findings_by_severity.get("high", 0) >= 2
    assert row.critical_or_high == row.findings_by_severity.get("high", 0)
    assert row.ai_indicators >= 1 and row.dependency_vulnerabilities is None
    summary = tool_summary(tool, None, census)
    assert summary.purpose is None and not summary.model_analysed and summary.capabilities == 0
    with_model = tool_summary(tool, _tm(tool, caps=[_cap(tool, "a", "b", "c")]), census)
    assert with_model.purpose == f"{tool} purpose" and with_model.capabilities == 1
