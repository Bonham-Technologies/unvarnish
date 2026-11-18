from unvarnish.model.prompts.compare import (
    CONSOLIDATE_MAX_TOKENS,
    NORMALISE_MAX_TOKENS,
    build_consolidate_request,
    build_consolidate_system,
    build_normalise_request,
    build_normalise_system,
    capability_line,
)
from unvarnish.schemas.comparison import (
    IntegrationEntry,
    IntegrationRow,
    MatrixCell,
    MatrixRow,
    ToolSummary,
)
from unvarnish.schemas.finding import Evidence
from unvarnish.schemas.toolmodel import Capability, capability_id


def _cap(tool: str, actor: str, action: str, obj: str, implicit: bool = False) -> Capability:
    return Capability(id=capability_id(tool, actor, action, obj), tool=tool, actor=actor,
                      action=action, object=obj, description="desc", implicit=implicit,
                      evidence=[Evidence(path="a.py")])


def test_system_prompts_carry_schemas():
    for build in (build_normalise_system, build_consolidate_system):
        text = build()
        assert '"additionalProperties": false' in text and "{{" not in text
    assert "capability_id" in build_normalise_system()
    assert "starting point" in build_consolidate_system()


def test_capability_line_and_normalise_request():
    a = _cap("alpha", "admin", "export", "report", implicit=True)
    line = capability_line("alpha", a)
    assert line == f"alpha | {a.id} | admin can export report | desc | implicit"
    req = build_normalise_request({"alpha": [a], "beta": []}, effort="low")
    body = req.messages[0].content
    assert "## alpha (1 capabilities)" in body and "## beta (0 capabilities)" in body
    assert line in body
    assert req.schema_name == "CapabilityNormalisation"
    assert req.max_tokens == NORMALISE_MAX_TOKENS and req.effort == "low"


def test_consolidate_request_carries_matrix_and_integration():
    summaries = [ToolSummary(tool="alpha", purpose="Tracks expenses", actors=["admin"],
                             capabilities=3, source_lines=900, model_analysed=True)]
    matrix = [MatrixRow(name="Export reports", description="d", actor="staff",
                        cells=[MatrixCell(tool="alpha", labels=["admin can export report"]),
                               MatrixCell(tool="beta", labels=[])], tools_covering=1)]
    integration = [IntegrationRow(name="Expenses DB", category="data_store", tools=["alpha"],
                                  entries=[IntegrationEntry(tool="alpha", kind="db",
                                                            description="pg")])]
    req = build_consolidate_request(summaries, matrix, integration, effort=None)
    body = req.messages[0].content
    assert "## Tools" in body and "alpha: Tracks expenses" in body
    assert "## Capability matrix" in body and "Export reports" in body
    assert "alpha: admin can export report" in body and "beta: -" in body
    assert "## Integration and data map" in body and "Expenses DB [data_store]: alpha" in body
    assert req.schema_name == "Consolidation" and req.max_tokens == CONSOLIDATE_MAX_TOKENS
