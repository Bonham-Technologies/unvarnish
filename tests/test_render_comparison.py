from tests.test_compare_phase import _compare_stub, _two_tools
from tests.test_render_documents import _phases
from unvarnish.artifacts import read_artifact
from unvarnish.model.base import BackendError
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.compare import run_comparison
from unvarnish.phases.ingest import ingest_tool
from unvarnish.render.comparison import integration_diagram
from unvarnish.render.prose import BLOCKS
from unvarnish.schemas.render import RenderState


def test_prose_blocks_exist():
    assert {"tools_reviewed", "consolidation_proposal"} <= set(BLOCKS)


def test_comparison_document_two_tools(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    prose_before = stub.count("prose")  # the per-tool documents used the same stub
    results = run_comparison(engagement, backend=stub)
    assert [r.phase for r in results] == ["compare", "render_comparison"]
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    doc = engagement.comparison_doc.read_text()
    assert doc.startswith("# Acme: Tool Comparison")
    assert "(s)" not in doc
    for heading in ("## 1. Tools reviewed", "## 2. Capability matrix",
                    "## 3. Integration and data map", "## 4. Risk comparison",
                    "## 5. Consolidation proposal"):
        assert heading in doc, heading
    assert "PROSE Write one paragraph per tool" in doc
    assert "PROSE Write the consolidation proposal" in doc
    assert "| Capability | Actor | alpha | beta | Covered by |" in doc
    assert ("| Admin Can Export Report | staff | admin can export report | "
            "admin can export report | 2 |") in doc
    assert "| System | Category | Tools | Details |" in doc
    assert "| expenses db | data store | alpha, beta |" in doc
    assert "```mermaid" in doc
    assert "| Measure | alpha | beta |" in doc and "| Source lines |" in doc
    assert "| Secrets in history | 2 | 2 |" in doc
    assert "starting point" in doc
    assert "- no audit trail" in doc and "| Finance can export a report | alpha, beta |" in doc
    assert "| export reports | alpha | single data store |" in doc
    state = read_artifact(engagement.comparison_render_state, RenderState).data
    assert set(state.documents) == {"comparison.md"}
    assert stub.count("prose") - prose_before == 2
    again = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.skipped for r in again)  # fresh


def test_comparison_document_single_tool_states_skips(engagement, synthetic_repo):
    stub = _compare_stub()
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    prose_before = stub.count("prose")
    results = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    doc = engagement.comparison_doc.read_text()
    assert "Skipped: one tool with a tool model" in doc
    assert "No consolidation proposal" in doc
    assert stub.count("prose") - prose_before == 1  # tools_reviewed only


def test_comparison_prose_failure_falls_back(engagement, synthetic_repo):
    stub = _compare_stub(prose=BackendError("400"))
    _two_tools(engagement, synthetic_repo, stub)
    results = run_comparison(engagement, backend=stub)
    assert results[1].status == PhaseStatus.ok and len(results[1].failures) == 2
    assert "_No model-written text for this section: model call failed._" in (
        engagement.comparison_doc.read_text())


def test_integration_diagram_caps_rows():
    from unvarnish.schemas.comparison import Comparison, IntegrationEntry, IntegrationRow

    rows = [IntegrationRow(name=f"sys{i}", category="external_system", tools=["a"],
                           entries=[IntegrationEntry(tool="a", kind="http", description="d")])
            for i in range(50)]
    cmp = Comparison(tools=["a"], tools_with_model=["a"], summaries=[], integration_map=rows,
                     risk_table=[])
    d = integration_diagram(cmp, max_rows=10)
    assert len([n for n in d.nodes if n.kind == "external"]) == 10
    assert d.note and "10 most shared of 50" in d.note
    assert len(d.edges) == 10
