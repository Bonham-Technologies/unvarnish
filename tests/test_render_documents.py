import json

import pytest

from tests.stub_backend import StubBackend
from tests.test_rollup_modules import MODULE
from tests.test_rollup_tool import DIRECTORY, TOOL
from tests.test_verify import _unit_reply
from unvarnish.artifacts import read_artifact
from unvarnish.model.base import BackendError
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.render import RenderPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.phases.verify import VerifyPhase
from unvarnish.schemas.render import RenderState


def _verdict(req) -> str:
    body = req.messages[0].content
    verdict = "rejected" if "README.md" in body else "confirmed"  # the README credential
    return json.dumps({"verdict": verdict, "reason": "checked the lines"})


def _prose(req) -> str:
    return "PROSE " + req.messages[0].content.split("\n", 1)[0][:40]


def _stub(**over) -> StubBackend:
    replies = {"UnitExtraction": _unit_reply, "ModuleRollup": MODULE, "ToolRollup": TOOL,
               "DirectoryRollup": DIRECTORY, "Verdict": _verdict, "prose": _prose}
    replies.update(over)
    return StubBackend(replies)


def _phases(stub):
    return [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(backend=stub),
            RollupModulesPhase(backend=stub), RollupToolPhase(backend=stub),
            VerifyPhase(backend=stub), RenderPhase(backend=stub)]


def _run_all(eng, tool, stub):
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    results = PhaseRunner(_phases(stub)).run(ctx)
    return ctx, results


def test_all_three_documents_render(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx, results = _run_all(eng, tool, stub)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    p = ctx.paths
    assert p.findings_doc.exists() and p.architecture_doc.exists() and p.requirements_doc.exists()

    findings = p.findings_doc.read_text()
    for doc in (p.findings_doc, p.architecture_doc, p.requirements_doc):
        assert "(s)" not in doc.read_text(), doc.name
    assert "## Executive summary" in findings
    assert "PROSE Write the executive summary" in findings
    assert "model-assisted analysis (stub/stub-model)" in findings
    assert "verification: confirmed" in findings
    assert "**Verifier.** checked the lines" in findings
    assert "No auth anywhere" in findings and "**unverified**" in findings  # tool-level
    from unvarnish.schemas.verify import ModelFindings
    mf = read_artifact(p.model_findings, ModelFindings).data
    assert mf.rejected == 1  # the README.md credential finding
    n_cred = sum(1 for f in mf.findings if f.title == "Hardcoded credential")
    assert findings.count("#### Hardcoded credential") == n_cred - 1  # rejected one excluded
    assert "rejected on verification and is excluded" in findings
    assert findings.index("AWS access key ID in git history") < findings.index(
        "Hardcoded credential")  # scanner before model at equal severity
    assert "Mixed responsibilities" in findings  # module-level medium finding
    assert "Model findings (after verification)" in findings

    arch = p.architecture_doc.read_text()
    assert arch.startswith("# expense-bot: Architecture")
    assert arch.count("```mermaid") == 2 and "flowchart LR" in arch
    assert "| `app.py` | entry point |" in arch
    assert "PROSE Write one or two paragraphs on what" in arch
    assert "PROSE Write one paragraph on where" in arch
    assert "PROSE Write one paragraph on how the tool" in arch
    assert "## 8. Analysis coverage" in arch and "single pass" in arch
    assert "| Frameworks (detected) |" in arch

    req = p.requirements_doc.read_text()
    assert req.startswith("# expense-bot: Requirements Inventory")
    assert "| admin | export | report |" in req
    assert "| admin | bypass | approval | yes |" in req  # implicit flagged
    assert "no implementing module identified" in req
    assert "| expenses db | db |" in req and "admin can export report" in req
    assert "| limit 500 | threshold | `app.py` |" in req
    assert "PROSE Write the open questions" in req and "who owns it?" in req

    state = read_artifact(p.render_state, RenderState).data
    assert set(state.documents) == {"findings.md", "architecture.md", "requirements.md"}
    assert is_fresh(RenderPhase(backend=stub), ctx)
    assert stub.count("prose") == 5


def test_render_without_model_writes_findings_only(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results)
    doc = ctx.paths.findings_doc.read_text()
    assert "Model-assisted analysis was not run" in doc
    assert "_No model-written text for this section: no model configured._" in doc
    assert not ctx.paths.architecture_doc.exists() and not ctx.paths.requirements_doc.exists()
    assert RenderPhase().outputs(ctx) == [ctx.paths.render_state, ctx.paths.findings_doc]


def test_render_prose_failure_falls_back(ingested):
    eng, tool = ingested
    stub = _stub(prose=BackendError("400 bad request"))
    ctx, results = _run_all(eng, tool, stub)
    render = results[-1]
    assert render.status == PhaseStatus.ok and len(render.failures) == 5
    doc = ctx.paths.findings_doc.read_text()
    assert "_No model-written text for this section: model call failed._" in doc


def test_render_override_with_unknown_prose_block(ingested):
    eng, tool = ingested
    override = eng.root / "templates"
    override.mkdir()
    (override / "findings.md.j2").write_text('# {{ tool.name }}\n\n{% prose "nonexistent" %}\n')
    stub = _stub()
    ctx, results = _run_all(eng, tool, stub)
    render = results[-1]
    assert render.status == PhaseStatus.ok
    assert any("nonexistent" in f for f in render.failures)
    doc = ctx.paths.findings_doc.read_text()
    assert doc.startswith("# expense-bot\n") and "unknown prose block 'nonexistent'" in doc
    assert ctx.paths.architecture_doc.exists()  # the other documents still render


def test_findings_appendix_lists_model_gaps(ingested):
    eng, tool = ingested

    def flaky_unit(req):
        if "File: README.md" in req.messages[0].content:
            return "garbage"
        return _unit_reply(req)

    stub = _stub(UnitExtraction=flaky_unit, ModuleRollup="garbage")
    ctx = build_context(eng, tool, budget=BudgetTracker(None))
    for phase in (InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(),
                  ExtractPhase(backend=stub), RollupModulesPhase(backend=stub)):
        assert phase.run(ctx).status == PhaseStatus.ok, phase.name
    assert RenderPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    doc = ctx.paths.findings_doc.read_text()
    assert "Units the model could not analyse" in doc and "`README.md`" in doc
    assert "Files whose module rollup failed" in doc and "`app.py`" in doc
    assert "Everything in the source tree was analysed" not in doc
    assert not ctx.paths.architecture_doc.exists()  # no tool.json yet


def test_empty_module_map_renders_a_sentence_not_a_none_diagram(ingested, tmp_path):
    """UNVAR-77: a tool model with no module map wrote ```mermaid\\nNone into architecture.md."""
    import shutil

    from unvarnish.config import BrandingConfig
    from unvarnish.export.pandoc import export_markdown
    from unvarnish.schemas.diagrams import DiagramSet

    tool = json.loads(TOOL)
    tool["module_map"] = []
    eng, tool_name = ingested
    ctx, results = _run_all(eng, tool_name, _stub(ToolRollup=json.dumps(tool)))
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    arch = ctx.paths.architecture_doc.read_text(encoding="utf-8")
    section = arch.split("## 4. Module map and interactions", 1)[1].split("\n## ", 1)[0]
    assert "\nNone\n" not in section and "```mermaid\nNone" not in arch
    assert "unvarnish-diagram: modules" not in section and "```mermaid" not in section
    assert "No module map was identified" in section
    assert arch.count("```mermaid") == 1  # the context diagram still renders

    if shutil.which("pandoc") is None or shutil.which("dot") is None:
        pytest.skip("pandoc and graphviz needed for the export check")
    diagrams = read_artifact(ctx.paths.diagrams, DiagramSet).data.diagrams
    out = tmp_path / "architecture.html"
    failures = export_markdown(ctx.paths.architecture_doc, "html", out, diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work")
    html = out.read_text(encoding="utf-8")
    assert failures == []
    assert 'alt="Module map' not in html
