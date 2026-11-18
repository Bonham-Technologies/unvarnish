"""Known-issues burn-down, task 5: comparison."""
import json

from typer.testing import CliRunner

from tests.test_compare_phase import CONSOLIDATION, _compare_stub, _two_tools
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.phases.compare import run_comparison
from unvarnish.schemas.comparison import Comparison

runner = CliRunner()


def _consolidation(**over):
    base = json.loads(CONSOLIDATION)
    base.update(over)
    return json.dumps(base)


def test_serves_column_is_escaped_and_unknown_tools_are_marked(engagement, synthetic_repo):
    stub = _compare_stub(Consolidation=_consolidation(
        abstract_requirements=[{"statement": "One login", "serves": ["alpha | admins", "beta"]}],
        recommended_approach=[{"capability": "export", "recommended_tool": "gamma",
                               "rationale": "best"}]))
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    assert "alpha \\| admins, beta" in doc
    assert "gamma (not a reviewed tool)" in doc


def test_footnote_says_when_matching_did_not_run(engagement, synthetic_repo):
    stub = _compare_stub(CapabilityNormalisation="not json")
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.normalised is False
    doc = engagement.comparison_doc.read_text()
    if cmp.unmapped_capabilities:
        assert "Capability matching did not run" in doc
        assert "could not be grouped" not in doc


def test_a_failed_proposal_is_retried_on_the_next_compare(engagement, synthetic_repo):
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.phases.base import is_fresh
    from unvarnish.phases.compare import ComparePhase, EngagementContext

    stub = _compare_stub(Consolidation="not json")
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    ectx = EngagementContext(engagement=engagement, budget=BudgetTracker(None))
    assert not is_fresh(ComparePhase(backend=stub), ectx)


def test_a_crash_in_compare_is_recorded(engagement, synthetic_repo, monkeypatch):
    import unvarnish.phases.compare as compare_mod

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)

    def boom(*a, **k):
        raise RuntimeError("matrix exploded")

    monkeypatch.setattr(compare_mod, "build_matrix", boom)
    run_comparison(engagement, backend=stub, force=True)
    failures = json.loads((engagement.comparison_dir / "failures.json").read_text())
    assert "matrix exploded" in json.dumps(failures)


def test_not_ready_is_a_typed_result(engagement, synthetic_repo, fake_llm):
    from tests.test_cli_compare import _engagement

    eng = _engagement(engagement.root.parent / "other", synthetic_repo, fake_llm)
    results = run_comparison(eng)
    assert results[0].not_ready
    assert runner.invoke(app, ["compare", "-e", str(eng.root)]).exit_code == 2


def test_normalisation_input_is_capped():
    from unvarnish.model.prompts.compare import MAX_CAPABILITIES_PER_TOOL, build_normalise_request
    from unvarnish.schemas.toolmodel import Capability

    caps = [Capability(id=f"c{i}", tool="a", actor="user", action="do", object=f"thing {i}",
                       description="d", implicit=False) for i in range(500)]
    req = build_normalise_request({"a": caps, "b": caps[:3]}, None)
    text = req.messages[0].content
    assert text.count("\na | ") <= MAX_CAPABILITIES_PER_TOOL
    assert "more not sent" in text
