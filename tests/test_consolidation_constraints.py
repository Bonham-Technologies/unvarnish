"""Consultant constraints for the consolidation proposal (spec §17)."""
from unvarnish.config import ConsolidationConstraints, EngagementConfig
from unvarnish.schemas.comparison import Comparison, Consolidation


def test_constraints_are_optional_and_parse_from_yaml_shape():
    cfg = EngagementConfig.model_validate({"client": "Acme"})
    assert cfg.consolidation.is_empty()
    cfg = EngagementConfig.model_validate({"client": "Acme", "consolidation": {
        "target_platform": "Azure App Service, .NET 8",
        "approved_stack": ["React", "PostgreSQL"], "must_keep": ["SAP integration"],
        "retire": ["Access databases"], "notes": "One team of three."}})
    c = cfg.consolidation
    assert not c.is_empty() and c.approved_stack == ["React", "PostgreSQL"]


def test_old_artifacts_and_replies_without_the_new_fields_still_load():
    assert Consolidation.model_validate({}).constraint_conflicts == []
    cmp = Comparison.model_validate({"tools": ["a", "b"], "tools_with_model": [],
                                     "summaries": []})
    assert cmp.constraints is None
    assert ConsolidationConstraints().is_empty()


def test_request_carries_constraints_only_when_given():
    from unvarnish.model.prompts.compare import (
        COMPARE_PROMPT_VERSION,
        build_consolidate_request,
    )
    from unvarnish.schemas.comparison import ToolSummary

    summaries = [ToolSummary(tool="a", purpose="p"), ToolSummary(tool="b", purpose="q")]
    plain = build_consolidate_request(summaries, [], [], None)
    assert "Consultant constraints" not in plain.messages[0].content
    c = ConsolidationConstraints(target_platform="Azure", approved_stack=["React"],
                                 must_keep=["SAP integration"], retire=["Access"],
                                 notes="One team.")
    text = build_consolidate_request(summaries, [], [], None, constraints=c).messages[0].content
    assert "## Consultant constraints" in text
    for part in ("Target platform: Azure", "Approved stack: React", "Must keep: SAP integration",
                 "Retire: Access", "Notes: One team."):
        assert part in text
    assert "constraint_conflicts" in plain.system and COMPARE_PROMPT_VERSION >= "2026-10-19.1"


def test_compare_applies_records_and_hashes_constraints(engagement, synthetic_repo):
    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.artifacts import read_artifact
    from unvarnish.phases.compare import ComparePhase, EngagementContext, run_comparison
    from unvarnish.schemas.comparison import Comparison

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    from unvarnish.model.budget import BudgetTracker

    ectx = EngagementContext(engagement=engagement, budget=BudgetTracker(None))
    before = ComparePhase(backend=stub).inputs_hash(ectx)
    data = engagement.config.model_dump()
    data["consolidation"] = {"target_platform": "Azure", "must_keep": ["SAP"]}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()
    assert ComparePhase(backend=stub).inputs_hash(ectx) != before
    run_comparison(engagement, backend=stub)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.constraints is not None and cmp.constraints.target_platform == "Azure"
    sent = [r for r in stub.requests if r.schema_name == "Consolidation"][-1]
    assert "Target platform: Azure" in sent.messages[0].content


def test_document_shows_constraints_and_conflicts(engagement, synthetic_repo):
    import json

    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.phases.compare import run_comparison

    stub = _compare_stub()
    original = stub.replies["Consolidation"]
    reply = json.loads(original if isinstance(original, str) else original(None))
    reply["constraint_conflicts"] = ["Reports | need Excel macros, which Azure cannot run"]
    stub.replies["Consolidation"] = json.dumps(reply)
    _two_tools(engagement, synthetic_repo, stub)
    data = engagement.config.model_dump()
    data["consolidation"] = {"target_platform": "Azure | .NET", "approved_stack": ["React"]}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    assert "### Consultant constraints" in doc
    assert "Target platform: Azure \\| .NET" in doc and "Approved stack: React" in doc
    assert "### Conflicts with the constraints" in doc
    assert "need Excel macros" in doc
    prose = [r for r in stub.requests if r.schema_name == "prose"
             and "consolidation" in r.messages[0].content]
    assert prose and "Azure" in prose[-1].messages[0].content


def test_document_without_constraints_has_no_constraint_headings(engagement, synthetic_repo):
    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.phases.compare import run_comparison

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    assert "### Consultant constraints" not in doc
    assert "### Conflicts with the constraints" not in doc
