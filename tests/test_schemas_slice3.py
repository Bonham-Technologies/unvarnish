import json

from tests.stub_backend import StubBackend
from unvarnish.config import EngagementConfig
from unvarnish.engagement import ToolPaths
from unvarnish.model.budget import BudgetTracker
from unvarnish.model.structured import strict_schema
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.schemas.rollup import ModuleRollup, module_file_id
from unvarnish.schemas.toolmodel import DirectoryRollup, ToolRollup, capability_id
from unvarnish.schemas.verify import Verdict


def test_module_file_id_stable_and_file_safe():
    a = module_file_id("apps/x/y.ts")
    assert a == module_file_id("apps/x/y.ts")
    assert len(a) == 16 and a.isalnum()
    assert a != module_file_id("apps/x/z.ts")


def test_strict_schemas_build_for_every_model_output():
    for cls in (ModuleRollup, DirectoryRollup, ToolRollup, Verdict):
        s = strict_schema(cls)
        assert s["additionalProperties"] is False
        text = json.dumps(s)
        for kw in ('"minimum"', '"maximum"', '"minItems"', '"default"'):
            assert kw not in text, (cls.__name__, kw)
        assert '"title": "' not in text  # pydantic's schema titles are stripped


def test_capability_id_normalises_case_and_space():
    assert capability_id("t", "Admin ", "export", "Report") == capability_id(
        "t", "admin", "EXPORT", "report")
    assert capability_id("t", "admin", "export", "report") != capability_id(
        "u", "admin", "export", "report")


def test_tool_paths_slice3(tmp_path):
    p = ToolPaths(tmp_path)
    assert p.module_dir == tmp_path / "analysis" / "modules"
    assert p.modules_index == tmp_path / "analysis" / "modules.json"
    assert p.tool_model == tmp_path / "analysis" / "tool.json"
    assert p.capabilities == tmp_path / "analysis" / "capabilities.json"
    assert p.model_findings == tmp_path / "analysis" / "findings.json"
    assert p.architecture_doc == tmp_path / "docs" / "architecture.md"
    assert p.requirements_doc == tmp_path / "docs" / "requirements.md"


def test_finding_verification_note_round_trips():
    f = Finding(tool="t", category=Category.security, severity=Severity.high, title="x",
                summary="s", impact="i", remediation="r", evidence=[Evidence(path="a.py")],
                source=Source.model, model="m", verification_note="evidence shows it")
    assert Finding.model_validate(f.model_dump()).verification_note == "evidence shows it"
    assert Finding.model_validate(
        {**f.model_dump(), "verification_note": None}).verification_note is None


def test_pipeline_config_rollup_input_tokens_default():
    assert EngagementConfig().pipeline.rollup_input_tokens == 40_000


def test_extract_uses_shared_budget(ingested):
    eng, tool = ingested
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))  # another phase already spent the cap
    ctx = build_context(eng, tool, budget=tracker)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    stub = StubBackend()
    assert ExtractPhase(backend=stub).run(ctx).status == PhaseStatus.stopped
    assert stub.requests == []
