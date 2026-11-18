from unvarnish.model.prompts.rollup import (
    UNIT_TEXT_CHARS,
    ToolFacts,
    build_directory_rollup_request,
    build_directory_rollup_system,
    build_module_rollup_request,
    build_module_rollup_system,
    build_tool_rollup_request,
    build_tool_rollup_system,
    chunk_text,
    digest_text,
    unit_text,
)
from unvarnish.schemas.analysis import ExternalRef, Unit, UnitExtraction, UnitKind, UnitResult
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.rollup import ModuleDigest
from unvarnish.schemas.toolmodel import DirectoryRollup, EntryPoint


def _unit_result(purpose: str = "Adds two numbers.", line_start: int = 1,
                 line_end: int = 10) -> UnitResult:
    unit = Unit(id="u1", tool="t", module_id="a.py", path="a.py", language="python",
                kind=UnitKind.function, name="add", line_start=line_start, line_end=line_end,
                byte_start=0, byte_end=10, token_estimate=5, split_method="structural")
    ext = UnitExtraction(purpose=purpose, interface=["add"],
                         external_calls=[ExternalRef(system="db.internal", kind="db",
                                                     detail="reads rows")],
                         data_read=["expenses"], risks=["no input validation"], confidence=0.7)
    return UnitResult(unit=unit, extraction=ext, backend="b", model="m", usage=Usage(),
                      prompt_version="v")


def _digest(path: str = "a.py") -> ModuleDigest:
    return ModuleDigest(id="x", path=path, language="python", units=2, lines=50,
                        summary="Handles expenses.", responsibilities=["store", "report"],
                        interface=["add"], dependencies_out=["b.py"],
                        external_systems=["db.internal"], data_read=["expenses"], findings=1)


def test_system_prompts_carry_schema_and_taxonomy():
    for build in (build_module_rollup_system, build_directory_rollup_system,
                  build_tool_rollup_system):
        text = build()
        assert '"additionalProperties": false' in text
        assert "security, data_handling, maintainability" in text
        assert "{{" not in text  # every placeholder substituted


def test_unit_text_is_bounded_and_descriptive():
    text = unit_text(_unit_result(purpose="x" * 5000))
    assert len(text) <= UNIT_TEXT_CHARS
    assert text.startswith("### function add, lines 1-10")
    short = unit_text(_unit_result())
    assert "db.internal (db): reads rows" in short and "reads: expenses" in short
    assert "risks: no input validation" in short


def test_module_request_lists_units_and_file_facts():
    req = build_module_rollup_request("a.py", "python", 120, [_unit_result(), _unit_result()],
                                      ["Flask"], effort="low")
    body = req.messages[0].content
    assert body.startswith("File: a.py\nLanguage: python\nLines: 120\nFrameworks: Flask\n")
    assert "Units analysed: 2" in body and body.count("### function add") == 2
    assert req.schema_name == "ModuleRollup" and req.cache_system and req.effort == "low"


def test_digest_text_and_directory_request():
    text = digest_text(_digest())
    assert text.startswith("- a.py (python, 50 lines, 2 units): Handles expenses.")
    assert "depends on: b.py" in text and "findings: 1" in text
    req = build_directory_rollup_request("apps/api", [_digest("apps/api/a.py")], effort=None)
    assert req.messages[0].content.startswith("Path prefix: apps/api\nFiles: 1\n")
    assert req.schema_name == "DirectoryRollup"
    root = build_directory_rollup_request("", [_digest()], effort=None)
    assert "Path prefix: (repository root)" in root.messages[0].content


def test_tool_request_single_pass_and_chunked():
    facts = ToolFacts(tool="expense-bot", languages={"python": 900}, frameworks=["Flask"],
                      files_analysed=3, source_lines=900, commits=4, authors=2,
                      first_commit="2026-01-05", last_commit="2026-02-01")
    single = build_tool_rollup_request(facts, [_digest()], [], effort=None)
    body = single.messages[0].content
    assert "Tool: expense-bot" in body and "Files:" in body and "- a.py (python" in body
    assert single.schema_name == "ToolRollup"

    dr = DirectoryRollup(summary="API layer.", entry_points=[EntryPoint(
        name="POST /expenses", kind="http", module="apps/api/a.py", description="create")])
    chunked = build_tool_rollup_request(facts, [], [("apps/api", 12, dr)], effort=None)
    body = chunked.messages[0].content
    assert "summarised in 1 directory chunk" in body
    assert "## Chunk apps/api (12 files)" in body and "POST /expenses" in body
    assert "- a.py (python" not in body
    assert chunk_text("x", 1, dr).startswith("## Chunk x (1 files)")
