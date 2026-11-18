# Unvarnish Slice 4: Cross-Tool Comparison Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the engagement-level `compare` command that joins every tool's analysis into a capability matrix, integration map, risk table, and (for two or more tools) a consolidation proposal, and renders `comparison.md`.

**Architecture:** Two engagement-level phases in one module (`phases/compare.py`): `ComparePhase` writes `comparison/comparison.json` from pure JSON joins plus two model calls (capability normalisation, consolidation proposal); `RenderComparisonPhase` renders `comparison.md` through the slice 3 prose and diagram machinery. Tools without a tool model still appear in the risk table and are flagged; one tool skips the matrix and the proposal with a stated reason. Everything is offline-testable with `StubBackend` and the fake server's autofill.

**Tech Stack:** Python 3.12+, Pydantic v2, Jinja2 (`{% prose %}` tag from slice 3), Typer/Rich, pytest, ruff. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` sections 3 (`compare`), 4 (`comparison/`), 5.3, 6.10, 8.6, 13. Slice 3 plan for the machinery this reuses: `docs/superpowers/plans/2026-10-17-unvarnish-slice3-rollups-verify-documents.md`.

## Global Constraints

- Python 3.12+, Pydantic v2, ruff `line-length = 100`, select `E,F,I,UP,B`; PEP 695 generics.
- "JSON is the source of truth. Markdown documents are rendered from JSON." Every table, list, number, and diagram in `comparison.md` comes from `comparison.json`; the model writes only `{% prose %}` blocks.
- Every artifact carries `schema_version`, `produced_by`, `produced_at`, `inputs_hash`; an empty `inputs_hash` marks a stopped phase stale so a later run resumes.
- "Secrets never live in the engagement"; model text that reaches disk passes through `redact_text`. No absolute paths in artifacts.
- "One bad file never kills a run": a failed model call is recorded in `comparison/failures.json` and the document still renders with what exists. Only invalid configuration, an unreachable backend after retries, the budget cap, and disk write failure stop a run.
- Exit codes: 0 success, 1 completed with recorded failures, 2 configuration or backend error, 3 budget cap reached.
- `unvarnish compare [--force]`: "Run the cross-tool phase. Works with one tool (skips matrix and proposal)."
- Spec 6.10: capability normalisation is "One call over all tools' capabilities"; integration map and risk table are "Pure JSON joins, no model"; consolidation "Only when two or more tools. One call".
- Spec 8.6: comparison.md sections are 1. Tools reviewed (one paragraph each), 2. Capability matrix, 3. Integration and data map, 4. Risk comparison table, 5. Consolidation proposal "Explicitly labelled a starting point for the consultant's architecture work."
- Schemas sent to a model go through `strict_schema`; structured calls go through `complete_structured` via `call_structured`.
- Model phase tests run offline. Commit messages end with the session's attribution lines. Lint touched files per task and the whole tree at the end of each task.

## Review Focus

1. **A tool without `tool.json`** (scanner-only run, or its rollup failed) among the compared tools. It must appear in the risk table and the tools-reviewed section flagged "not model-analysed", be absent from the matrix and the proposal, and never crash `compare`. (Task 3: `test_compare_includes_scanner_only_tool`; Task 4: document test.)
2. **Only one tool** in the engagement. Integration map, risk table, and tools-reviewed render; matrix and proposal are skipped with a stated reason; no normalisation or consolidation call is made; exit 0. (Task 3: `test_compare_single_tool_skips_matrix_and_proposal`; Task 5: CLI test.)
3. **Normalisation output that cites unknown capability ids or omits some capabilities.** Unknown references are dropped and counted; omitted capabilities become their own rows flagged unmapped so nothing a tool can do disappears from the matrix. (Task 1: `test_build_matrix_drops_unknown_and_appends_unmapped`.)
4. **The same store or external system named with different case or spacing across tools** must merge into one integration row. (Task 1: `test_integration_map_merges_case_and_spacing`.)
5. **The consolidation call fails** (malformed output three times). `comparison.json` is still written without a proposal, the document renders the proposal section with a fallback sentence, the failure is recorded, and `compare` exits 1. (Task 3: `test_compare_records_failed_consolidation`; Task 5: CLI exit code test.)
6. **`compare` before any tool has been run** (no inventory). A clear error and exit 2, not a traceback. (Task 5: `test_compare_before_run_exits_2`.)

## File Structure

Created:

- `src/unvarnish/schemas/comparison.py` — `CapabilityRef`, `NormalisedCapability`, `CapabilityNormalisation` (model output), `MatrixCell`, `MatrixRow`, `IntegrationEntry`, `IntegrationRow`, `RiskRow`, `AbstractRequirement`, `ApproachRecommendation`, `Consolidation` (model output), `ToolSummary`, `Comparison` (artifact).
- `src/unvarnish/analysis/comparison.py` — pure joins: `build_matrix`, `integration_map`, `risk_row`, `tool_summary`, `normalise_name`.
- `src/unvarnish/model/prompts/compare_normalise_system.md`, `compare_consolidate_system.md`, `src/unvarnish/model/prompts/compare.py`.
- `src/unvarnish/phases/compare.py` — `EngagementContext`, `ToolInputs`, `load_tool_inputs`, `ComparePhase`, `RenderComparisonPhase`, `run_comparison`.
- `src/unvarnish/render/comparison.py` — `build_comparison_context`, `integration_diagram`.
- `src/unvarnish/render/templates/comparison.md.j2`.
- `tests/test_comparison_joins.py`, `tests/test_compare_prompts.py`, `tests/test_compare_phase.py`, `tests/test_render_comparison.py`, `tests/test_cli_compare.py`.

Modified:

- `src/unvarnish/engagement.py` — `comparison_file`, `comparison_doc`, `comparison_render_state`, `comparison_failures` properties.
- `src/unvarnish/render/prose.py` — two new blocks: `tools_reviewed`, `consolidation_proposal`.
- `src/unvarnish/phases/render.py` — `override_dirs(root, config)` helper so the comparison renderer shares template overrides.
- `src/unvarnish/cli.py` — `compare` command; comparison rows in `status`.
- `README.md`, `scripts/smoke.sh`.

---

### Task 1: Comparison schemas, paths, and pure joins

**Files:**
- Create: `src/unvarnish/schemas/comparison.py`, `src/unvarnish/analysis/comparison.py`
- Modify: `src/unvarnish/engagement.py`
- Test: `tests/test_comparison_joins.py`

**Interfaces:**
- Consumes: `Capability`, `ToolModel`, `DataStore`, `ExternalSystem` (slice 3 `schemas/toolmodel.py`); `Census`, `Metrics`, `GitStats`, `ScannerFindings`, `ModelFindings`, `Dependencies`; `merged_findings`, `ai_indicators` from `render/findings.py`; `Classification`; `strict_schema`.
- Produces (schemas): `CapabilityRef(tool, capability_id)`, `NormalisedCapability(name, description, actor, members: list[CapabilityRef])`, `CapabilityNormalisation(capabilities: list[NormalisedCapability])`, `MatrixCell(tool, labels: list[str])`, `MatrixRow(name, description, actor, cells, tools_covering: int, unmapped: bool = False)`, `IntegrationEntry(tool, kind, direction: str | None, description)`, `IntegrationRow(name, category: Literal["data_store","external_system"], entries, tools: list[str])`, `RiskRow(tool, model_analysed, files_analysed, source_lines, largest_file_lines, tests_present, secrets_current, secrets_history, bus_factor: int | None, top_author_share: float | None, findings_by_severity: dict[str, int], critical_or_high, ai_indicators, dependency_vulnerabilities: int | None)`, `AbstractRequirement(statement, serves: list[str])`, `ApproachRecommendation(capability, recommended_tool, rationale)`, `Consolidation(union_capabilities: list[str], abstract_requirements, recommended_approach, gaps: list[str], open_questions: list[str])`, `ToolSummary(tool, purpose: str | None, actors: list[str], capabilities: int, source_lines, model_analysed)`, `Comparison(tools, tools_with_model, summaries, capability_matrix, unmapped_capabilities: int, dropped_references: int, integration_map, risk_table, consolidation: Consolidation | None, skipped_reason: str | None, backend: str | None, model: str | None, usage: Usage, prompt_version: str | None, stopped_for_budget: bool = False)`.
- Produces (joins, `unvarnish.analysis.comparison`): `normalise_name(s: str) -> str` (lowercase, collapsed whitespace, stripped punctuation at ends), `capability_label(c: Capability) -> str`, `build_matrix(norm: CapabilityNormalisation | None, caps_by_tool: dict[str, list[Capability]]) -> tuple[list[MatrixRow], int, int]` (rows, unmapped count, dropped reference count), `integration_map(models: dict[str, ToolModel]) -> list[IntegrationRow]`, `risk_row(tool, census, metrics, git, scan, model_findings, deps) -> RiskRow`, `tool_summary(tool, tm: ToolModel | None, census) -> ToolSummary`.
- Produces (paths): `Engagement.comparison_file`, `.comparison_doc`, `.comparison_render_state`, `.comparison_failures` under `comparison/`.

- [ ] **Step 1: Write the failing tests**

`tests/test_comparison_joins.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_comparison_joins.py -q 2>&1 | tail -3`
Expected: FAIL at import (`ModuleNotFoundError: No module named 'unvarnish.analysis.comparison'`).

- [ ] **Step 3: Write the schemas and paths**

`src/unvarnish/schemas/comparison.py`:

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.cost import Usage


class CapabilityRef(BaseModel):
    tool: str
    capability_id: str


class NormalisedCapability(BaseModel):
    name: str
    description: str
    actor: str
    members: list[CapabilityRef] = Field(default_factory=list)


class CapabilityNormalisation(BaseModel):
    """Model output: every tool's capabilities grouped into cross-tool capabilities."""

    capabilities: list[NormalisedCapability] = Field(default_factory=list)


class MatrixCell(BaseModel):
    tool: str
    labels: list[str] = Field(default_factory=list)  # "actor can action object" per member


class MatrixRow(BaseModel):
    name: str
    description: str
    actor: str
    cells: list[MatrixCell]
    tools_covering: int
    unmapped: bool = False  # a tool capability the model did not place in any group


class IntegrationEntry(BaseModel):
    tool: str
    kind: str
    direction: str | None = None
    description: str


class IntegrationRow(BaseModel):
    name: str
    category: Literal["data_store", "external_system"]
    entries: list[IntegrationEntry]
    tools: list[str]


class RiskRow(BaseModel):
    tool: str
    model_analysed: bool
    files_analysed: int
    source_lines: int
    largest_file_lines: int
    tests_present: bool
    secrets_current: int
    secrets_history: int
    bus_factor: int | None
    top_author_share: float | None
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    critical_or_high: int = 0
    ai_indicators: int = 0
    dependency_vulnerabilities: int | None = None


class AbstractRequirement(BaseModel):
    statement: str
    serves: list[str] = Field(default_factory=list)  # tool names whose users it serves


class ApproachRecommendation(BaseModel):
    capability: str
    recommended_tool: str
    rationale: str


class Consolidation(BaseModel):
    """Model output: a starting point for the consultant's consolidation architecture."""

    union_capabilities: list[str] = Field(default_factory=list)
    abstract_requirements: list[AbstractRequirement] = Field(default_factory=list)
    recommended_approach: list[ApproachRecommendation] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)


class ToolSummary(BaseModel):
    tool: str
    purpose: str | None
    actors: list[str] = Field(default_factory=list)
    capabilities: int = 0
    source_lines: int = 0
    model_analysed: bool = False


class Comparison(BaseModel):
    """Artifact comparison/comparison.json."""

    tools: list[str]
    tools_with_model: list[str]
    summaries: list[ToolSummary]
    capability_matrix: list[MatrixRow] = Field(default_factory=list)
    unmapped_capabilities: int = 0
    dropped_references: int = 0
    integration_map: list[IntegrationRow] = Field(default_factory=list)
    risk_table: list[RiskRow] = Field(default_factory=list)
    consolidation: Consolidation | None = None
    skipped_reason: str | None = None
    backend: str | None = None
    model: str | None = None
    usage: Usage = Field(default_factory=Usage)
    prompt_version: str | None = None
    stopped_for_budget: bool = False
```

In `src/unvarnish/engagement.py`, after the `cost_file` property:

```python
    @property
    def comparison_file(self) -> Path:
        return self.comparison_dir / "comparison.json"

    @property
    def comparison_doc(self) -> Path:
        return self.comparison_dir / "comparison.md"

    @property
    def comparison_render_state(self) -> Path:
        return self.comparison_dir / "render-state.json"

    @property
    def comparison_failures(self) -> Path:
        return self.comparison_dir / "failures.json"
```

- [ ] **Step 4: Write the joins**

`src/unvarnish/analysis/comparison.py`:

```python
from __future__ import annotations

import re

from unvarnish.analysis.languages import Classification
from unvarnish.render.findings import ai_indicators, merged_findings
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    IntegrationEntry,
    IntegrationRow,
    MatrixCell,
    MatrixRow,
    RiskRow,
    ToolSummary,
)
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import Capability, ToolModel
from unvarnish.schemas.verify import ModelFindings

_EDGE_PUNCT = re.compile(r"^[\W_]+|[\W_]+$")


def normalise_name(s: str) -> str:
    return _EDGE_PUNCT.sub("", " ".join(s.lower().split()))


def capability_label(c: Capability) -> str:
    return f"{c.actor} can {c.action} {c.object}"


def build_matrix(norm: CapabilityNormalisation | None,
                 caps_by_tool: dict[str, list[Capability]]) -> tuple[list[MatrixRow], int, int]:
    """Matrix rows from the model's grouping; unplaced capabilities become their own rows.

    Returns (rows, unmapped capability count, dropped unknown-reference count). Every row has
    exactly one cell per tool, in `caps_by_tool` order, so the table renders rectangular.
    """
    tools = list(caps_by_tool)
    by_id = {(t, c.id): c for t, caps in caps_by_tool.items() for c in caps}
    placed: set[tuple[str, str]] = set()
    rows: list[MatrixRow] = []
    dropped = 0
    for group in (norm.capabilities if norm else []):
        members: dict[str, list[str]] = {t: [] for t in tools}
        for ref in group.members:
            cap = by_id.get((ref.tool, ref.capability_id))
            if cap is None or (ref.tool, ref.capability_id) in placed:
                dropped += 1
                continue
            placed.add((ref.tool, ref.capability_id))
            members[ref.tool].append(capability_label(cap))
        if not any(members.values()):
            continue
        rows.append(MatrixRow(
            name=group.name, description=group.description, actor=group.actor,
            cells=[MatrixCell(tool=t, labels=members[t]) for t in tools],
            tools_covering=sum(1 for t in tools if members[t])))
    unmapped = 0
    for t in tools:
        for cap in caps_by_tool[t]:
            if (t, cap.id) in placed:
                continue
            unmapped += 1
            rows.append(MatrixRow(
                name=capability_label(cap), description=cap.description, actor=cap.actor,
                cells=[MatrixCell(tool=u, labels=[capability_label(cap)] if u == t else [])
                       for u in tools],
                tools_covering=1, unmapped=True))
    return rows, unmapped, dropped


def integration_map(models: dict[str, ToolModel]) -> list[IntegrationRow]:
    """Stores and external systems joined across tools by normalised name; shared first."""
    groups: dict[tuple[str, str], IntegrationRow] = {}
    for tool, tm in models.items():
        items = [("data_store", s.name, s.kind, None, s.description) for s in tm.data_stores]
        items += [("external_system", x.name, x.kind, x.direction, x.description)
                  for x in tm.external_systems]
        for category, name, kind, direction, description in items:
            key = (category, normalise_name(name))
            row = groups.get(key)
            if row is None:
                row = groups[key] = IntegrationRow(name=name.strip(), category=category,
                                                   entries=[], tools=[])
            row.entries.append(IntegrationEntry(tool=tool, kind=kind, direction=direction,
                                                description=description))
            if tool not in row.tools:
                row.tools.append(tool)
    return sorted(groups.values(), key=lambda r: (-len(r.tools), r.category, r.name.lower()))


def risk_row(tool: str, census: Census, metrics: Metrics, git: GitStats, scan: ScannerFindings,
             model_findings: ModelFindings | None, deps: Dependencies) -> RiskRow:
    live = [f for f in census.files if not f.excluded]
    findings = merged_findings(scan.findings, model_findings.findings if model_findings else [])
    by_sev = {sev.value: n for sev in Severity
              if (n := sum(1 for f in findings if f.severity == sev))}
    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    history = [f for f in secrets if f.title.endswith("in git history")]
    return RiskRow(
        tool=tool, model_analysed=model_findings is not None,
        files_analysed=sum(1 for f in live if f.classification != Classification.binary),
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        largest_file_lines=max((m.lines for m in metrics.files), default=0),
        tests_present=any(f.classification == Classification.test for f in live),
        secrets_current=len(secrets) - len(history), secrets_history=len(history),
        bus_factor=git.bus_factor, top_author_share=git.top_author_share,
        findings_by_severity=by_sev,
        critical_or_high=by_sev.get("critical", 0) + by_sev.get("high", 0),
        ai_indicators=len(ai_indicators(git)),
        dependency_vulnerabilities=len(deps.advisories) if deps.advisories_checked else None,
    )


def tool_summary(tool: str, tm: ToolModel | None, census: Census) -> ToolSummary:
    live = [f for f in census.files if not f.excluded]
    return ToolSummary(
        tool=tool, purpose=tm.purpose if tm else None,
        actors=[a.name for a in tm.actors] if tm else [],
        capabilities=len(tm.capabilities) if tm else 0,
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        model_analysed=tm is not None,
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_comparison_joins.py -q 2>&1 | tail -3`
Expected: all PASS. (`render/findings.py` imports `phases.base`, which imports `engagement`; `analysis/comparison.py` importing `render.findings` is therefore fine and creates no cycle because nothing in `phases.base` or `engagement` imports `analysis.comparison`.)

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/schemas/comparison.py src/unvarnish/analysis/comparison.py src/unvarnish/engagement.py tests/test_comparison_joins.py
git add src/unvarnish/schemas/comparison.py src/unvarnish/analysis/comparison.py src/unvarnish/engagement.py tests/test_comparison_joins.py
git commit -m "feat: comparison schemas, engagement comparison paths, and pure cross-tool joins"
```

---

### Task 2: Normalisation and consolidation prompts

**Files:**
- Create: `src/unvarnish/model/prompts/compare_normalise_system.md`, `src/unvarnish/model/prompts/compare_consolidate_system.md`, `src/unvarnish/model/prompts/compare.py`
- Test: `tests/test_compare_prompts.py`

**Interfaces:**
- Consumes: `Capability`, `capability_label`, `MatrixRow`, `IntegrationRow`, `ToolSummary`, `CapabilityNormalisation`, `Consolidation`, `strict_schema`, `CompletionRequest`, `Message`.
- Produces: `COMPARE_PROMPT_VERSION = "2026-10-17.1"`, `NORMALISE_MAX_TOKENS = 16_000`, `CONSOLIDATE_MAX_TOKENS = 16_000`, `build_normalise_system() -> str`, `build_consolidate_system() -> str`, `capability_line(tool, c: Capability) -> str` (`"<tool> | <id> | <label> | <description> | implicit"`), `build_normalise_request(caps_by_tool: dict[str, list[Capability]], effort, system=None) -> CompletionRequest` (schema_name `"CapabilityNormalisation"`), `build_consolidate_request(summaries: Sequence[ToolSummary], matrix: Sequence[MatrixRow], integration: Sequence[IntegrationRow], effort, system=None) -> CompletionRequest` (schema_name `"Consolidation"`).

- [ ] **Step 1: Write the failing tests**

`tests/test_compare_prompts.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_compare_prompts.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.model.prompts.compare'`.

- [ ] **Step 3: Write the system prompts**

`src/unvarnish/model/prompts/compare_normalise_system.md`:

```markdown
You are the capability normalisation stage of Unvarnish, a tool that vets internally built
software for a consultant who is deciding whether several similar tools can become one.

You receive every capability of every tool under review, one per line:
`tool | capability_id | actor can action object | description | implicit`. Group capabilities
that accomplish the same thing for the same kind of user into one cross-tool capability, even
when the tools name them differently. Produce one JSON object. Do not add commentary outside the
JSON.

## Rules

- Every capability belongs to at most one group. Cite members by tool and capability_id exactly
  as given; never invent ids.
- A group may have members from one tool only when nothing comparable exists elsewhere, but
  prefer leaving a one-tool capability out of your output (it is kept as its own row) to
  forcing a weak match.
- name: a short, neutral name for what the capability accomplishes (not any one tool's wording).
- description: one sentence in plain language.
- actor: the kind of user who needs it, normalised across tools (for example "finance staff"
  rather than three different role names).

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

`src/unvarnish/model/prompts/compare_consolidate_system.md`:

```markdown
You are the consolidation stage of Unvarnish, a tool that vets internally built software for a
consultant who must propose whether and how several similar tools become one.

You receive a summary of each tool, the cross-tool capability matrix (which tool covers which
capability and how), and the integration and data map (which stores and external systems each
tool touches). Produce a consolidation proposal as one JSON object. It is explicitly a starting
point for the consultant's own architecture work, not a finished design. Do not add commentary
outside the JSON.

## What to produce

- union_capabilities: every distinct capability a consolidated tool would need, one line each,
  drawn from the matrix. Nothing a current tool does may silently disappear.
- abstract_requirements: requirements stated independently of any current implementation,
  written to serve the widest population of users across the tools. serves lists the tools
  whose users each requirement covers.
- recommended_approach: for each capability covered by more than one tool, which tool's
  approach is soundest and why, judged on what the matrix and integration map show (data
  handling, external dependencies, implicit rules). Name the tool exactly as given.
- gaps: capabilities or data needs that no current tool covers well, and conflicts between tools
  (two sources of truth for the same data, incompatible rules).
- open_questions: what the consultant must settle with stakeholders before designing: ownership,
  volumes, which rules are intentional, which integrations must survive.

Plain language throughout; the reader does not code. Do not soften conflicts between tools.

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

- [ ] **Step 4: Write the builders**

`src/unvarnish/model/prompts/compare.py`:

```python
from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from pydantic import BaseModel

from unvarnish.analysis.comparison import capability_label
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    Consolidation,
    IntegrationRow,
    MatrixRow,
    ToolSummary,
)
from unvarnish.schemas.toolmodel import Capability

COMPARE_PROMPT_VERSION = "2026-10-17.1"  # bump whenever either compare prompt changes
NORMALISE_MAX_TOKENS = 16_000
CONSOLIDATE_MAX_TOKENS = 16_000
DESCRIPTION_CHARS = 300


@cache
def _system(template_name: str, schema_cls: type[BaseModel]) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath(template_name)
                .read_text(encoding="utf-8"))
    return template.replace("{{SCHEMA}}", json.dumps(strict_schema(schema_cls), indent=1,
                                                     sort_keys=True))


def build_normalise_system() -> str:
    return _system("compare_normalise_system.md", CapabilityNormalisation)


def build_consolidate_system() -> str:
    return _system("compare_consolidate_system.md", Consolidation)


def capability_line(tool: str, c: Capability) -> str:
    desc = " ".join(c.description.split())[:DESCRIPTION_CHARS]
    flag = "implicit" if c.implicit else "designed"
    return f"{tool} | {c.id} | {capability_label(c)} | {desc} | {flag}"


def build_normalise_request(caps_by_tool: dict[str, list[Capability]], effort: str | None,
                            system: str | None = None) -> CompletionRequest:
    parts: list[str] = []
    for tool, caps in caps_by_tool.items():
        parts.append(f"## {tool} ({len(caps)} capabilities)")
        parts.extend(capability_line(tool, c) for c in caps)
        parts.append("")
    return CompletionRequest(system=system or build_normalise_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="CapabilityNormalisation", effort=effort,
                             cache_system=True, max_tokens=NORMALISE_MAX_TOKENS)


def build_consolidate_request(summaries: Sequence[ToolSummary], matrix: Sequence[MatrixRow],
                              integration: Sequence[IntegrationRow], effort: str | None,
                              system: str | None = None) -> CompletionRequest:
    parts = ["## Tools"]
    for s in summaries:
        actors = ", ".join(s.actors) or "unknown actors"
        parts.append(f"- {s.tool}: {s.purpose or 'purpose not analysed'} (actors: {actors}; "
                     f"{s.capabilities} capabilities; {s.source_lines:,} source lines)")
    parts += ["", "## Capability matrix"]
    for row in matrix:
        cells = "; ".join(f"{c.tool}: {', '.join(c.labels) if c.labels else '-'}"
                          for c in row.cells)
        flag = " (unmapped: one tool only)" if row.unmapped else ""
        parts.append(f"- {row.name} [{row.actor}]{flag}: {row.description} | {cells}")
    parts += ["", "## Integration and data map"]
    for r in integration:
        parts.append(f"- {r.name} [{r.category}]: {', '.join(r.tools)}")
        parts.extend(f"  - {e.tool}: {e.kind}{' ' + e.direction if e.direction else ''}; "
                     f"{' '.join(e.description.split())[:DESCRIPTION_CHARS]}"
                     for e in r.entries)
    return CompletionRequest(system=system or build_consolidate_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="Consolidation", effort=effort, cache_system=True,
                             max_tokens=CONSOLIDATE_MAX_TOKENS)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_compare_prompts.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/model/prompts/compare.py tests/test_compare_prompts.py
git add src/unvarnish/model/prompts/compare_normalise_system.md src/unvarnish/model/prompts/compare_consolidate_system.md src/unvarnish/model/prompts/compare.py tests/test_compare_prompts.py
git commit -m "feat: capability normalisation and consolidation prompts"
```

---

### Task 3: The engagement-level compare phase

**Files:**
- Create: `src/unvarnish/phases/compare.py`
- Test: `tests/test_compare_phase.py`

**Interfaces:**
- Consumes: Task 1 schemas and joins; Task 2 builders; `call_structured`, `BudgetTracker`, `BudgetExceeded`, `record_cost`, `resolve_backend`/`resolve_model_ref`/`NoModelConfigured`; `PhaseRunner`, `PhaseResult`, `PhaseStatus`, `is_fresh` (duck-typed: they only call `outputs(ctx)`, `inputs_hash(ctx)`, `run(ctx)`); `read_artifact`/`write_artifact`/`hash_files`/`hash_inputs`; `Failures`, `FailureRecord`.
- Produces:
  - `EngagementContext(engagement: Engagement, budget: BudgetTracker)` dataclass with `config` property.
  - `ToolInputs(tool, census, metrics, git, scan, deps, tool_model: ToolModel | None, model_findings: ModelFindings | None)`; `load_tool_inputs(eng, tool) -> ToolInputs | None` (None when the tool has no inventory yet).
  - `ENGAGEMENT_TOOL = "(engagement)"` (the `tool` value in cost and failure records).
  - `merge_engagement_failures(eng, phase, items) -> None`.
  - `class ComparePhase(backend=None)`: `name = "compare"`, `inputs_hash(ectx)`, `outputs(ectx) = [eng.comparison_file]`, `run(ectx) -> PhaseResult`.
  - `class RenderComparisonPhase(backend=None)` stub in this task is NOT created here; Task 4 adds it. This task adds `run_comparison(eng, *, force=False, backend=None, budget=None) -> list[PhaseResult]` running `[ComparePhase]` only; Task 4 extends the list.

- [ ] **Step 1: Write the failing tests**

`tests/test_compare_phase.py`:

```python
import json

from tests.stub_backend import StubBackend
from tests.test_render_documents import _phases, _stub
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.compare import (
    ENGAGEMENT_TOOL,
    ComparePhase,
    EngagementContext,
    load_tool_inputs,
    run_comparison,
)
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.comparison import Comparison
from unvarnish.schemas.cost import Usage

CONSOLIDATION = json.dumps({
    "union_capabilities": ["export reports", "bypass approval"],
    "abstract_requirements": [{"statement": "Finance can export a report",
                               "serves": ["alpha", "beta"]}],
    "recommended_approach": [{"capability": "export reports", "recommended_tool": "alpha",
                              "rationale": "single data store"}],
    "gaps": ["no audit trail"], "open_questions": ["who owns the data?"],
})


def _normalise(req) -> str:
    """Group capability lines with the same label across tools."""
    groups: dict[str, list[dict]] = {}
    for line in req.messages[0].content.splitlines():
        if " | " not in line:
            continue
        tool, cid, label, _desc, _flag = [p.strip() for p in line.split(" | ")]
        groups.setdefault(label, []).append({"tool": tool, "capability_id": cid})
    return json.dumps({"capabilities": [
        {"name": label.title(), "description": "d", "actor": "staff", "members": members}
        for label, members in groups.items()]})


def _compare_stub(**over) -> StubBackend:
    stub = _stub(CapabilityNormalisation=_normalise, Consolidation=CONSOLIDATION)
    stub.replies.update(over)
    return stub


def _two_tools(engagement: Engagement, synthetic_repo, stub, *, model_for=("alpha", "beta")):
    for name in ("alpha", "beta"):
        ingest_tool(engagement, name, str(synthetic_repo), "repo")
        ctx = build_context(engagement, name, budget=BudgetTracker(None))
        phases = _phases(stub) if name in model_for else [InventoryPhase(), GitPhase(),
                                                           ScanPhase()]
        results = PhaseRunner(phases).run(ctx)
        assert all(r.status == PhaseStatus.ok for r in results), name
    return EngagementContext(engagement=engagement, budget=BudgetTracker(None))


def test_load_tool_inputs_none_before_inventory(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    assert load_tool_inputs(engagement, "alpha") is None


def test_compare_two_tools(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok and not res.failures, res
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools == ["alpha", "beta"] == cmp.tools_with_model
    shared = next(r for r in cmp.capability_matrix if r.name == "Admin Can Export Report")
    assert shared.tools_covering == 2 and not shared.unmapped
    assert cmp.unmapped_capabilities == 0 and cmp.dropped_references == 0
    db = next(r for r in cmp.integration_map if r.name == "expenses db")
    assert db.tools == ["alpha", "beta"] and db.category == "data_store"
    assert [r.tool for r in cmp.risk_table] == ["alpha", "beta"]
    assert all(r.model_analysed for r in cmp.risk_table)
    assert cmp.consolidation and cmp.consolidation.gaps == ["no audit trail"]
    assert cmp.skipped_reason is None and cmp.backend == "stub"
    assert stub.count("CapabilityNormalisation") == 1 and stub.count("Consolidation") == 1
    assert is_fresh(ComparePhase(backend=stub), ectx)
    assert cmp.usage.total() > 0


def test_compare_single_tool_skips_matrix_and_proposal(engagement, synthetic_repo):
    stub = _compare_stub()
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    ectx = EngagementContext(engagement=engagement, budget=BudgetTracker(None))
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.capability_matrix == [] and cmp.consolidation is None
    assert cmp.skipped_reason and "one tool" in cmp.skipped_reason
    assert len(cmp.risk_table) == 1 and len(cmp.integration_map) >= 1
    assert stub.count("CapabilityNormalisation") == 0 and stub.count("Consolidation") == 0


def test_compare_includes_scanner_only_tool(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.tools == ["alpha", "beta"] and cmp.tools_with_model == ["alpha"]
    beta = next(r for r in cmp.risk_table if r.tool == "beta")
    assert not beta.model_analysed and beta.secrets_history == 2
    assert next(s for s in cmp.summaries if s.tool == "beta").purpose is None
    assert cmp.capability_matrix == [] and "one tool" in (cmp.skipped_reason or "")
    assert stub.count("CapabilityNormalisation") == 0


def test_compare_records_failed_consolidation(engagement, synthetic_repo):
    stub = _compare_stub(Consolidation="garbage")
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.ok and res.failures
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.consolidation is None and cmp.capability_matrix  # matrix survived
    assert "consolidation" in (cmp.skipped_reason or "").lower()
    items = read_artifact(engagement.comparison_failures, Failures).data.items
    assert items and items[0].phase == "compare" and items[0].unit_id == "consolidation"
    assert is_fresh(ComparePhase(backend=stub), ectx)  # a recorded failure is a result


def test_compare_without_model_uses_per_tool_rows(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    res = ComparePhase().run(ectx)  # no injected backend, no models configured
    assert res.status == PhaseStatus.ok
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.capability_matrix and all(r.unmapped for r in cmp.capability_matrix)
    assert cmp.consolidation is None and "no model configured" in (cmp.skipped_reason or "")
    assert cmp.backend is None


def test_compare_budget_stop(engagement, synthetic_repo):
    stub = _compare_stub()
    ectx = _two_tools(engagement, synthetic_repo, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ectx = EngagementContext(engagement=engagement, budget=tracker)
    res = ComparePhase(backend=stub).run(ectx)
    assert res.status == PhaseStatus.stopped
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.stopped_for_budget and cmp.consolidation is None
    assert not is_fresh(ComparePhase(backend=stub), ectx)


def test_compare_before_any_run_fails_clearly(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    res = ComparePhase().run(EngagementContext(engagement=engagement,
                                                budget=BudgetTracker(None)))
    assert res.status == PhaseStatus.failed and "unvarnish run" in (res.message or "")


def test_run_comparison_records_cost_under_engagement(engagement, synthetic_repo):
    from unvarnish.model.budget import load_ledger

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    results = run_comparison(engagement, backend=stub)
    assert results[0].phase == "compare" and results[0].status == PhaseStatus.ok
    entries = [e for e in load_ledger(engagement).entries if e.phase == "compare"]
    assert entries and entries[0].tool == ENGAGEMENT_TOOL
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_compare_phase.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.phases.compare'`.

- [ ] **Step 3: Write the phase**

`src/unvarnish/phases/compare.py`:

```python
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.comparison import build_matrix, integration_map, risk_row, tool_summary
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.compare import (
    COMPARE_PROMPT_VERSION,
    build_consolidate_request,
    build_normalise_request,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseRunner, PhaseStatus
from unvarnish.phases.modelrun import call_structured
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.comparison import (
    CapabilityNormalisation,
    Comparison,
    Consolidation,
)
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.compare")
ENGAGEMENT_TOOL = "(engagement)"


@dataclass
class EngagementContext:
    engagement: Engagement
    budget: BudgetTracker

    @property
    def config(self) -> EngagementConfig:
        return self.engagement.config


@dataclass
class ToolInputs:
    tool: str
    census: Census
    metrics: Metrics
    git: GitStats
    scan: ScannerFindings
    deps: Dependencies
    tool_model: ToolModel | None
    model_findings: ModelFindings | None


def _optional[T](path: Path, cls: type[T]) -> T | None:
    if not path.exists():
        return None
    try:
        return read_artifact(path, cls).data  # type: ignore[arg-type]
    except Exception as exc:
        log.warning("ignoring unreadable %s: %r", path.name, exc)
        return None


def load_tool_inputs(eng: Engagement, tool: str) -> ToolInputs | None:
    """Everything compare needs for one tool, or None when the tool has not been run."""
    p = eng.tool_paths(tool)
    if not (p.census.exists() and p.metrics.exists() and p.scanner_findings.exists()
            and p.dependencies.exists()):
        return None
    git = (read_artifact(p.git, GitStats).data if p.git.exists()
           else GitStats(tool=tool, available=False, reason="git phase has not run"))
    return ToolInputs(
        tool=tool, census=read_artifact(p.census, Census).data,
        metrics=read_artifact(p.metrics, Metrics).data, git=git,
        scan=read_artifact(p.scanner_findings, ScannerFindings).data,
        deps=read_artifact(p.dependencies, Dependencies).data,
        tool_model=_optional(p.tool_model, ToolModel),
        model_findings=_optional(p.model_findings, ModelFindings),
    )


def merge_engagement_failures(eng: Engagement, phase: str, items: list[FailureRecord]) -> None:
    existing: list[FailureRecord] = []
    if eng.comparison_failures.exists():
        try:
            existing = read_artifact(eng.comparison_failures, Failures).data.items
        except Exception:
            log.warning("comparison/failures.json unreadable; rewriting it")
    kept = [f for f in existing if f.phase != phase]
    write_artifact(eng.comparison_failures, Failures(tool=ENGAGEMENT_TOOL, items=kept + items),
                   produced_by=phase, inputs_hash="")


class ComparePhase:
    name = "compare"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, eng: Engagement) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(eng, self.name)
        except NoModelConfigured:
            return None

    def _inputs(self, eng: Engagement) -> list[Path]:
        out: list[Path] = []
        for tool in eng.tool_names():
            p = eng.tool_paths(tool)
            out += [p.census, p.metrics, p.git, p.dependencies, p.scanner_findings,
                    p.tool_model, p.model_findings]
        return out

    def inputs_hash(self, ectx: EngagementContext) -> str:
        eng = ectx.engagement
        ref = resolve_model_ref(eng.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files(self._inputs(eng)), ",".join(eng.tool_names()),
                            model_part, COMPARE_PROMPT_VERSION])

    def outputs(self, ectx: EngagementContext) -> list[Path]:
        return [ectx.engagement.comparison_file]

    def run(self, ectx: EngagementContext) -> PhaseResult:
        eng = ectx.engagement
        inputs = [i for t in eng.tool_names() if (i := load_tool_inputs(eng, t)) is not None]
        if not inputs:
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="no tool has been analysed yet; run `unvarnish run` first")
        models = {i.tool: i.tool_model for i in inputs if i.tool_model is not None}
        caps_by_tool = {t: tm.capabilities for t, tm in models.items()}
        backend = self._resolve(eng)
        ref = resolve_model_ref(eng.config, self.name)
        effort = ref.effort if ref else None
        budget = ectx.budget
        usage = Usage()
        failures: list[FailureRecord] = []
        stopped = False
        stop = threading.Event()
        norm: CapabilityNormalisation | None = None
        consolidation: Consolidation | None = None
        skipped: list[str] = []

        def call[T](req, cls: type[T], item: str) -> T | None:
            nonlocal usage, stopped
            try:
                budget.check()
            except BudgetExceeded:
                stopped = True
                return None
            res, failure = call_structured(backend, req, cls, phase=self.name, item_id=item,
                                           path=None, stop=stop)
            if res is None:
                if failure:
                    failures.append(failure)
                return None
            usage = usage + res.usage
            budget.add(res.usage)
            return res.parsed

        if len(models) < 2:
            skipped.append("one tool with a tool model: matrix and proposal skipped"
                           if models else "no tool has a tool model: matrix and proposal skipped")
        elif backend is None:
            skipped.append("no model configured: capabilities are listed per tool, "
                           "no grouping or proposal")
        else:
            norm = call(build_normalise_request(caps_by_tool, effort), CapabilityNormalisation,
                        "normalisation")
            if norm is None and not stopped:
                skipped.append("capability normalisation failed: capabilities listed per tool")

        if len(models) >= 2:
            matrix, unmapped, dropped = build_matrix(norm, caps_by_tool)
        else:
            matrix, unmapped, dropped = [], 0, 0
        integration = integration_map(models)
        summaries = [tool_summary(i.tool, i.tool_model, i.census) for i in inputs]
        risk = [risk_row(i.tool, i.census, i.metrics, i.git, i.scan, i.model_findings, i.deps)
                for i in inputs]

        if len(models) >= 2 and backend is not None and not stopped:
            consolidation = call(
                build_consolidate_request(summaries, matrix, integration, effort),
                Consolidation, "consolidation")
            if consolidation is None and not stopped:
                skipped.append("consolidation proposal failed: see comparison/failures.json")

        cmp = Comparison(
            tools=[i.tool for i in inputs], tools_with_model=list(models), summaries=summaries,
            capability_matrix=matrix, unmapped_capabilities=unmapped,
            dropped_references=dropped, integration_map=integration, risk_table=risk,
            consolidation=consolidation, skipped_reason="; ".join(skipped) or None,
            backend=backend.name if backend else None, model=backend.model if backend else None,
            usage=usage, prompt_version=COMPARE_PROMPT_VERSION, stopped_for_budget=stopped,
        )
        eng.comparison_dir.mkdir(parents=True, exist_ok=True)
        write_artifact(eng.comparison_file, cmp, produced_by=self.name,
                       inputs_hash="" if stopped else self.inputs_hash(ectx))
        if usage.total() and backend is not None:
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase=self.name,
                                       backend=backend.name, model=backend.model, usage=usage,
                                       at=datetime.now(UTC)))
        merge_engagement_failures(eng, self.name, failures)
        msg = (f"{len(inputs)} tools ({len(models)} with a tool model), "
               f"{len(matrix)} matrix rows, {len(integration)} shared systems/stores, "
               f"{'proposal written' if consolidation else 'no proposal'}, "
               f"{usage.total():,} tokens")
        if stopped:
            msg = "budget cap reached: " + msg
        log.info("compare: %s", msg)
        return PhaseResult(phase=self.name,
                           status=PhaseStatus.stopped if stopped else PhaseStatus.ok,
                           message=msg, failures=[f"{f.unit_id}: {f.error}" for f in failures])


def comparison_phases(backend: Backend | None = None) -> list:
    return [ComparePhase(backend)]


def run_comparison(eng: Engagement, *, force: bool = False, backend: Backend | None = None,
                   budget: BudgetTracker | None = None) -> list[PhaseResult]:
    ectx = EngagementContext(engagement=eng,
                             budget=budget or BudgetTracker(eng.config.budget.max_tokens))
    return PhaseRunner(comparison_phases(backend)).run(ectx, force=force)  # type: ignore[arg-type]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_compare_phase.py -q 2>&1 | tail -3`
Expected: all PASS. If `test_compare_two_tools` fails on `"Admin Can Export Report"`, check the label the stub builds: `capability_line` writes `admin can export report` and the stub title-cases it.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/phases/compare.py tests/test_compare_phase.py
git add src/unvarnish/phases/compare.py tests/test_compare_phase.py
git commit -m "feat: engagement-level compare phase producing comparison.json"
```

---

### Task 4: Render comparison.md

**Files:**
- Create: `src/unvarnish/render/comparison.py`, `src/unvarnish/render/templates/comparison.md.j2`
- Modify: `src/unvarnish/render/prose.py` (two blocks), `src/unvarnish/phases/render.py` (`override_dirs`), `src/unvarnish/phases/compare.py` (`RenderComparisonPhase`, `comparison_phases`)
- Test: `tests/test_render_comparison.py`

**Interfaces:**
- Consumes: `Comparison`, `Diagram`/`Node`/`Edge`/`to_mermaid`, `generate_prose`, `prose_block_names`, `make_env`, `render_document`, `template_source_hash`, `PROSE_PROMPT_VERSION`, `RenderState`, `cell` filter.
- Produces: `BLOCKS["tools_reviewed"]`, `BLOCKS["consolidation_proposal"]`; `override_dirs(root: Path, config: EngagementConfig) -> list[Path]` in `phases/render.py` (with `template_override_dirs(ctx)` delegating to it); `integration_diagram(cmp: Comparison, max_rows: int = 40) -> Diagram`; `build_comparison_context(eng, cmp) -> dict` with keys `client, consultant, generated_at, cmp, tools, matrix_rows (list of {name, actor, cells: list[str], covered, unmapped}), risk_measures (list of {label, values: list[str]}), integration_mermaid, analysis_mode, prose_facts`; `RenderComparisonPhase(backend=None)` with `name = "render_comparison"`, outputs `[comparison_render_state, comparison_doc]`; `comparison_phases(backend)` returns `[ComparePhase, RenderComparisonPhase]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_render_comparison.py`:

```python
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
    results = run_comparison(engagement, backend=stub)
    assert [r.phase for r in results] == ["compare", "render_comparison"]
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    doc = engagement.comparison_doc.read_text()
    assert doc.startswith("# Acme: Tool Comparison")
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
    assert stub.count("prose") == 2
    again = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.skipped for r in again)  # fresh


def test_comparison_document_single_tool_states_skips(engagement, synthetic_repo):
    stub = _compare_stub()
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    results = run_comparison(engagement, backend=stub)
    assert all(r.status == PhaseStatus.ok for r in results)
    doc = engagement.comparison_doc.read_text()
    assert "Skipped: one tool with a tool model" in doc
    assert "No consolidation proposal" in doc
    assert stub.count("prose") == 1  # tools_reviewed only


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
    assert d.note and "10 of 50" in d.note
    assert len(d.edges) == 10
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_render_comparison.py -q 2>&1 | tail -3`
Expected: FAIL with `ImportError: cannot import name 'RenderComparisonPhase'`.

- [ ] **Step 3: Add the prose blocks and the override helper**

In `src/unvarnish/render/prose.py`, add to the `BLOCKS` tuple:

```python
    ProseBlock("tools_reviewed", (
        "Write one paragraph per tool, in the order given, each starting with the tool's name: "
        "what it is for, who uses it, how big it is, and whether it was model-analysed. Flag "
        "any tool that was not model-analysed so the reader knows its row in the matrix is "
        "missing."), 600),
    ProseBlock("consolidation_proposal", (
        "Write the consolidation proposal in three or four short paragraphs from the facts: "
        "what one tool would have to do (the union of capabilities), which current approach "
        "to keep for each contested capability and why, the gaps and conflicts between the "
        "tools, and the questions to settle before designing. State plainly that this is a "
        "starting point for the consultant's architecture work, not a design."), 450),
```

In `src/unvarnish/phases/render.py`, replace `template_override_dirs`:

```python
def override_dirs(root: Path, config: EngagementConfig) -> list[Path]:
    dirs = [root / "templates"]
    if config.report.templates_dir:
        dirs.append(Path(config.report.templates_dir))
    dirs.append(user_config_path().parent / "templates")
    return dirs


def template_override_dirs(ctx: ToolContext) -> list[Path]:
    return override_dirs(ctx.engagement.root, ctx.config)
```

and import `EngagementConfig` from `unvarnish.config`.

- [ ] **Step 4: Write the context builder and the diagram**

`src/unvarnish/render/comparison.py`:

```python
from __future__ import annotations

from unvarnish.engagement import Engagement
from unvarnish.render.diagram import Diagram, Edge, Node, to_mermaid
from unvarnish.render.findings import generated_at
from unvarnish.schemas.comparison import Comparison


def integration_diagram(cmp: Comparison, max_rows: int = 40) -> Diagram:
    rows = cmp.integration_map[:max_rows]
    nodes = [Node(id=f"tool:{t}", label=t, kind="tool") for t in cmp.tools_with_model]
    edges: list[Edge] = []
    for i, r in enumerate(rows):
        nid = f"sys{i}"
        nodes.append(Node(id=nid, label=r.name,
                          kind="store" if r.category == "data_store" else "external"))
        for e in r.entries:
            edges.append(Edge(source=f"tool:{e.tool}", target=nid, label=e.kind))
    note = (f"Showing the {len(rows)} most shared of {len(cmp.integration_map)} systems."
            if len(cmp.integration_map) > max_rows else None)
    return Diagram(title="integration map", nodes=nodes, edges=edges, note=note)


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


def _risk_measures(cmp: Comparison) -> list[dict]:
    rows = cmp.risk_table
    severities = ("critical", "high", "medium", "low", "info")
    measures: list[tuple[str, list[str]]] = [
        ("Model analysis", ["yes" if r.model_analysed else "**no**" for r in rows]),
        ("Files analysed", [f"{r.files_analysed:,}" for r in rows]),
        ("Source lines", [f"{r.source_lines:,}" for r in rows]),
        ("Largest file (lines)", [f"{r.largest_file_lines:,}" for r in rows]),
        ("Automated tests", ["present" if r.tests_present else "**none**" for r in rows]),
        ("Secrets in working tree", [str(r.secrets_current) for r in rows]),
        ("Secrets in history", [str(r.secrets_history) for r in rows]),
        ("Bus factor", ["—" if r.bus_factor is None else str(r.bus_factor) for r in rows]),
        ("Top author share", [_pct(r.top_author_share) for r in rows]),
        ("Critical or high findings", [str(r.critical_or_high) for r in rows]),
    ]
    measures += [(f"Findings: {sev}", [str(r.findings_by_severity.get(sev, 0)) for r in rows])
                 for sev in severities if any(r.findings_by_severity.get(sev) for r in rows)]
    measures += [
        ("AI tooling indicators", [str(r.ai_indicators) for r in rows]),
        ("Dependency vulnerabilities", ["not checked" if r.dependency_vulnerabilities is None
                                        else str(r.dependency_vulnerabilities) for r in rows]),
    ]
    return [{"label": label, "values": values} for label, values in measures]


def build_comparison_context(eng: Engagement, cmp: Comparison) -> dict:
    matrix_rows = [{
        "name": r.name, "actor": r.actor, "unmapped": r.unmapped, "covered": r.tools_covering,
        "cells": ["; ".join(c.labels) if c.labels else "—" for c in r.cells],
    } for r in cmp.capability_matrix]
    analysis_mode = f"{cmp.backend}/{cmp.model}" if cmp.backend else "scanners only"
    prose_facts = {
        "tools_reviewed": {
            "client": eng.config.client,
            "tools": [s.model_dump() for s in cmp.summaries],
            "risk": [r.model_dump() for r in cmp.risk_table],
        },
        "consolidation_proposal": {
            "tools": [s.tool for s in cmp.summaries],
            "consolidation": cmp.consolidation.model_dump() if cmp.consolidation else None,
            "shared_capabilities": [r.name for r in cmp.capability_matrix
                                    if r.tools_covering > 1],
            "single_tool_capabilities": [r.name for r in cmp.capability_matrix
                                         if r.tools_covering == 1],
            "shared_systems": [r.name for r in cmp.integration_map if len(r.tools) > 1],
        },
    }
    return {
        "client": eng.config.client, "consultant": eng.config.consultant,
        "generated_at": generated_at(), "cmp": cmp, "tools": cmp.tools,
        "matrix_tools": cmp.tools_with_model, "matrix_rows": matrix_rows,
        "risk_measures": _risk_measures(cmp),
        "integration_mermaid": to_mermaid(integration_diagram(cmp)),
        "analysis_mode": analysis_mode, "prose_facts": prose_facts,
    }
```

- [ ] **Step 5: Write the template**

`src/unvarnish/render/templates/comparison.md.j2`:

```jinja
# {{ client or "Engagement" }}: Tool Comparison

**Prepared by:** {{ consultant or "—" }} · **Generated:** {{ generated_at }} · **Tools:** {% for t in tools %}`{{ t }}`{{ ", " if not loop.last }}{% endfor %}

{{ "" }}
> Rendered from `comparison/comparison.json`. Prose sections are model-written ({{ analysis_mode }});
> every table and diagram is generated directly from the per-tool analysis. Tools without a model
> analysis appear in the risk table only.
{% if cmp.skipped_reason %}

Skipped: {{ cmp.skipped_reason }}.
{% endif %}

## 1. Tools reviewed

{% prose "tools_reviewed" %}{{ "" }}

| Tool | Purpose | Actors | Capabilities | Source lines | Model analysis |
|---|---|---|---:|---:|---|
{% for s in cmp.summaries %}
| `{{ s.tool }}` | {{ s.purpose | cell if s.purpose else "*not model-analysed*" }} | {{ s.actors | join(", ") | cell if s.actors else "—" }} | {{ s.capabilities }} | {{ s.source_lines | fmt_int }} | {{ "yes" if s.model_analysed else "**no**" }} |
{% endfor %}

## 2. Capability matrix

{% if not matrix_rows %}
No capability matrix{% if cmp.skipped_reason %} ({{ cmp.skipped_reason }}){% endif %}.
{% else %}
| Capability | Actor | {% for t in matrix_tools %}{{ t }} | {% endfor %}Covered by |
|---|---|{% for t in matrix_tools %}---|{% endfor %}---:|
{% for r in matrix_rows %}
| {{ r.name | cell }}{{ " \\*" if r.unmapped else "" }} | {{ r.actor | cell }} | {% for c in r.cells %}{{ c | cell }} | {% endfor %}{{ r.covered }} |
{% endfor %}
{% if cmp.unmapped_capabilities %}

\* {{ cmp.unmapped_capabilities }} capabilit{{ "y" if cmp.unmapped_capabilities == 1 else "ies" }} could not be grouped with anything in another tool and {{ "is" if cmp.unmapped_capabilities == 1 else "are" }} listed on {{ "its" if cmp.unmapped_capabilities == 1 else "their" }} own.
{% endif %}
{% if cmp.dropped_references %}

{{ cmp.dropped_references }} reference(s) the model made to capabilities that do not exist were dropped.
{% endif %}
{% endif %}

## 3. Integration and data map

```mermaid
{{ integration_mermaid }}
```

| System | Category | Tools | Details |
|---|---|---|---|
{% for r in cmp.integration_map %}
| {{ r.name | cell }} | {{ r.category | replace("_", " ") }} | {{ r.tools | join(", ") }} | {% for e in r.entries %}{{ e.tool }}: {{ e.kind }}{% if e.direction %} {{ e.direction }}{% endif %}{{ "; " if not loop.last }}{% endfor %} |
{% else %}
| — | — | — | No stores or external systems identified |
{% endfor %}

## 4. Risk comparison

| Measure | {% for t in tools %}{{ t }} | {% endfor %}
|---|{% for t in tools %}---:|{% endfor %}
{% for m in risk_measures %}
| {{ m.label }} | {% for v in m.values %}{{ v }} | {% endfor %}
{% endfor %}

## 5. Consolidation proposal

> This proposal is a starting point for the consultant's architecture work, generated from the
> matrix, the integration map, and the tool models. It is not a design.

{% if cmp.consolidation %}
{% prose "consolidation_proposal" %}{{ "" }}

### Union of capabilities

{% for c in cmp.consolidation.union_capabilities %}
- {{ c | cell }}
{% else %}
- None listed.
{% endfor %}

### Abstract requirements

| Requirement | Serves users of |
|---|---|
{% for r in cmp.consolidation.abstract_requirements %}
| {{ r.statement | cell }} | {{ r.serves | join(", ") if r.serves else "—" }} |
{% else %}
| None listed | — |
{% endfor %}

### Recommended approach per capability

| Capability | Keep the approach of | Why |
|---|---|---|
{% for r in cmp.consolidation.recommended_approach %}
| {{ r.capability | cell }} | {{ r.recommended_tool | cell }} | {{ r.rationale | cell }} |
{% else %}
| None listed | — | — |
{% endfor %}

### Gaps and conflicts

{% for g in cmp.consolidation.gaps %}
- {{ g | cell }}
{% else %}
- None listed.
{% endfor %}

### Open questions

{% for q in cmp.consolidation.open_questions %}
- {{ q | cell }}
{% else %}
- None listed.
{% endfor %}
{% else %}
No consolidation proposal{% if cmp.skipped_reason %}: {{ cmp.skipped_reason }}{% endif %}.
{% endif %}
```

- [ ] **Step 6: Add the render phase**

Append to `src/unvarnish/phases/compare.py` (and add the imports it needs: `hashlib`, `make_env`, `prose_block_names`, `render_document`, `template_source_hash` from `unvarnish.render.markdown`, `generate_prose`, `PROSE_PROMPT_VERSION` from `unvarnish.render.prose`, `build_comparison_context` from `unvarnish.render.comparison`, `override_dirs` from `unvarnish.phases.render`, `RenderState` from `unvarnish.schemas.render`):

```python
class RenderComparisonPhase:
    name = "render_comparison"
    TEMPLATE = "comparison.md.j2"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, eng: Engagement) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(eng, self.name)
        except NoModelConfigured:
            return None

    def _env(self, eng: Engagement):
        return make_env(override_dirs(eng.root, eng.config))

    def inputs_hash(self, ectx: EngagementContext) -> str:
        eng = ectx.engagement
        ref = resolve_model_ref(eng.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files([eng.comparison_file]),
                            template_source_hash(self._env(eng), self.TEMPLATE),
                            eng.config.client or "", eng.config.consultant or "",
                            eng.config.report.tone, PROSE_PROMPT_VERSION, model_part])

    def outputs(self, ectx: EngagementContext) -> list[Path]:
        return [ectx.engagement.comparison_render_state, ectx.engagement.comparison_doc]

    def run(self, ectx: EngagementContext) -> PhaseResult:
        eng = ectx.engagement
        cmp = read_artifact(eng.comparison_file, Comparison).data
        env = self._env(eng)
        backend = self._resolve(eng)
        ref = resolve_model_ref(eng.config, self.name)
        effort = ref.effort if ref else None
        context = build_comparison_context(eng, cmp)
        names = prose_block_names(env, self.TEMPLATE)
        if cmp.consolidation is None:
            names = [n for n in names if n != "consolidation_proposal"]  # inside a false branch
        facts = {n: context["prose_facts"].get(n, {}) for n in names}
        prose = generate_prose(backend, facts, tone=eng.config.report.tone, effort=effort,
                               budget=ectx.budget)
        if cmp.consolidation is None:
            prose.text.setdefault("consolidation_proposal", "")
        doc = render_document(env, self.TEMPLATE, {**context, "prose": prose.text})
        eng.comparison_doc.write_text(doc)
        merge_engagement_failures(eng, self.name, prose.failures)
        write_artifact(eng.comparison_render_state,
                       RenderState(tool=ENGAGEMENT_TOOL, documents={
                           eng.comparison_doc.name: hashlib.sha256(doc.encode()).hexdigest()}),
                       produced_by=self.name,
                       inputs_hash="" if prose.stopped_for_budget else self.inputs_hash(ectx))
        if prose.usage.total() and backend is not None:
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase=self.name,
                                       backend=backend.name, model=backend.model,
                                       usage=prose.usage, at=datetime.now(UTC)))
        msg = f"wrote {eng.comparison_doc.name}"
        if prose.usage.total():
            msg += f" ({prose.usage.total():,} tokens of prose)"
        status = PhaseStatus.stopped if prose.stopped_for_budget else PhaseStatus.ok
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.unit_id}: {f.error}" for f in prose.failures])
```

and change `comparison_phases` to `return [ComparePhase(backend), RenderComparisonPhase(backend)]`.

The `{% prose "consolidation_proposal" %}` tag sits inside `{% if cmp.consolidation %}`; `prose_block_names` finds it anyway, so the phase removes it from the request when there is no proposal (no wasted call) and supplies an empty string so the lookup never fails.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_render_comparison.py tests/test_compare_phase.py tests/test_render_documents.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 8: Lint and commit**

```bash
uv run ruff check src/unvarnish/render src/unvarnish/phases/compare.py src/unvarnish/phases/render.py tests/test_render_comparison.py
git add src/unvarnish/render/comparison.py src/unvarnish/render/templates/comparison.md.j2 src/unvarnish/render/prose.py src/unvarnish/phases/render.py src/unvarnish/phases/compare.py tests/test_render_comparison.py
git commit -m "feat: render comparison.md with matrix, integration map, risk table, and proposal"
```

---

### Task 5: `compare` command, status rows, docs, smoke

**Files:**
- Modify: `src/unvarnish/cli.py`, `tests/fake_llm.py` (export `request_schema`), `README.md`, `scripts/smoke.sh`
- Test: `tests/test_cli_compare.py`

**Interfaces:**
- Consumes: `run_comparison`, `EngagementContext`, `comparison_phases`, `is_fresh`, `BudgetTracker`, `setup_run_logging`.
- Produces: `unvarnish compare [--force] [-v] [-e DIR]` with exit codes 0/1/2/3; `status` appends `(engagement)` rows for `compare` and `render_comparison`; `tests.fake_llm.request_schema(body) -> dict | None` (public alias of `_request_schema`).

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_compare.py`:

```python
import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import fill_schema, request_schema
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()


def _engagement(tmp_path, synthetic_repo, fake, tools=("alpha", "beta")) -> Engagement:
    eng = Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham Technologies")
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **model_config(fake)})
    eng.save_config()
    for name in tools:
        ingest_tool(eng, name, str(synthetic_repo), "repo")
    return eng


def test_compare_before_run_exits_2(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 2 and "unvarnish run" in out.output


def test_compare_two_tools_end_to_end(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert eng.comparison_doc.exists() and eng.comparison_file.exists()
    doc = eng.comparison_doc.read_text()
    assert "| Measure | alpha | beta |" in doc
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert "(engagement)" in status.output and "render_comparison" in status.output
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "compare" in cost.output and "(engagement)" in cost.output
    again = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert again.exit_code == 0 and "fresh" in again.output


def test_compare_single_tool_exits_0(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm, tools=("alpha",))
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert "Skipped: one tool" in eng.comparison_doc.read_text()


def test_compare_failed_consolidation_exits_1(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    filled = lambda body: json.dumps(fill_schema(request_schema(body)))  # noqa: E731
    fake_llm.script(filled, "garbage", "garbage", "garbage")  # normalise ok; consolidation fails
    out = runner.invoke(app, ["compare", "-e", str(eng.root)])
    assert out.exit_code == 1, out.output
    assert "recorded failure" in out.output
    assert json.loads(eng.comparison_file.read_text())["data"]["consolidation"] is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli_compare.py -q 2>&1 | tail -3`
Expected: FAIL with `ImportError: cannot import name 'request_schema'` (and `compare` is not a command).

- [ ] **Step 3: Implement**

In `tests/fake_llm.py`, add after `_request_schema`:

```python
request_schema = _request_schema  # public name for tests that script schema-filled replies
```

In `src/unvarnish/cli.py`:

1. Import `from unvarnish.phases.compare import EngagementContext, comparison_phases, run_comparison`.

2. Add the command after `run`:

```python
@app.command()
def compare(
    force: bool = typer.Option(False, "--force", help="Rerun even if fresh."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detail on the console."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Compare every analysed tool: capability matrix, integration map, risk table, proposal."""
    eng = _load_engagement(engagement)
    _select_tools(eng, None)  # exits 2 when the engagement has no tools
    log_path = setup_run_logging(eng, verbose)
    try:
        results = run_comparison(eng, force=force,
                                 budget=BudgetTracker(eng.config.budget.max_tokens))
    except (BackendConfigError, BackendUnavailable) as exc:
        err_console.print(f"[red]error:[/red] {exc}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    table = Table("phase", "status", "detail", title="compare")
    any_failed = any_stopped = False
    for r in results:
        colour = {"ok": "green", "skipped": "dim", "failed": "red", "stopped": "yellow"}[r.status]
        detail = r.message or ""
        if r.failures:
            detail += f" [yellow]({len(r.failures)} recorded failure(s))[/yellow]"
            any_failed = True
        any_failed = any_failed or r.status == PhaseStatus.failed
        any_stopped = any_stopped or r.status == PhaseStatus.stopped
        table.add_row(r.phase, f"[{colour}]{r.status}[/{colour}]", detail)
    console.print(table)
    console.print(f"Log: {log_path}")
    if results and results[0].status == PhaseStatus.failed and "unvarnish run" in (
            results[0].message or ""):
        err_console.print(f"[red]error:[/red] {results[0].message}")
        raise typer.Exit(code=2)
    if any_stopped:
        err_console.print("Budget cap reached; rerun [cyan]unvarnish compare[/cyan] to resume.")
        raise typer.Exit(code=3)
    if any_failed:
        err_console.print("Compare completed with recorded failures; see comparison/failures.json.")
        raise typer.Exit(code=1)
```

3. In `status`, after the per-tool loop and before `console.print(table)`:

```python
    ectx = EngagementContext(engagement=eng, budget=BudgetTracker(None))
    for p in comparison_phases():
        table.add_row("(engagement)", p.name, _phase_cell(p, ectx))
```

(`_phase_cell` reaches its generic freshness branch for these two names; it never touches `ctx.paths` there.)

4. In `README.md`, add after the Documents section:

```markdown
## Comparing tools

    unvarnish compare           # after `run` on the tools you want compared

Writes `comparison/comparison.json` and `comparison/comparison.md`: one paragraph per tool, a
capability matrix (one model call groups every tool's capabilities into cross-tool rows;
anything it cannot group stays as its own row), an integration and data map (pure join of the
tools' stores and external systems), a risk comparison table (pure join of the per-tool
numbers), and, for two or more model-analysed tools, a consolidation proposal (one model call).
Tools that were run without a model appear in the risk table and are flagged. With one tool the
matrix and proposal are skipped and the document says so. The proposal is labelled a starting
point for your own architecture work.
```

5. In `scripts/smoke.sh`, add a second tool and the comparison after the run:

```bash
uv run unvarnish add scanners --files "$(dirname "$0")/../src/unvarnish/scanners" -e "$E"
uv run unvarnish add render --files "$(dirname "$0")/../src/unvarnish/render" -e "$E"
```

(replacing the single `add self` line) and, after `unvarnish run`:

```bash
uv run unvarnish compare -e "$E"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest -q 2>&1 | tail -2`
Expected: whole suite PASSES.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check .
git add src/unvarnish/cli.py tests/fake_llm.py tests/test_cli_compare.py README.md scripts/smoke.sh
git commit -m "feat: compare command, engagement rows in status, docs and smoke"
```

---

## Self-review notes

**Spec coverage.** 3 (`compare [--force]`, works with one tool: Task 5, Task 3). 4 (`comparison/comparison.json`, `comparison.md`: Task 1 paths, Tasks 3–4). 5.3 (`Comparison`, `MatrixRow`, `IntegrationRow`, `RiskRow`, `Consolidation` with union, abstract requirements, recommended approach, gaps, open questions: Task 1). 6.10 (normalisation one call; integration map and risk table pure joins; consolidation one call only for two or more tools; renders comparison.md: Tasks 3–4). 8.6 (five sections, "starting point" label: Task 4). 6.11/6.12 (budget shared via `EngagementContext`, cache via `CachingBackend`, freshness via `inputs_hash`: Task 3). 13 (failures recorded in `comparison/failures.json`, run continues: Task 3).

**Known deviations, to ledger at execution.** Spec 6.10 says compare "runs when at least one tool has `tool.json`"; this plan also runs it with no tool model at all so the risk table and tools-reviewed section are available on a scanner-only engagement (the matrix and proposal are skipped with a stated reason). `RiskRow` is a richer "by the numbers" shape than the spec names. The consultant-constraints input (spec 17) is not added. `run` does not chain `compare`; the CLI keeps them separate as the spec's command list does.

**Type consistency checked.** `build_matrix` return triple used identically in Tasks 1 and 3. `ToolSummary`, `MatrixRow`, `IntegrationRow` field names match across Tasks 1, 2 (prompt builders), 3, 4 (template). `EngagementContext.budget` consumed by both phases and the CLI. `comparison_phases(backend)` returns one phase in Task 3 and two in Task 4; Task 5's `status` uses the final list. The `_compare_stub` and `_two_tools` helpers are defined in Task 3's test module and imported by Task 4's tests. The prose stub in `tests/test_render_documents.py` returns `"PROSE " + first 40 chars of the instruction`, so the Task 4 assertions use the first words of the two new block instructions ("Write one paragraph per tool" and "Write the consolidation proposal").
