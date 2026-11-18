# Unvarnish Slice 3: Rollups, Verification, and Full Documents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the per-unit extractions from slice 2 into module and tool models, verify high-severity model findings independently, and render all three per-tool documents (architecture, findings, requirements) with model-written prose blocks and Mermaid diagrams.

**Architecture:** Three new model phases (`rollup_modules`, `rollup_tool`, `verify`) reuse the slice 2 structured-output machinery through one small shared helper (`phases/modelrun.py`: error mapping, parallel execution against a budget shared across the whole run). `render` becomes a three-document phase: Jinja templates own structure, a `{% prose "name" %}` tag marks the blocks a model writes from a JSON facts payload, and diagrams are a tiny node/edge model emitted as Mermaid. Everything is offline-testable with an in-process stub backend; an env-gated scale test runs the full pipeline on a real repository (ESCAPESUITE) with schema-filled fake replies.

**Tech Stack:** Python 3.12+, Pydantic v2, Jinja2 (custom extension), Typer/Rich, anthropic + openai SDKs (unchanged), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` (sections 5.2, 6.7, 6.8, 6.9, 6.11, 6.12, 8, 10, 13, 14, 16 slice 3). Slice 2 plan for the code this builds on: `docs/superpowers/plans/2026-10-17-unvarnish-slice2-model-layer.md`.

## Global Constraints

- Python 3.12+, Pydantic v2, ruff `line-length = 100`, select `E,F,I,UP,B`; PEP 695 generics (`def f[T](...)`), never `TypeVar`.
- "JSON is the source of truth. Markdown documents are rendered from JSON." Every number, table, list, and diagram in a document comes from JSON; the model writes only designated prose blocks.
- "Every artifact carries `schema_version`, `produced_by`, `produced_at`, and `inputs_hash`." Use `write_artifact`/`read_artifact`; an empty `inputs_hash` marks a phase as stale so a later run resumes.
- "Secrets never live in the engagement." Prompts and artifacts may carry the redacted excerpts already stored in findings, never raw secrets; nothing from the environment is written to disk.
- "Absolute paths are never stored." Evidence paths are relative POSIX paths inside the tool (enforced by `Evidence`).
- "One bad file never kills a run." Per-module and per-finding model failures go to `failures.json` and the run continues; only invalid configuration, an unreachable backend after retries, the budget cap, and disk write failure stop a run.
- Exit codes: 0 success, 1 completed with recorded failures, 2 configuration or backend error, 3 budget cap reached.
- Budget cap (`budget.max_tokens`) is per run across every model phase and tool, not per phase.
- Category taxonomy is fixed: `security, data_handling, maintainability, reliability, operability, compliance, process, dependency`. Severities: `critical, high, medium, low, info`.
- Tone: `report.tone` is `direct` (default) or `measured`; the direct instruction "state problems plainly, quantify where possible, never hedge or soften a scanner finding, avoid jargon, write for a reader who does not code" and the prompt "forbids phrases that minimise ('minor', 'simply', 'just') when describing high or critical findings."
- Model responses go through `CachingBackend` (content-addressed); structured calls go through `complete_structured` (retry, repair, `StructuredOutputError`). Schemas sent to models must be built with `strict_schema` (no unsupported keywords).
- Model phase tests run offline. No test may call a real backend.
- `tree-sitter>=0.23,<0.26` stays pinned. No new runtime dependencies in this slice (Graphviz SVG rendering is slice 6).
- Every commit message ends with the attribution lines from the session's system reminder.
- Lint only the files a task touches (`uv run ruff check <files>`), then the whole tree at the end of each task.

## Review Focus

The spec implies these inputs but no task's tests exercised them when this plan was first drafted; each now has a pinned test in the owning task.

1. **A module whose units all failed extraction or whose artifacts are missing.** `rollup_modules` must skip it with a recorded reason and the documents must list it under "Not analysed"; it must not crash or produce an empty rollup. (Task 4: `test_rollup_skips_modules_without_units`; Task 9: findings appendix test.)
2. **A tool with more modules than fit one rollup call (ESCAPESUITE has about 1,000).** The tool rollup must chunk by directory, every module must still be covered, and the architecture document must say chunks were used. (Task 5: `test_rollup_tool_hierarchical_when_over_budget`.)
3. **Model findings that cite a path that is not a known module, or lines outside the file.** They must be dropped and counted, never turned into an `Evidence` that fails validation during render. (Task 4: `test_to_module_findings_drops_out_of_range`; Task 5: `test_tool_findings_drop_unknown_paths`.)
4. **A verification call that fails (refusal, malformed output) for a critical finding.** The finding is kept, shown as unverified with its original severity, the failure is recorded, and the run exits 1 not 2. (Task 6: `test_verify_keeps_finding_when_verification_fails`.)
5. **A template override naming an unknown prose block, or a model refusing a prose block.** The document still renders with a fallback sentence in that block and a recorded failure; no document goes missing. (Task 8: `test_generate_prose_unknown_block_falls_back`; Task 9: `test_render_override_with_unknown_prose_block`.)
6. **No model configured at all (slice 1 mode).** `render` still writes `findings.md` with scanner findings only and does not write the other two documents. (Task 9: `test_render_without_model_writes_findings_only`.)

## File Structure

Created:

- `src/unvarnish/schemas/rollup.py` — `module_file_id`, `ModuleRollup` (model output), `Module` (artifact), `ModuleDigest`, `ModulesIndex`.
- `src/unvarnish/schemas/toolmodel.py` — `Actor`, `EntryPoint`, `DataStore`, `ExternalSystem`, `ModuleMapEntry`, `DataFlow`, `CapabilityOut`, `Capability`, `capability_id`, `BusinessRule`, `ToolCandidateFinding`, `DirectoryRollup`, `ToolRollup` (model outputs), `ToolModel` (artifact `tool.json`), `DataInventoryRow`, `RequirementsInventory` (artifact `capabilities.json`).
- `src/unvarnish/schemas/verify.py` — `Verdict` (model output), `ModelFindings` (artifact `findings.json`).
- `src/unvarnish/phases/modelrun.py` — `call_structured`, `ItemOutcome`, `ParallelOutcome`, `run_parallel`, `merge_failures`.
- `src/unvarnish/model/prompts/rollup_module_system.md`, `rollup_directory_system.md`, `rollup_tool_system.md`, `verify_system.md`, `prose_system.md`.
- `src/unvarnish/model/prompts/rollup.py` — rollup prompt builders and `ToolFacts`.
- `src/unvarnish/model/prompts/verify.py` — verification prompt builder.
- `src/unvarnish/phases/rollup_modules.py`, `rollup_tool.py`, `verify.py` — the three phases.
- `src/unvarnish/render/diagram.py` — `Diagram` model, `to_mermaid`, `context_diagram`, `module_diagram`.
- `src/unvarnish/render/prose.py` — prose blocks, tone instructions, `generate_prose`.
- `src/unvarnish/render/inputs.py` — `RenderInputs`, `load_render_inputs`.
- `src/unvarnish/render/architecture.py`, `requirements.py` — context builders.
- `src/unvarnish/render/templates/architecture.md.j2`, `requirements.md.j2`.
- `tests/stub_backend.py` — in-process `StubBackend`.
- `tests/test_schemas_slice3.py`, `test_modelrun.py`, `test_rollup_prompts.py`, `test_rollup_modules.py`, `test_rollup_tool.py`, `test_verify.py`, `test_diagram.py`, `test_prose.py`, `test_render_documents.py`, `test_scale.py`.

Modified:

- `src/unvarnish/engagement.py` — new `ToolPaths` attributes.
- `src/unvarnish/config.py` — `PipelineConfig.rollup_input_tokens`.
- `src/unvarnish/schemas/finding.py` — `Finding.verification_note`.
- `src/unvarnish/phases/base.py` — `ToolContext.budget`, `build_context(..., budget=)`.
- `src/unvarnish/phases/extract.py` — shared budget, `merge_failures`.
- `src/unvarnish/phases/render.py` — three documents, prose, diagrams.
- `src/unvarnish/render/findings.py` — merged scanner + model findings, appendix, prose facts.
- `src/unvarnish/render/markdown.py` — `ProseExtension`, `prose_block_names`.
- `src/unvarnish/render/templates/findings.md.j2` — executive summary, badges, appendix.
- `src/unvarnish/phases/__init__.py` — phase order.
- `src/unvarnish/model/estimate.py` — per-phase estimates.
- `src/unvarnish/cli.py` — dry-run estimates, status cells.
- `tests/fake_llm.py` — `fill_schema`, `autofill`.
- `README.md`.

---

### Task 1: Schemas, paths, config, shared budget

**Files:**
- Create: `src/unvarnish/schemas/rollup.py`, `src/unvarnish/schemas/toolmodel.py`, `src/unvarnish/schemas/verify.py`, `tests/stub_backend.py`
- Modify: `src/unvarnish/engagement.py` (ToolPaths), `src/unvarnish/config.py` (PipelineConfig), `src/unvarnish/schemas/finding.py` (Finding), `src/unvarnish/phases/base.py` (ToolContext, build_context), `src/unvarnish/phases/extract.py` (budget line in `run`), `src/unvarnish/cli.py` (`run`)
- Test: `tests/test_schemas_slice3.py`

**Interfaces:**
- Consumes: `CandidateFinding`, `UnitResult`, `Usage`, `Finding`, `Evidence`, `Category`, `Severity` (slice 2); `strict_schema`; `BudgetTracker`.
- Produces: everything listed under File Structure for the three schema modules; `ToolPaths.module_dir`, `.modules_index`, `.tool_model`, `.capabilities`, `.model_findings`, `.architecture_doc`, `.requirements_doc`; `PipelineConfig.rollup_input_tokens: int = 40_000`; `Finding.verification_note: str | None`; `ToolContext.budget: BudgetTracker | None`; `build_context(eng, tool, budget: BudgetTracker | None = None)`; `StubBackend(replies: dict[str, Reply] | None, default: Reply, *, json_schema: bool = True)` with `.requests: list[CompletionRequest]`.

- [ ] **Step 1: Write the failing tests**

`tests/stub_backend.py` (test utility, not a test):

```python
from __future__ import annotations

import threading
from collections.abc import Callable

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse
from unvarnish.schemas.cost import Usage

Reply = str | Exception | Callable[[CompletionRequest], "str | Exception"]


class StubBackend:
    """In-process Backend. Replies are chosen by `req.schema_name` (the pydantic class name
    that complete_structured sets, or "prose" for prose blocks); a reply may be text, an
    exception to raise, or a callable of the request."""

    name = "stub"
    model = "stub-model"

    def __init__(self, replies: dict[str, Reply] | None = None,
                 default: Reply = '{"echo": true}', *, json_schema: bool = True) -> None:
        self.replies = replies or {}
        self.default = default
        self.capabilities = BackendCapabilities(json_schema=json_schema)
        self.requests: list[CompletionRequest] = []
        self._lock = threading.Lock()

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        with self._lock:
            self.requests.append(req)
        reply = self.replies.get(req.schema_name, self.default)
        if callable(reply):
            reply = reply(req)
        if isinstance(reply, Exception):
            raise reply
        return CompletionResponse(text=reply, model=self.model,
                                  usage=Usage(input_tokens=100, output_tokens=20))

    def forget(self, reqs) -> int:
        return 0

    def count(self, schema_name: str) -> int:
        return sum(1 for r in self.requests if r.schema_name == schema_name)
```

`tests/test_schemas_slice3.py`:

```python
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
    assert Finding.model_validate({**f.model_dump(), "verification_note": None}).verification_note is None


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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_schemas_slice3.py -q 2>&1 | tail -5`
Expected: FAIL at import (`ModuleNotFoundError: No module named 'unvarnish.schemas.rollup'`).

- [ ] **Step 3: Write the schema modules**

`src/unvarnish/schemas/rollup.py`:

```python
from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from unvarnish.schemas.analysis import CandidateFinding
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Finding


def module_file_id(path: str) -> str:
    """Stable, file-safe id for a module (a source file path)."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]


class ModuleRollup(BaseModel):
    """Model output for one module (file) over its unit extractions."""

    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    interface: list[str] = Field(default_factory=list)
    dependencies_in: list[str] = Field(default_factory=list)
    dependencies_out: list[str] = Field(default_factory=list)
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class Module(BaseModel):
    """Artifact analysis/modules/<module_file_id>.json."""

    id: str
    tool: str
    path: str
    unit_ids: list[str]
    rollup: ModuleRollup
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class ModuleDigest(BaseModel):
    """Compact row in modules.json: the input to the tool rollup and the module map."""

    id: str
    path: str
    language: str | None = None
    units: int
    lines: int
    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    interface: list[str] = Field(default_factory=list)
    dependencies_out: list[str] = Field(default_factory=list)
    external_systems: list[str] = Field(default_factory=list)
    data_read: list[str] = Field(default_factory=list)
    data_written: list[str] = Field(default_factory=list)
    findings: int = 0


class ModulesIndex(BaseModel):
    tool: str
    modules: list[ModuleDigest] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)  # module paths whose rollup call failed
    skipped: list[str] = Field(default_factory=list)  # modules with no extracted units
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
```

`src/unvarnish/schemas/toolmodel.py`:

```python
from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity


class Actor(BaseModel):
    name: str
    description: str


class EntryPoint(BaseModel):
    name: str
    kind: Literal["http", "cli", "ui", "job", "queue", "library", "other"]
    module: str
    description: str


class DataStore(BaseModel):
    name: str
    kind: Literal["db", "file", "cache", "queue", "object_store", "spreadsheet",
                  "browser_storage", "other"]
    description: str
    modules: list[str] = Field(default_factory=list)


class ExternalSystem(BaseModel):
    name: str
    kind: Literal["http", "db", "queue", "email", "auth", "payment", "storage", "other"]
    direction: Literal["inbound", "outbound", "both"]
    description: str
    modules: list[str] = Field(default_factory=list)


class ModuleMapEntry(BaseModel):
    path: str
    role: str
    depends_on: list[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    source: str
    target: str
    data: str
    via: str | None = None


class CapabilityOut(BaseModel):
    actor: str
    action: str
    object: str
    description: str
    implementing_modules: list[str] = Field(default_factory=list)
    data_touched: list[str] = Field(default_factory=list)
    implicit: bool = False


def capability_id(tool: str, actor: str, action: str, obj: str) -> str:
    key = f"{tool}|{actor.strip().lower()}|{action.strip().lower()}|{obj.strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


class Capability(CapabilityOut):
    id: str
    tool: str
    evidence: list[Evidence] = Field(default_factory=list)  # empty: no known module cited


class BusinessRule(BaseModel):
    description: str
    module: str
    kind: Literal["hardcoded_list", "threshold", "exemption", "mapping", "schedule", "other"]


class ToolCandidateFinding(BaseModel):
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    paths: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)


class DirectoryRollup(BaseModel):
    """Model output over one chunk of module digests when a tool is too big for one call."""

    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    external_systems: list[ExternalSystem] = Field(default_factory=list)
    notable_modules: list[ModuleMapEntry] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    candidate_findings: list[ToolCandidateFinding] = Field(default_factory=list)


class ToolRollup(BaseModel):
    """Model output for the whole tool."""

    purpose: str
    actors: list[Actor] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    external_systems: list[ExternalSystem] = Field(default_factory=list)
    internal_stack: list[str] = Field(default_factory=list)
    module_map: list[ModuleMapEntry] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    deployment_assumptions: list[str] = Field(default_factory=list)
    capabilities: list[CapabilityOut] = Field(default_factory=list)
    business_rules: list[BusinessRule] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    candidate_findings: list[ToolCandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class ToolModel(BaseModel):
    """Artifact analysis/tool.json."""

    tool: str
    purpose: str
    actors: list[Actor]
    entry_points: list[EntryPoint]
    data_stores: list[DataStore]
    external_systems: list[ExternalSystem]
    internal_stack: list[str]
    module_map: list[ModuleMapEntry]
    data_flows: list[DataFlow]
    deployment_assumptions: list[str]
    capabilities: list[Capability]
    business_rules: list[BusinessRule]
    open_questions: list[str]
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    hierarchical: bool = False
    chunks: int = 0
    modules_covered: int = 0
    confidence: float
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class DataInventoryRow(BaseModel):
    name: str
    kind: str
    description: str
    used_by: list[str] = Field(default_factory=list)  # capability ids


class RequirementsInventory(BaseModel):
    """Artifact analysis/capabilities.json: the requirements view of the tool model."""

    tool: str
    actors: list[Actor]
    capabilities: list[Capability]
    data_inventory: list[DataInventoryRow]
    business_rules: list[BusinessRule]
    open_questions: list[str]
```

`src/unvarnish/schemas/verify.py`:

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Finding


class Verdict(BaseModel):
    """Model output of one independent verification call."""

    verdict: Literal["confirmed", "downgraded", "rejected"]
    reason: str


class ModelFindings(BaseModel):
    """Artifact analysis/findings.json: deduplicated model findings after verification."""

    tool: str
    findings: list[Finding] = Field(default_factory=list)
    verified: int = 0
    confirmed: int = 0
    downgraded: int = 0
    rejected: int = 0
    unverified: int = 0
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
```

- [ ] **Step 4: Wire paths, config, Finding, shared budget**

In `src/unvarnish/engagement.py`, add to `ToolPaths.__init__` after `self.extract_state = ...`:

```python
        self.module_dir = self.analysis / "modules"
        self.modules_index = self.analysis / "modules.json"
        self.tool_model = self.analysis / "tool.json"
        self.capabilities = self.analysis / "capabilities.json"
        self.model_findings = self.analysis / "findings.json"
        self.architecture_doc = self.docs / "architecture.md"
        self.requirements_doc = self.docs / "requirements.md"
```

In `src/unvarnish/config.py`, add to `PipelineConfig`:

```python
    rollup_input_tokens: int = 40_000  # module digests per tool-rollup call before chunking
```

In `src/unvarnish/schemas/finding.py`, add to `Finding` after `verification`:

```python
    verification_note: str | None = None  # the verifier's one-line reason
```

In `src/unvarnish/phases/base.py`: add `from unvarnish.model.budget import BudgetTracker` to the imports, add a last field to `ToolContext`:

```python
    budget: BudgetTracker | None = None  # shared across phases and tools for one run
```

and change `build_context`:

```python
def build_context(eng: Engagement, tool: str, budget: BudgetTracker | None = None) -> ToolContext:
    paths = eng.tool_paths(tool)
    meta = load_tool_meta(paths)
    return ToolContext(
        engagement=eng, tool=tool, paths=paths, meta=meta,
        source_root=resolve_source_root(eng, meta), budget=budget,
    )
```

In `src/unvarnish/phases/extract.py` `run`, replace `budget = BudgetTracker(ctx.config.budget.max_tokens)` with:

```python
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
```

In `src/unvarnish/cli.py` `run`, import `BudgetTracker` from `unvarnish.model.budget` and create one tracker before the loop, passing it to every context:

```python
    tracker = BudgetTracker(eng.config.budget.max_tokens)
    for name in names:
        ctx = build_context(eng, name, budget=tracker)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_schemas_slice3.py tests/test_extract_phase.py tests/test_cli_model_commands.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/schemas src/unvarnish/engagement.py src/unvarnish/config.py src/unvarnish/phases/base.py src/unvarnish/phases/extract.py src/unvarnish/cli.py tests/stub_backend.py tests/test_schemas_slice3.py
git add -A src/unvarnish/schemas src/unvarnish/engagement.py src/unvarnish/config.py src/unvarnish/phases/base.py src/unvarnish/phases/extract.py src/unvarnish/cli.py tests/stub_backend.py tests/test_schemas_slice3.py
git commit -m "feat: rollup, tool model, and verification schemas; shared run budget"
```

---

### Task 2: Model-run helper and failure merging

**Files:**
- Create: `src/unvarnish/phases/modelrun.py`
- Modify: `src/unvarnish/phases/extract.py` (`_persist`)
- Test: `tests/test_modelrun.py`

**Interfaces:**
- Consumes: `complete_structured`, `StructuredResult`, `StructuredOutputError`, `ModelRefusal`, `BackendError`, `BackendUnavailable`, `BudgetTracker`, `BudgetExceeded`, `FailureRecord`, `Failures`, `Usage`, `ToolContext`.
- Produces:
  - `call_structured[T](backend, req, model_cls, *, phase: str, item_id: str | None, path: str | None, stop: threading.Event) -> tuple[StructuredResult[T] | None, FailureRecord | None]`
  - `ItemOutcome[T](result: T | None = None, failures: list[FailureRecord] = [], usage: Usage = Usage())`
  - `ParallelOutcome[T](results, failures, usage, processed: int, stopped_for_budget: bool, fatal: BackendUnavailable | None)` with property `stopped`.
  - `run_parallel[I, T](items: Sequence[I], worker: Callable[[I, threading.Event], ItemOutcome[T]], *, workers: int, budget: BudgetTracker) -> ParallelOutcome[T]`
  - `merge_failures(ctx: ToolContext, phase: str, items: list[FailureRecord]) -> None`

- [ ] **Step 1: Write the failing tests**

`tests/test_modelrun.py`:

```python
import threading

import pytest

from tests.stub_backend import StubBackend
from unvarnish.artifacts import read_artifact
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    Message,
    ModelRefusal,
)
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import build_context
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.verify import Verdict


def _req() -> CompletionRequest:
    return CompletionRequest(system="s", messages=[Message(role="user", content="u")])


def test_call_structured_returns_result():
    stub = StubBackend({"Verdict": '{"verdict": "confirmed", "reason": "ok"}'})
    res, failure = call_structured(stub, _req(), Verdict, phase="verify", item_id="f1",
                                   path="a.py", stop=threading.Event())
    assert failure is None and res is not None and res.parsed.verdict == "confirmed"


def test_call_structured_maps_recoverable_errors():
    stop = threading.Event()
    bad = StubBackend({"Verdict": "not json at all"})
    res, failure = call_structured(bad, _req(), Verdict, phase="verify", item_id="f1",
                                   path="a.py", stop=stop)
    assert res is None and failure.phase == "verify" and failure.attempts == 3
    assert failure.unit_id == "f1" and failure.path == "a.py"

    refusing = StubBackend({"Verdict": ModelRefusal("harmful")})
    _, failure = call_structured(refusing, _req(), Verdict, phase="verify", item_id="f1",
                                 path=None, stop=stop)
    assert failure.error == "refused (harmful)"

    erroring = StubBackend({"Verdict": BackendError("400 bad request")})
    _, failure = call_structured(erroring, _req(), Verdict, phase="verify", item_id="f1",
                                 path=None, stop=stop)
    assert "400" in failure.error
    assert not stop.is_set()


def test_call_structured_outage_sets_stop_and_raises():
    stop = threading.Event()
    down = StubBackend({"Verdict": BackendUnavailable("503")})
    with pytest.raises(BackendUnavailable):
        call_structured(down, _req(), Verdict, phase="verify", item_id="x", path=None, stop=stop)
    assert stop.is_set()


def test_run_parallel_stops_at_budget():
    budget = BudgetTracker(150)

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        return ItemOutcome(result=item, usage=Usage(input_tokens=100))

    out = run_parallel([1, 2, 3, 4, 5], worker, workers=1, budget=budget)
    assert out.processed == 2 and out.results == [1, 2]
    assert out.stopped_for_budget and out.stopped and out.fatal is None
    assert out.usage.total() == 200


def test_run_parallel_collects_failures_and_results():
    budget = BudgetTracker(None)

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        if item % 2:
            return ItemOutcome(failures=[FailureRecord(phase="p", error=f"odd {item}")])
        return ItemOutcome(result=item, usage=Usage(output_tokens=1))

    out = run_parallel(list(range(6)), worker, workers=3, budget=budget)
    assert sorted(out.results) == [0, 2, 4]
    assert sorted(f.error for f in out.failures) == ["odd 1", "odd 3", "odd 5"]
    assert out.processed == 6 and not out.stopped


def test_run_parallel_outage_cancels_the_rest():
    seen: list[int] = []

    def worker(item: int, stop: threading.Event) -> ItemOutcome[int]:
        seen.append(item)
        if item == 0:
            stop.set()
            raise BackendUnavailable("down")
        return ItemOutcome(result=item)

    out = run_parallel(list(range(20)), worker, workers=1, budget=BudgetTracker(None))
    assert isinstance(out.fatal, BackendUnavailable)
    assert seen == [0]  # the stop event short-circuited every later item


def test_merge_failures_replaces_only_its_phase(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    merge_failures(ctx, "extract", [FailureRecord(phase="extract", error="e1")])
    merge_failures(ctx, "verify", [FailureRecord(phase="verify", error="v1")])
    merge_failures(ctx, "extract", [FailureRecord(phase="extract", error="e2")])
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert sorted((f.phase, f.error) for f in items) == [("extract", "e2"), ("verify", "v1")]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_modelrun.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.phases.modelrun'`.

- [ ] **Step 3: Write the helper**

`src/unvarnish/phases/modelrun.py`:

```python
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from pydantic import BaseModel

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.model.base import (
    Backend,
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    ModelRefusal,
)
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.model.structured import (
    StructuredOutputError,
    StructuredResult,
    complete_structured,
)
from unvarnish.phases.base import ToolContext
from unvarnish.schemas.analysis import FailureRecord, Failures
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.modelrun")


def call_structured[T: BaseModel](
    backend: Backend, req: CompletionRequest, model_cls: type[T], *, phase: str,
    item_id: str | None, path: str | None, stop: threading.Event,
) -> tuple[StructuredResult[T] | None, FailureRecord | None]:
    """One structured call. Recoverable errors become a FailureRecord; an outage stops the run."""
    try:
        return complete_structured(backend, req, model_cls), None
    except ModelRefusal as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=f"refused ({exc.category})")
    except StructuredOutputError as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=exc.last_error[:500], attempts=exc.attempts)
    except BackendUnavailable:
        stop.set()  # nothing else can succeed; let the other workers drain
        raise
    except BackendError as exc:
        return None, FailureRecord(phase=phase, unit_id=item_id, path=path,
                                   error=str(exc)[:500])


@dataclass
class ItemOutcome[T]:
    result: T | None = None
    failures: list[FailureRecord] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)


@dataclass
class ParallelOutcome[T]:
    results: list[T] = field(default_factory=list)
    failures: list[FailureRecord] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    processed: int = 0
    stopped_for_budget: bool = False
    fatal: BackendUnavailable | None = None

    @property
    def stopped(self) -> bool:
        return self.stopped_for_budget or self.fatal is not None


def run_parallel[I, T](
    items: Sequence[I], worker: Callable[[I, threading.Event], ItemOutcome[T]], *,
    workers: int, budget: BudgetTracker,
) -> ParallelOutcome[T]:
    """Run `worker` over `items` in a thread pool against a shared budget.

    The budget is checked before each item and charged after it. A budget cap or a backend
    outage sets the stop event: pending items are skipped, running ones drain, and the outcome
    records what finished. An interrupt propagates after the pool drains.
    """
    stop = threading.Event()
    budget_hit = threading.Event()
    out: ParallelOutcome[T] = ParallelOutcome()

    def guarded(item: I) -> ItemOutcome[T] | None:
        if stop.is_set():
            return None
        try:
            budget.check()
        except BudgetExceeded:
            budget_hit.set()
            stop.set()
            return None
        result = worker(item, stop)
        budget.add(result.usage)
        return result

    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = [pool.submit(guarded, item) for item in items]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except BackendUnavailable as exc:
                out.fatal = out.fatal or exc
                continue
            if res is None:
                continue
            out.processed += 1
            out.failures.extend(res.failures)
            out.usage = out.usage + res.usage
            if res.result is not None:
                out.results.append(res.result)
    except BaseException:  # interrupt: stop the workers, then propagate
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    out.stopped_for_budget = budget_hit.is_set()
    return out


def merge_failures(ctx: ToolContext, phase: str, items: list[FailureRecord]) -> None:
    """Replace `phase`'s entries in failures.json, keeping every other phase's entries."""
    existing: list[FailureRecord] = []
    if ctx.paths.failures.exists():
        try:
            existing = read_artifact(ctx.paths.failures, Failures).data.items
        except Exception:  # unreadable: start over rather than fail the phase
            log.warning("failures.json unreadable; rewriting it")
    kept = [f for f in existing if f.phase != phase]
    write_artifact(ctx.paths.failures, Failures(tool=ctx.tool, items=kept + items),
                   produced_by=phase, inputs_hash="")
```

In `src/unvarnish/phases/extract.py` `_persist`, replace the `write_artifact(ctx.paths.failures, ...)` call with:

```python
        merge_failures(ctx, self.name, failures)
```

and import it: `from unvarnish.phases.modelrun import merge_failures`. (`Failures` stays imported only if still used; remove the import if ruff flags it.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_modelrun.py tests/test_extract_phase.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/phases/modelrun.py src/unvarnish/phases/extract.py tests/test_modelrun.py
git add src/unvarnish/phases/modelrun.py src/unvarnish/phases/extract.py tests/test_modelrun.py
git commit -m "feat: shared model-run helper (error mapping, parallel budgeted execution, failure merging)"
```

---

### Task 3: Rollup prompts

**Files:**
- Create: `src/unvarnish/model/prompts/rollup_module_system.md`, `src/unvarnish/model/prompts/rollup_directory_system.md`, `src/unvarnish/model/prompts/rollup_tool_system.md`, `src/unvarnish/model/prompts/rollup.py`
- Test: `tests/test_rollup_prompts.py`

**Interfaces:**
- Consumes: `UnitResult`, `ModuleDigest`, `DirectoryRollup`, `ModuleRollup`, `ToolRollup`, `strict_schema`, `CompletionRequest`, `Message`, `Category`, `Severity`.
- Produces (all in `unvarnish.model.prompts.rollup`):
  - `ROLLUP_PROMPT_VERSION = "2026-10-17.1"`
  - `build_module_rollup_system() -> str`, `build_directory_rollup_system() -> str`, `build_tool_rollup_system() -> str` (cached)
  - `unit_text(r: UnitResult) -> str`, `digest_text(d: ModuleDigest) -> str`, `chunk_text(prefix: str, n_files: int, dr: DirectoryRollup) -> str`
  - `build_module_rollup_request(path, language, file_lines, units: Sequence[UnitResult], frameworks: Sequence[str], effort: str | None, system: str | None = None) -> CompletionRequest`
  - `build_directory_rollup_request(prefix: str, digests: Sequence[ModuleDigest], effort, system=None) -> CompletionRequest`
  - `class ToolFacts(BaseModel)`: `tool, languages: dict[str, int], frameworks: list[str], files_analysed: int, source_lines: int, commits: int | None, authors: int | None, first_commit: str | None, last_commit: str | None`
  - `build_tool_rollup_request(facts: ToolFacts, digests: Sequence[ModuleDigest], chunks: Sequence[tuple[str, int, DirectoryRollup]], effort, system=None) -> CompletionRequest`

- [ ] **Step 1: Write the failing tests**

`tests/test_rollup_prompts.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_rollup_prompts.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.model.prompts.rollup'`.

- [ ] **Step 3: Write the system prompts**

`src/unvarnish/model/prompts/rollup_module_system.md`:

```markdown
You are the module rollup stage of Unvarnish, a tool that vets internally built software for a
consultant who will report the findings to the organisation's leadership and engineers.

You receive the analysed units of one source file. For each unit you get its purpose, interface,
external calls, data read and written, authentication and error handling, risks, and the findings
already recorded against it. Produce one JSON object describing the file as a whole. Do not add
commentary outside the JSON.

## What to produce

- summary: one paragraph, plain language: what this file is for, who or what calls it, and what it
  depends on.
- responsibilities: short statements, one per distinct responsibility. Three to eight is typical;
  more than eight is itself a signal worth a finding.
- interface: the names other code or users reach this file through (exports, routes, commands).
- dependencies_in: files, services, or callers that use this file, where the units show them.
- dependencies_out: files, libraries, and services this file relies on.
- candidate_findings: problems visible only at file level: duplicated logic between units,
  inconsistent error handling, mixed responsibilities, a file that should be several, auth checked
  on some routes but not others. Do not repeat findings already recorded for the units. Each needs
  a category, a severity, a line range inside the file, and a short excerpt or a description of
  what is at those lines.
- confidence: 0 to 1, how sure you are given what the units show.

Categories: {{CATEGORIES}}
Severities: {{SEVERITIES}}

Severity guide: critical means exploitable now or data loss likely; high means a real defect with
clear impact; medium means a defect that will bite under plausible conditions; low means worth
fixing when touched; info is context only. Do not soften.

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

`src/unvarnish/model/prompts/rollup_directory_system.md`:

```markdown
You are the directory rollup stage of Unvarnish, a tool that vets internally built software for a
consultant who will report the findings to the organisation's leadership and engineers.

The tool under review is too large to describe in one pass. You receive compact digests of many
analysed source files that share a path prefix. Your output will be combined with other chunks to
describe the whole tool, so be concrete and cite file paths exactly as given. Do not add
commentary outside the JSON.

## What to produce

- summary: one paragraph: what this part of the codebase does and how it fits the rest.
- responsibilities: short statements, one per distinct responsibility of this part.
- entry_points: how users or other systems reach this part: HTTP routes, commands, UI screens,
  scheduled jobs, queues. module is a file path exactly as given in the digests.
- data_stores: where this part persists data (databases, files, caches, spreadsheets, browser
  storage), with the files that touch each.
- external_systems: everything outside the codebase this part talks to, with direction.
- notable_modules: up to 15 files that matter most for understanding this part: path exactly as
  given, role, and the files it depends on.
- risks: short statements of anything a careful engineer would worry about across these files.
- candidate_findings: problems that span files: duplicated subsystems, two competing data paths,
  missing auth across a set of routes. paths are file paths exactly as given.

Categories: {{CATEGORIES}}
Severities: {{SEVERITIES}}

Do not invent files: every path you cite must appear in the input.

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

`src/unvarnish/model/prompts/rollup_tool_system.md`:

```markdown
You are the tool rollup stage of Unvarnish, a tool that vets internally built software for a
consultant who will report the findings to the organisation's leadership and engineers.

You receive inventory facts about one tool (languages, frameworks, size, history) and either
compact digests of every analysed file or, when the tool is large, summaries of directory chunks.
Produce the tool model as one JSON object. Do not add commentary outside the JSON.

## What to produce

- purpose: one paragraph for a reader who does not code: what the tool does, for whom, and why it
  seems to exist.
- actors: the kinds of people or systems that use it (name, description).
- entry_points: how actors reach it: HTTP routes, commands, UI screens, scheduled jobs, queues.
  module is a file path exactly as given.
- data_stores: where data persists (databases, files, caches, spreadsheets, browser storage).
- external_systems: everything outside the codebase it talks to, with direction (inbound,
  outbound, both).
- internal_stack: languages, frameworks, runtimes, build tools, as evidenced.
- module_map: the files that matter to understand the architecture: path exactly as given, role,
  and the files it depends on. Up to 40.
- data_flows: source and target are names of actors, modules, stores, or external systems exactly
  as you named them elsewhere in this output; data is what moves; via is the mechanism if known.
- deployment_assumptions: what the code assumes about where and how it runs: environment
  variables, hosts, ports, schedules, containers, file system layout.
- capabilities: "actor can action object" rows, one per distinct thing a user can accomplish.
  implementing_modules are file paths exactly as given; data_touched are store or system names as
  you named them. implicit is true when the capability exists only as a hardcoded rule rather
  than a designed feature.
- business_rules: rules embedded in code: hardcoded lists, thresholds, exemptions, mappings,
  schedules. module is a file path exactly as given.
- open_questions: what the code cannot tell you that a stakeholder interview should settle.
- candidate_findings: problems visible only across the whole tool: no authentication anywhere,
  two competing data paths, duplicated subsystems. paths are file paths exactly as given.
- confidence: 0 to 1.

Categories: {{CATEGORIES}}
Severities: {{SEVERITIES}}

Do not invent files: every path you cite must appear in the input. Do not soften.

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

- [ ] **Step 4: Write the prompt builders**

`src/unvarnish/model/prompts/rollup.py`:

```python
from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from pydantic import BaseModel

from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.rollup import ModuleDigest, ModuleRollup
from unvarnish.schemas.toolmodel import DirectoryRollup, ToolRollup

ROLLUP_PROMPT_VERSION = "2026-10-17.1"  # bump whenever any rollup prompt changes
UNIT_TEXT_CHARS = 1200
UNITS_PER_MODULE = 200
LIST_CAP = 12


@cache
def _system(template_name: str, schema_cls: type[BaseModel]) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath(template_name)
                .read_text(encoding="utf-8"))
    cats = ", ".join(c.value for c in Category)
    sevs = ", ".join(s.value for s in Severity)
    schema = json.dumps(strict_schema(schema_cls), indent=1, sort_keys=True)
    return (template.replace("{{CATEGORIES}}", cats).replace("{{SEVERITIES}}", sevs)
            .replace("{{SCHEMA}}", schema))


def build_module_rollup_system() -> str:
    return _system("rollup_module_system.md", ModuleRollup)


def build_directory_rollup_system() -> str:
    return _system("rollup_directory_system.md", DirectoryRollup)


def build_tool_rollup_system() -> str:
    return _system("rollup_tool_system.md", ToolRollup)


def _join(items: Sequence[str]) -> str:
    return "; ".join(items[:LIST_CAP]) + (f"; (+{len(items) - LIST_CAP} more)"
                                         if len(items) > LIST_CAP else "")


def unit_text(r: UnitResult) -> str:
    u, e = r.unit, r.extraction
    label = u.kind.value + (f" {u.name}" if u.name else "")
    window = " (window)" if u.split_method == "windowed" else ""
    lines = [f"### {label}, lines {u.line_start}-{u.line_end}{window}", e.purpose]
    if e.interface:
        lines.append("interface: " + _join(e.interface))
    if e.external_calls:
        lines.append("external: " + _join([f"{c.system} ({c.kind}): {c.detail}"
                                           for c in e.external_calls]))
    if e.data_read:
        lines.append("reads: " + _join(e.data_read))
    if e.data_written:
        lines.append("writes: " + _join(e.data_written))
    if e.auth_behaviour:
        lines.append("auth: " + e.auth_behaviour)
    if e.error_handling:
        lines.append("errors: " + e.error_handling)
    if e.risks:
        lines.append("risks: " + _join(e.risks))
    if r.findings:
        lines.append("findings already recorded: " + _join([
            f"{f.title} [{f.severity}] lines {f.evidence[0].line_start}-{f.evidence[0].line_end}"
            for f in r.findings]))
    return "\n".join(lines)[:UNIT_TEXT_CHARS]


def build_module_message(path: str, language: str | None, file_lines: int,
                         units: Sequence[UnitResult], frameworks: Sequence[str]) -> str:
    parts = [f"File: {path}", f"Language: {language or 'unknown'}", f"Lines: {file_lines}",
             f"Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}",
             f"Units analysed: {len(units)}", ""]
    for r in units[:UNITS_PER_MODULE]:
        parts.append(unit_text(r))
        parts.append("")
    if len(units) > UNITS_PER_MODULE:
        parts.append(f"(+{len(units) - UNITS_PER_MODULE} more units omitted)")
    return "\n".join(parts)


def build_module_rollup_request(path: str, language: str | None, file_lines: int,
                                units: Sequence[UnitResult], frameworks: Sequence[str],
                                effort: str | None, system: str | None = None) -> CompletionRequest:
    return CompletionRequest(
        system=system or build_module_rollup_system(),
        messages=[Message(role="user", content=build_module_message(
            path, language, file_lines, units, frameworks))],
        schema_name="ModuleRollup", effort=effort, cache_system=True,
    )


def digest_text(d: ModuleDigest) -> str:
    bits = [f"- {d.path} ({d.language or '?'}, {d.lines} lines, {d.units} units): "
            f"{d.summary[:400]}"]
    if d.responsibilities:
        bits.append("  responsibilities: " + _join(d.responsibilities))
    if d.interface:
        bits.append("  interface: " + _join(d.interface))
    if d.dependencies_out:
        bits.append("  depends on: " + _join(d.dependencies_out))
    if d.external_systems:
        bits.append("  external: " + _join(d.external_systems))
    if d.data_read or d.data_written:
        bits.append(f"  data: reads {_join(d.data_read) or '-'}; "
                    f"writes {_join(d.data_written) or '-'}")
    if d.findings:
        bits.append(f"  findings: {d.findings}")
    return "\n".join(bits)


def build_directory_rollup_request(prefix: str, digests: Sequence[ModuleDigest],
                                   effort: str | None,
                                   system: str | None = None) -> CompletionRequest:
    body = (f"Path prefix: {prefix or '(repository root)'}\nFiles: {len(digests)}\n\n"
            + "\n".join(digest_text(d) for d in digests))
    return CompletionRequest(system=system or build_directory_rollup_system(),
                             messages=[Message(role="user", content=body)],
                             schema_name="DirectoryRollup", effort=effort, cache_system=True)


class ToolFacts(BaseModel):
    tool: str
    languages: dict[str, int]
    frameworks: list[str]
    files_analysed: int
    source_lines: int
    commits: int | None = None
    authors: int | None = None
    first_commit: str | None = None
    last_commit: str | None = None


def facts_text(f: ToolFacts) -> str:
    langs = ", ".join(f"{k} {v:,} lines" for k, v in
                      sorted(f.languages.items(), key=lambda kv: -kv[1])[:8]) or "unknown"
    history = (f"{f.commits:,} commits by {f.authors} author(s), {f.first_commit} to "
               f"{f.last_commit}" if f.commits is not None else "no git history")
    return (f"Tool: {f.tool}\nLanguages: {langs}\n"
            f"Frameworks: {', '.join(f.frameworks) if f.frameworks else 'none detected'}\n"
            f"Files analysed: {f.files_analysed:,}; source lines: {f.source_lines:,}\n"
            f"History: {history}")


def chunk_text(prefix: str, n_files: int, dr: DirectoryRollup) -> str:
    lines = [f"## Chunk {prefix or '(repository root)'} ({n_files} files)", dr.summary]
    if dr.responsibilities:
        lines.append("responsibilities: " + _join(dr.responsibilities))
    if dr.entry_points:
        lines.append("entry points: " + _join([f"{e.name} [{e.kind}] in {e.module}"
                                               for e in dr.entry_points]))
    if dr.data_stores:
        lines.append("data stores: " + _join([f"{s.name} [{s.kind}]" for s in dr.data_stores]))
    if dr.external_systems:
        lines.append("external systems: " + _join([f"{s.name} [{s.kind}, {s.direction}]"
                                                   for s in dr.external_systems]))
    if dr.notable_modules:
        lines.append("notable modules:")
        lines.extend(f"- {m.path}: {m.role}" + (f" (depends on {_join(m.depends_on)})"
                                                if m.depends_on else "")
                     for m in dr.notable_modules)
    if dr.risks:
        lines.append("risks: " + _join(dr.risks))
    if dr.candidate_findings:
        lines.append("findings: " + _join([f"{c.title} [{c.severity}]"
                                           for c in dr.candidate_findings]))
    return "\n".join(lines)


def build_tool_rollup_request(facts: ToolFacts, digests: Sequence[ModuleDigest],
                              chunks: Sequence[tuple[str, int, DirectoryRollup]],
                              effort: str | None, system: str | None = None) -> CompletionRequest:
    parts = [facts_text(facts), ""]
    if chunks:
        n = len(chunks)
        parts.append(f"The tool was summarised in {n} directory chunk{'s' if n != 1 else ''}:")
        parts.append("")
        for prefix, n_files, dr in chunks:
            parts.append(chunk_text(prefix, n_files, dr))
            parts.append("")
    else:
        parts.append("Files:")
        parts.extend(digest_text(d) for d in digests)
    return CompletionRequest(system=system or build_tool_rollup_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="ToolRollup", effort=effort, cache_system=True)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_rollup_prompts.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/model/prompts/rollup.py tests/test_rollup_prompts.py
git add src/unvarnish/model/prompts tests/test_rollup_prompts.py
git commit -m "feat: module, directory, and tool rollup prompts"
```

---

### Task 4: rollup_modules phase

**Files:**
- Create: `src/unvarnish/phases/rollup_modules.py`
- Test: `tests/test_rollup_modules.py`

**Interfaces:**
- Consumes: Task 1 schemas and paths, Task 2 `call_structured`/`run_parallel`/`merge_failures`/`ItemOutcome`, Task 3 builders, `resolve_backend`/`resolve_model_ref`/`NoModelConfigured`, `record_cost`, `Census`, `UnitsIndex`, `UnitResult`.
- Produces:
  - `to_module_findings(cands: list[CandidateFinding], path: str, file_lines: int, tool: str, model: str) -> tuple[list[Finding], int]`
  - `make_digest(module: Module, units: Sequence[UnitResult], lines: int) -> ModuleDigest`
  - `class RollupModulesPhase(backend: Backend | None = None)` with `name = "rollup_modules"`, `outputs = [modules_index]`.
  - Per-module artifact `analysis/modules/<module_file_id>.json` (`Module`) with `inputs_hash = hash_inputs([*unit_artifact_hashes, backend, model, effort, ROLLUP_PROMPT_VERSION])`.

- [ ] **Step 1: Write the failing tests**

`tests/test_rollup_modules.py`:

```python
import json

from tests.stub_backend import StubBackend
from unvarnish.artifacts import read_artifact
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase, to_module_findings
from unvarnish.phases.split import SplitPhase
from unvarnish.schemas.analysis import CandidateFinding, Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.rollup import Module, ModulesIndex, module_file_id

UNIT = json.dumps({
    "purpose": "Does a thing.", "interface": ["main"], "external_calls": [
        {"system": "db.internal", "kind": "db", "detail": "reads"}],
    "data_read": ["expenses"], "data_written": [], "auth_behaviour": None,
    "error_handling": None, "risks": [], "candidate_findings": [], "confidence": 0.8,
})
MODULE = json.dumps({
    "summary": "A module.", "responsibilities": ["one", "two"], "interface": ["main"],
    "dependencies_in": [], "dependencies_out": ["os"],
    "candidate_findings": [
        {"category": "maintainability", "severity": "medium", "title": "Mixed responsibilities",
         "summary": "s", "impact": "i", "remediation": "r", "line_start": 1, "line_end": 1,
         "excerpt": "x", "confidence": 0.9},
        {"category": "security", "severity": "high", "title": "Out of file",
         "summary": "s", "impact": "i", "remediation": "r", "line_start": 999999,
         "line_end": 999999, "excerpt": "y", "confidence": 0.9},
    ],
    "confidence": 0.7,
})


def _stub(module_reply=MODULE) -> StubBackend:
    return StubBackend({"UnitExtraction": UNIT, "ModuleRollup": module_reply})


def _extracted(engagement, tool, stub, budget=None):
    ctx = build_context(engagement, tool, budget=budget)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    assert ExtractPhase(backend=stub).run(ctx).status == PhaseStatus.ok
    return ctx


def test_to_module_findings_drops_out_of_range():
    cands = [CandidateFinding(category=Category.security, severity=Severity.high, title="in",
                              summary="s", impact="i", remediation="r", line_start=3,
                              line_end=4, confidence=0.5),
             CandidateFinding(category=Category.security, severity=Severity.high, title="out",
                              summary="s", impact="i", remediation="r", line_start=0,
                              line_end=4, confidence=0.5),
             CandidateFinding(category=Category.security, severity=Severity.high, title="past",
                              summary="s", impact="i", remediation="r", line_start=9,
                              line_end=11, confidence=0.5)]
    findings, dropped = to_module_findings(cands, "a.py", 10, "t", "m")
    assert [f.title for f in findings] == ["in"] and dropped == 2
    assert findings[0].evidence[0].path == "a.py" and findings[0].model == "m"


def test_rollup_writes_module_artifacts_and_index(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert idx.failed == [] and idx.skipped == []
    paths = [d.path for d in idx.modules]
    assert "app.py" in paths and paths == sorted(paths)
    app = next(d for d in idx.modules if d.path == "app.py")
    assert app.external_systems == ["db.internal"] and app.data_read == ["expenses"]
    assert app.findings == 1 and app.units >= 2
    module = read_artifact(ctx.paths.module_dir / f"{module_file_id('app.py')}.json", Module)
    assert module.data.dropped_findings == 1
    assert module.data.findings[0].title == "Mixed responsibilities"
    assert is_fresh(RollupModulesPhase(backend=stub), ctx)
    assert stub.count("ModuleRollup") == len(idx.modules)


def test_rollup_is_resumable(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    RollupModulesPhase(backend=stub).run(ctx)
    before = stub.count("ModuleRollup")
    RollupModulesPhase(backend=stub).run(ctx)
    assert stub.count("ModuleRollup") == before


def test_rollup_skips_modules_without_units(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    for p in ctx.paths.unit_dir.glob("*.json"):
        art = json.loads(p.read_text())
        if art["data"]["unit"]["path"] == "README.md":
            p.unlink()
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert "README.md" in idx.skipped
    assert "README.md" not in [d.path for d in idx.modules]


def test_rollup_records_failures_and_continues(ingested):
    eng, tool = ingested
    stub = _stub(module_reply="not json")
    ctx = _extracted(eng, tool, stub)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok and res.failures
    idx = read_artifact(ctx.paths.modules_index, ModulesIndex).data
    assert idx.modules == [] and "app.py" in idx.failed
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert {f.phase for f in items} == {"rollup_modules"}
    assert all(f.attempts == 3 for f in items)


def test_rollup_stops_at_budget_and_stays_stale(ingested):
    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ctx = build_context(eng, tool, budget=tracker)
    res = RollupModulesPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.stopped
    assert stub.count("ModuleRollup") == 0
    assert read_artifact(ctx.paths.modules_index, ModulesIndex).data.stopped_for_budget
    assert not is_fresh(RollupModulesPhase(backend=stub), ctx)


def test_rollup_skipped_without_model(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    res = RollupModulesPhase().run(ctx)
    assert res.status == PhaseStatus.skipped and "no model configured" in res.message
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_rollup_modules.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.phases.rollup_modules'`.

- [ ] **Step 3: Write the phase**

`src/unvarnish/phases/rollup_modules.py`:

```python
from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.prompts.rollup import (
    ROLLUP_PROMPT_VERSION,
    build_module_rollup_request,
    build_module_rollup_system,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.schemas.analysis import CandidateFinding, UnitResult, UnitsIndex
from unvarnish.schemas.cost import CostEntry
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import (
    Module,
    ModuleDigest,
    ModuleRollup,
    ModulesIndex,
    module_file_id,
)

log = logging.getLogger("unvarnish.rollup_modules")
DIGEST_LIST_CAP = 20

WorkItem = tuple[str, list[UnitResult], list[str]]  # path, unit results, unit artifact hashes


def to_module_findings(cands: list[CandidateFinding], path: str, file_lines: int, tool: str,
                       model: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        upper = file_lines if file_lines > 0 else c.line_end
        if not (1 <= c.line_start <= c.line_end <= upper):
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title,
            summary=c.summary, impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=path, line_start=c.line_start, line_end=c.line_end,
                               excerpt=(c.excerpt or "")[:200] or None)],
            source=Source.model, model=model, confidence=c.confidence,
        ))
    return findings, dropped


def _unique(items: Sequence[str]) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it.strip(), None)
    return [s for s in seen if s][:DIGEST_LIST_CAP]


def make_digest(module: Module, units: Sequence[UnitResult], lines: int) -> ModuleDigest:
    return ModuleDigest(
        id=module.id, path=module.path, language=units[0].unit.language if units else None,
        units=len(units), lines=lines, summary=module.rollup.summary,
        responsibilities=module.rollup.responsibilities, interface=module.rollup.interface,
        dependencies_out=module.rollup.dependencies_out,
        external_systems=_unique([c.system for u in units for c in u.extraction.external_calls]),
        data_read=_unique([d for u in units for d in u.extraction.data_read]),
        data_written=_unique([d for u in units for d in u.extraction.data_written]),
        findings=len(module.findings),
    )


class RollupModulesPhase:
    name = "rollup_modules"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def inputs_hash(self, ctx: ToolContext) -> str:
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files([ctx.paths.extract_state, ctx.paths.units_index]),
                            model_part, ROLLUP_PROMPT_VERSION])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.modules_index]

    def _work(self, ctx: ToolContext, index: UnitsIndex) -> tuple[list[WorkItem], list[str]]:
        work: list[WorkItem] = []
        skipped: list[str] = []
        for path, unit_ids in sorted(index.modules.items()):
            results: list[UnitResult] = []
            hashes: list[str] = []
            for uid in unit_ids:
                p = ctx.paths.unit_dir / f"{uid}.json"
                if not p.exists():
                    continue
                try:
                    art = read_artifact(p, UnitResult)
                except Exception:  # unreadable unit artifact: treat as missing
                    continue
                results.append(art.data)
                hashes.append(art.meta.inputs_hash)
            if results:
                work.append((path, results, hashes))
            else:
                skipped.append(path)
        return work, skipped

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        if not ctx.paths.extract_state.exists():
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="extract has not run for this tool")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        index = read_artifact(ctx.paths.units_index, UnitsIndex).data
        census = read_artifact(ctx.paths.census, Census).data
        lines_by_path = {f.path: f.lines for f in census.files}
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        system = build_module_rollup_system()
        ctx.paths.module_dir.mkdir(parents=True, exist_ok=True)
        work, skipped = self._work(ctx, index)

        def worker(item: WorkItem, stop: threading.Event) -> ItemOutcome[ModuleDigest]:
            path, results, hashes = item
            lines = lines_by_path.get(path, 0)
            h = hash_inputs([*hashes, backend.name, backend.model, effort or "",
                             ROLLUP_PROMPT_VERSION])
            out_path = ctx.paths.module_dir / f"{module_file_id(path)}.json"
            if out_path.exists():
                try:
                    prior = read_artifact(out_path, Module)
                    if prior.meta.inputs_hash == h:
                        return ItemOutcome(result=make_digest(prior.data, results, lines))
                except Exception:  # unreadable artifact: redo the module
                    pass
            req = build_module_rollup_request(path, results[0].unit.language, lines, results,
                                              census.frameworks, effort, system=system)
            res, failure = call_structured(backend, req, ModuleRollup, phase=self.name,
                                           item_id=module_file_id(path), path=path, stop=stop)
            if res is None:
                return ItemOutcome(failures=[failure] if failure else [])
            findings, dropped = to_module_findings(res.parsed.candidate_findings, path, lines,
                                                   ctx.tool, backend.model)
            module = Module(
                id=module_file_id(path), tool=ctx.tool, path=path,
                unit_ids=[r.unit.id for r in results], rollup=res.parsed, findings=findings,
                dropped_findings=dropped, backend=backend.name, model=backend.model,
                usage=res.usage, prompt_version=ROLLUP_PROMPT_VERSION, attempts=res.attempts,
            )
            write_artifact(out_path, module, produced_by=self.name, inputs_hash=h)
            log.debug("rolled up %s (%d units, %d tokens)", path, len(results),
                      res.usage.total())
            return ItemOutcome(result=make_digest(module, results, lines), usage=res.usage)

        outcome = run_parallel(work, worker, workers=ctx.config.pipeline.concurrency,
                               budget=budget)
        failed = sorted({f.path for f in outcome.failures if f.path})
        idx = ModulesIndex(tool=ctx.tool, modules=sorted(outcome.results, key=lambda d: d.path),
                           failed=failed, skipped=skipped, usage=outcome.usage,
                           stopped_for_budget=outcome.stopped_for_budget)
        # An empty inputs_hash keeps the phase stale after a stop, so a later run resumes.
        write_artifact(ctx.paths.modules_index, idx, produced_by=self.name,
                       inputs_hash="" if outcome.stopped else self.inputs_hash(ctx))
        if outcome.usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=outcome.usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, outcome.failures)
        if outcome.fatal is not None:
            raise outcome.fatal
        msg = (f"{len(outcome.results)}/{len(work)} modules, {len(failed)} failed, "
               f"{len(skipped)} without units, {outcome.usage.total():,} tokens")
        status = PhaseStatus.stopped if outcome.stopped_for_budget else PhaseStatus.ok
        if outcome.stopped_for_budget:
            msg = "budget cap reached: " + msg
        log.info("rollup_modules %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in outcome.failures])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_rollup_modules.py -q 2>&1 | tail -3`
Expected: all PASS. If `test_rollup_skips_modules_without_units` fails because the synthetic repo's `README.md` is not a single-unit module, check the unit artifacts' paths and delete every artifact for that path (the test already deletes all of them); the assertion is on `skipped`, which only needs all of that module's unit artifacts gone.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/phases/rollup_modules.py tests/test_rollup_modules.py
git add src/unvarnish/phases/rollup_modules.py tests/test_rollup_modules.py
git commit -m "feat: rollup_modules phase with per-module artifacts and resumability"
```

---

### Task 5: rollup_tool phase with hierarchical chunking

**Files:**
- Create: `src/unvarnish/phases/rollup_tool.py`
- Test: `tests/test_rollup_tool.py`

**Interfaces:**
- Consumes: Task 1 schemas, Task 2 helpers, Task 3 builders, `ModulesIndex`, `Census`, `GitStats`, `estimate_tokens`.
- Produces:
  - `common_prefix(paths: Sequence[str]) -> str`
  - `partition_digests(digests: Sequence[ModuleDigest], budget_tokens: int) -> list[tuple[str, list[ModuleDigest]]]` (empty list means "fits in one call")
  - `tool_facts(ctx, census, git) -> ToolFacts`
  - `to_tool_findings(cands: Sequence[ToolCandidateFinding], known: set[str], tool: str, model: str) -> tuple[list[Finding], int]`
  - `build_tool_model(tool, rollup: ToolRollup, known: set[str], *, chunk_rollups: Sequence[tuple[str, int, DirectoryRollup]], backend_name, model, usage, attempts, modules_covered) -> ToolModel`
  - `requirements_inventory(tm: ToolModel) -> RequirementsInventory`
  - `class RollupToolPhase(backend=None)` with `name = "rollup_tool"`, outputs `[tool_model, capabilities]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_rollup_tool.py`:

```python
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
    assert res.status == PhaseStatus.failed and not ctx.paths.tool_model.exists()
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_rollup_tool.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.phases.rollup_tool'`.

- [ ] **Step 3: Write the phase**

`src/unvarnish/phases/rollup_tool.py`:

```python
from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.analysis.languages import Classification
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.rollup import (
    ROLLUP_PROMPT_VERSION,
    ToolFacts,
    build_directory_rollup_request,
    build_tool_rollup_request,
    digest_text,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import ModuleDigest, ModulesIndex
from unvarnish.schemas.toolmodel import (
    Capability,
    DataInventoryRow,
    DirectoryRollup,
    ModuleMapEntry,
    RequirementsInventory,
    ToolCandidateFinding,
    ToolModel,
    ToolRollup,
    capability_id,
)

log = logging.getLogger("unvarnish.rollup_tool")
MODULE_MAP_CAP = 60
Chunk = tuple[str, list[ModuleDigest]]
ChunkRollup = tuple[str, int, DirectoryRollup]


def common_prefix(paths: Sequence[str]) -> str:
    dirs = [p.rsplit("/", 1)[0] if "/" in p else "" for p in paths]
    parts = [d.split("/") if d else [] for d in dirs]
    if not parts:
        return ""
    out: list[str] = []
    for segs in zip(*parts, strict=False):
        if all(s == segs[0] for s in segs):
            out.append(segs[0])
        else:
            break
    return "/".join(out)


def partition_digests(digests: Sequence[ModuleDigest], budget_tokens: int) -> list[Chunk]:
    """Chunks of path-sorted digests that each fit `budget_tokens`; [] when all fit one call."""
    sized = [(d, estimate_tokens(digest_text(d))) for d in sorted(digests, key=lambda d: d.path)]
    if sum(n for _, n in sized) <= budget_tokens:
        return []
    chunks: list[list[ModuleDigest]] = []
    cur: list[ModuleDigest] = []
    cur_tokens = 0
    for d, n in sized:
        if cur and cur_tokens + n > budget_tokens:
            chunks.append(cur)
            cur, cur_tokens = [], 0
        cur.append(d)
        cur_tokens += n
    if cur:
        chunks.append(cur)
    return [(common_prefix([d.path for d in c]), c) for c in chunks]


def tool_facts(ctx: ToolContext, census: Census, git: GitStats) -> ToolFacts:
    live = [f for f in census.files if not f.excluded]
    return ToolFacts(
        tool=ctx.tool, languages=dict(census.languages), frameworks=list(census.frameworks),
        files_analysed=sum(1 for f in live if f.classification != Classification.binary),
        source_lines=sum(f.lines for f in live if f.classification == Classification.source),
        commits=git.commit_count if git.available else None,
        authors=len(git.authors) if git.available else None,
        first_commit=git.first_commit.date().isoformat() if git.first_commit else None,
        last_commit=git.last_commit.date().isoformat() if git.last_commit else None,
    )


def to_tool_findings(cands: Sequence[ToolCandidateFinding], known: set[str], tool: str,
                     model: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        paths = [p for p in dict.fromkeys(c.paths) if p in known]
        if not paths:
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title,
            summary=c.summary, impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=p, note="cited by tool-level analysis") for p in paths],
            source=Source.model, model=model, confidence=c.confidence,
        ))
    return findings, dropped


def _merge_named[T](base: Sequence[T], extra: Sequence[T]) -> list[T]:
    """Union by case-insensitive `.name`, base entries first."""
    out: list[T] = list(base)
    seen = {x.name.lower() for x in base}  # type: ignore[attr-defined]
    for x in extra:
        key = x.name.lower()  # type: ignore[attr-defined]
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def build_tool_model(tool: str, rollup: ToolRollup, known: set[str], *,
                     chunk_rollups: Sequence[ChunkRollup], backend_name: str, model: str,
                     usage: Usage, attempts: int, modules_covered: int) -> ToolModel:
    entry_points = list(rollup.entry_points)
    data_stores = list(rollup.data_stores)
    external = list(rollup.external_systems)
    cands = list(rollup.candidate_findings)
    extra_modules: list[ModuleMapEntry] = []
    for _, _, dr in chunk_rollups:
        entry_points = _merge_named(entry_points, dr.entry_points)
        data_stores = _merge_named(data_stores, dr.data_stores)
        external = _merge_named(external, dr.external_systems)
        cands.extend(dr.candidate_findings)
        extra_modules.extend(dr.notable_modules)
    module_map: list[ModuleMapEntry] = []
    seen_paths: set[str] = set()
    for m in [*rollup.module_map, *extra_modules]:
        if m.path in known and m.path not in seen_paths and len(module_map) < MODULE_MAP_CAP:
            seen_paths.add(m.path)
            module_map.append(ModuleMapEntry(path=m.path, role=m.role,
                                             depends_on=[d for d in m.depends_on if d in known]))
    findings, dropped = to_tool_findings(cands, known, tool, model)
    caps: dict[str, Capability] = {}
    for c in rollup.capabilities:
        cid = capability_id(tool, c.actor, c.action, c.object)
        if cid in caps:
            continue
        caps[cid] = Capability(
            **c.model_dump(), id=cid, tool=tool,
            evidence=[Evidence(path=p) for p in dict.fromkeys(c.implementing_modules)
                      if p in known],
        )
    return ToolModel(
        tool=tool, purpose=rollup.purpose, actors=rollup.actors,
        entry_points=[e for e in entry_points if e.module in known],
        data_stores=data_stores, external_systems=external,
        internal_stack=rollup.internal_stack, module_map=module_map,
        data_flows=rollup.data_flows, deployment_assumptions=rollup.deployment_assumptions,
        capabilities=list(caps.values()),
        business_rules=[r for r in rollup.business_rules if r.module in known],
        open_questions=rollup.open_questions, findings=findings, dropped_findings=dropped,
        hierarchical=bool(chunk_rollups), chunks=len(chunk_rollups),
        modules_covered=modules_covered, confidence=rollup.confidence, backend=backend_name,
        model=model, usage=usage, prompt_version=ROLLUP_PROMPT_VERSION, attempts=attempts,
    )


def requirements_inventory(tm: ToolModel) -> RequirementsInventory:
    def users_of(name: str) -> list[str]:
        n = name.lower()
        return [c.id for c in tm.capabilities
                if any(n in t.lower() or t.lower() in n for t in c.data_touched)]

    rows = [DataInventoryRow(name=s.name, kind=s.kind, description=s.description,
                             used_by=users_of(s.name)) for s in tm.data_stores]
    rows += [DataInventoryRow(name=s.name, kind=f"external:{s.kind}", description=s.description,
                              used_by=users_of(s.name)) for s in tm.external_systems]
    return RequirementsInventory(tool=tm.tool, actors=tm.actors, capabilities=tm.capabilities,
                                 data_inventory=rows, business_rules=tm.business_rules,
                                 open_questions=tm.open_questions)


class RollupToolPhase:
    name = "rollup_tool"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def inputs_hash(self, ctx: ToolContext) -> str:
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files([ctx.paths.modules_index, ctx.paths.census,
                                        ctx.paths.git]),
                            model_part, ROLLUP_PROMPT_VERSION,
                            str(ctx.config.pipeline.rollup_input_tokens)])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.tool_model, ctx.paths.capabilities]

    def _finish(self, ctx: ToolContext, backend: Backend, usage: Usage,
                failures: list[FailureRecord]) -> None:
        if usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, failures)

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        if not ctx.paths.modules_index.exists():
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="rollup_modules has not run for this tool")
        index = read_artifact(ctx.paths.modules_index, ModulesIndex).data
        if not index.modules:
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message="no module rollups available")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        census = read_artifact(ctx.paths.census, Census).data
        git = read_artifact(ctx.paths.git, GitStats).data
        known = {d.path for d in index.modules}
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        usage = Usage()
        failures: list[FailureRecord] = []
        chunks = partition_digests(index.modules, ctx.config.pipeline.rollup_input_tokens)
        chunk_rollups: list[ChunkRollup] = []

        if chunks:
            def worker(item: Chunk, stop: threading.Event) -> ItemOutcome[ChunkRollup]:
                prefix, digests = item
                req = build_directory_rollup_request(prefix, digests, effort)
                res, failure = call_structured(backend, req, DirectoryRollup, phase=self.name,
                                               item_id=f"chunk:{prefix or '(root)'}",
                                               path=None, stop=stop)
                if res is None:
                    return ItemOutcome(failures=[failure] if failure else [])
                return ItemOutcome(result=(prefix, len(digests), res.parsed), usage=res.usage)

            outcome = run_parallel(chunks, worker, workers=ctx.config.pipeline.concurrency,
                                   budget=budget)
            usage = usage + outcome.usage
            failures.extend(outcome.failures)
            if outcome.fatal is not None:
                self._finish(ctx, backend, usage, failures)
                raise outcome.fatal
            if outcome.stopped_for_budget:
                self._finish(ctx, backend, usage, failures)
                return PhaseResult(phase=self.name, status=PhaseStatus.stopped,
                                   message="budget cap reached during directory rollups")
            if not outcome.results:
                self._finish(ctx, backend, usage, failures)
                return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                                   message="every directory rollup failed",
                                   failures=[f.error for f in failures])
            chunk_rollups = sorted(outcome.results, key=lambda c: c[0])

        try:
            budget.check()
        except BudgetExceeded:
            self._finish(ctx, backend, usage, failures)
            return PhaseResult(phase=self.name, status=PhaseStatus.stopped,
                               message="budget cap reached before the tool rollup")
        req = build_tool_rollup_request(tool_facts(ctx, census, git),
                                        [] if chunks else index.modules, chunk_rollups, effort)
        res, failure = call_structured(backend, req, ToolRollup, phase=self.name,
                                       item_id="tool", path=None, stop=threading.Event())
        if res is None:
            if failure:
                failures.append(failure)
            self._finish(ctx, backend, usage, failures)
            return PhaseResult(phase=self.name, status=PhaseStatus.failed,
                               message=f"tool rollup failed: {failure.error if failure else '?'}",
                               failures=[f.error for f in failures])
        usage = usage + res.usage
        budget.add(res.usage)
        tm = build_tool_model(ctx.tool, res.parsed, known, chunk_rollups=chunk_rollups,
                              backend_name=backend.name, model=backend.model, usage=usage,
                              attempts=res.attempts, modules_covered=len(index.modules))
        h = self.inputs_hash(ctx)
        write_artifact(ctx.paths.tool_model, tm, produced_by=self.name, inputs_hash=h)
        write_artifact(ctx.paths.capabilities, requirements_inventory(tm), produced_by=self.name,
                       inputs_hash=h)
        self._finish(ctx, backend, usage, failures)
        how = f"hierarchical, {tm.chunks} chunks" if tm.hierarchical else "single pass"
        msg = (f"{len(tm.capabilities)} capabilities, {len(tm.findings)} findings, {how}, "
               f"{usage.total():,} tokens")
        log.info("rollup_tool %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, message=msg,
                           failures=[f.error for f in failures])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_rollup_tool.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/phases/rollup_tool.py tests/test_rollup_tool.py
git add src/unvarnish/phases/rollup_tool.py tests/test_rollup_tool.py
git commit -m "feat: rollup_tool phase with hierarchical directory chunking, tool.json and capabilities.json"
```

---

### Task 6: verify phase

**Files:**
- Create: `src/unvarnish/model/prompts/verify_system.md`, `src/unvarnish/model/prompts/verify.py`, `src/unvarnish/phases/verify.py`
- Test: `tests/test_verify.py`

**Interfaces:**
- Consumes: `Finding`, `Evidence`, `Verification`, `Severity`, `SEVERITY_ORDER`, `Verdict`, `ModelFindings`, `UnitResult`, `Module`, `ToolModel`, Task 2 helpers.
- Produces:
  - `unvarnish.model.prompts.verify`: `VERIFY_PROMPT_VERSION = "2026-10-17.1"`, `build_verify_system() -> str`, `build_verify_request(finding: Finding, excerpts: Sequence[str], effort: str | None, system: str | None = None) -> CompletionRequest` (schema_name `"Verdict"`).
  - `unvarnish.phases.verify`: `VERIFY_SEVERITIES = {Severity.critical, Severity.high}`, `collect_model_findings(ctx) -> list[Finding]`, `dedupe_findings(findings) -> list[Finding]`, `evidence_excerpt(source_root: Path, ev: Evidence, context: int = 5, max_lines: int = 80) -> str`, `downgrade(sev: Severity) -> Severity`, `class VerifyPhase(backend=None)` with `name = "verify"`, outputs `[model_findings]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_verify.py`:

```python
import json

from tests.stub_backend import StubBackend
from tests.test_rollup_modules import MODULE
from tests.test_rollup_tool import TOOL
from unvarnish.artifacts import read_artifact
from unvarnish.model.budget import BudgetTracker
from unvarnish.model.prompts.verify import build_verify_request
from unvarnish.phases.base import PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.phases.verify import (
    VerifyPhase,
    collect_model_findings,
    dedupe_findings,
    downgrade,
    evidence_excerpt,
)
from unvarnish.schemas.analysis import Failures
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source, Verification
from unvarnish.schemas.verify import ModelFindings


def _unit_reply(req) -> str:
    """UnitExtraction with one high finding at the unit's first line, same title everywhere."""
    user = req.messages[-1].content
    rng = user.split("lines ", 1)[1].split("\n", 1)[0].split(" ", 1)[0]
    lo = int(rng.split("-")[0])
    return json.dumps({
        "purpose": "Does a thing.", "interface": [], "external_calls": [], "data_read": [],
        "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
        "candidate_findings": [{
            "category": "security", "severity": "high", "title": "Hardcoded credential",
            "summary": "s", "impact": "i", "remediation": "r", "line_start": lo,
            "line_end": lo, "excerpt": "x", "confidence": 0.9}],
        "confidence": 0.8,
    })


def _finding(title="t", path="a.py", line=1, severity=Severity.high, confidence=0.5,
             category=Category.security) -> Finding:
    return Finding(tool="t", category=category, severity=severity, title=title, summary="s",
                   impact="i", remediation="r", source=Source.model, model="m",
                   confidence=confidence,
                   evidence=[Evidence(path=path, line_start=line, line_end=line)])


def test_dedupe_merges_same_problem_in_same_file():
    a = _finding(line=1, confidence=0.4)
    b = _finding(title=" T ", line=50, confidence=0.9)
    c = _finding(path="b.py")
    out = dedupe_findings([a, b, c])
    assert len(out) == 2
    merged = next(f for f in out if f.evidence[0].path == "a.py")
    assert [e.line_start for e in merged.evidence] == [1, 50]
    assert merged.confidence == 0.9 and merged.id == a.id


def test_dedupe_keeps_different_categories_apart():
    out = dedupe_findings([_finding(), _finding(category=Category.reliability)])
    assert len(out) == 2


def test_evidence_excerpt_numbers_lines_with_context(tmp_path):
    (tmp_path / "a.py").write_text("".join(f"line {i}\n" for i in range(1, 21)))
    text = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=10, line_end=11),
                            context=2)
    assert text.startswith("a.py lines 8-13:\n")
    assert "     8: line 8" in text and "    13: line 13" in text and "line 14" not in text
    clamped = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=1, line_end=1),
                               context=5)
    assert clamped.startswith("a.py lines 1-6:")
    capped = evidence_excerpt(tmp_path, Evidence(path="a.py", line_start=1, line_end=20),
                              context=0, max_lines=3)
    assert capped.startswith("a.py lines 1-3:")
    whole = evidence_excerpt(tmp_path, Evidence(path="a.py", excerpt="recorded"))
    assert "whole file cited" in whole and "recorded" in whole
    missing = evidence_excerpt(tmp_path, Evidence(path="nope.py", line_start=1))
    assert "not readable" in missing


def test_downgrade_steps_one_level_and_floors():
    assert downgrade(Severity.critical) == Severity.high
    assert downgrade(Severity.high) == Severity.medium
    assert downgrade(Severity.low) == Severity.info
    assert downgrade(Severity.info) == Severity.info


def test_verify_request_contains_claim_and_evidence_only():
    f = _finding(title="Hardcoded credential")
    req = build_verify_request(f, ["a.py lines 1-3:\n     1: x = 1"], effort="low")
    body = req.messages[0].content
    assert body.startswith("Claim: Hardcoded credential\nCategory: security\n"
                           "Severity claimed: high\n")
    assert "     1: x = 1" in body and req.schema_name == "Verdict"
    assert "confirmed" in req.system and "rejected" in req.system


def _pipeline(engagement, tool, stub, budget=None):
    ctx = build_context(engagement, tool, budget=budget)
    for phase in (InventoryPhase(), SplitPhase(), ExtractPhase(backend=stub),
                  RollupModulesPhase(backend=stub), RollupToolPhase(backend=stub)):
        assert phase.run(ctx).status == PhaseStatus.ok, phase.name
    return ctx


def test_collect_gathers_unit_module_and_tool_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL})
    ctx = _pipeline(eng, tool, stub)
    titles = {f.title for f in collect_model_findings(ctx)}
    assert {"Hardcoded credential", "Mixed responsibilities", "No auth anywhere"} <= titles


def test_verify_downgrades_and_writes_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "downgraded", "reason": "overstated"}'})
    ctx = _pipeline(eng, tool, stub)
    res = VerifyPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok, res
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    highs = [f for f in mf.findings if f.title in ("Hardcoded credential", "No auth anywhere")]
    assert highs and all(f.verification == Verification.downgraded for f in highs)
    assert all(f.severity == Severity.medium for f in highs)
    assert all(f.verification_note == "overstated" for f in highs)
    medium = next(f for f in mf.findings if f.title == "Mixed responsibilities")
    assert medium.verification == Verification.not_required
    assert mf.verified == len(highs) == mf.downgraded and mf.unverified == 0
    assert stub.count("Verdict") == len(highs)
    assert is_fresh(VerifyPhase(backend=stub), ctx)
    # dedupe collapsed the per-unit duplicates in app.py into one finding
    assert sum(1 for f in mf.findings if f.title == "Hardcoded credential"
               and f.evidence[0].path == "app.py") == 1


def test_verify_retains_rejected_findings(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "rejected", "reason": "no such thing"}'})
    ctx = _pipeline(eng, tool, stub)
    VerifyPhase(backend=stub).run(ctx)
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    rejected = [f for f in mf.findings if f.verification == Verification.rejected]
    assert rejected and mf.rejected == len(rejected)
    assert all(f.severity == Severity.high for f in rejected)  # severity untouched


def test_verify_keeps_finding_when_verification_fails(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL, "Verdict": "garbage"})
    ctx = _pipeline(eng, tool, stub)
    res = VerifyPhase(backend=stub).run(ctx)
    assert res.status == PhaseStatus.ok and res.failures
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    highs = [f for f in mf.findings if f.severity == Severity.high]
    assert highs and all(f.verification is None for f in highs)
    assert all("verification failed" in (f.verification_note or "") for f in highs)
    assert mf.unverified == len(highs) and mf.verified == 0
    items = read_artifact(ctx.paths.failures, Failures).data.items
    assert {f.phase for f in items} >= {"verify"}


def test_verify_budget_stop(ingested):
    eng, tool = ingested
    stub = StubBackend({"UnitExtraction": _unit_reply, "ModuleRollup": MODULE,
                        "ToolRollup": TOOL,
                        "Verdict": '{"verdict": "confirmed", "reason": "yes"}'})
    ctx = _pipeline(eng, tool, stub)
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    ctx = build_context(eng, tool, budget=tracker)
    assert VerifyPhase(backend=stub).run(ctx).status == PhaseStatus.stopped
    mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
    assert mf.stopped_for_budget and not is_fresh(VerifyPhase(backend=stub), ctx)


def test_verify_skipped_without_model(ingested):
    eng, tool = ingested
    assert VerifyPhase().run(build_context(eng, tool)).status == PhaseStatus.skipped
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_verify.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.model.prompts.verify'`.

- [ ] **Step 3: Write the verification prompt**

`src/unvarnish/model/prompts/verify_system.md`:

```markdown
You are an independent reviewer checking one claimed finding about a piece of internally built
software. You see only the claim and the cited source lines. You did not produce the claim and
you have no other context. Decide whether the evidence supports it.

- confirmed: the cited lines show the problem at the claimed severity.
- downgraded: the problem is real but the evidence does not support the claimed severity, or the
  impact is narrower than stated.
- rejected: the cited lines do not show the problem, or the claim misreads the code.

Be strict about evidence and strict about severity in both directions: a real credential in
source is high or critical however small the file; a style preference is never a finding.
Give a one-sentence reason a reader can check against the lines.

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

`src/unvarnish/model/prompts/verify.py`:

```python
from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.finding import Finding
from unvarnish.schemas.verify import Verdict

VERIFY_PROMPT_VERSION = "2026-10-17.1"  # bump whenever the verification prompt changes


@cache
def build_verify_system() -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath("verify_system.md")
                .read_text(encoding="utf-8"))
    return template.replace("{{SCHEMA}}", json.dumps(strict_schema(Verdict), indent=1,
                                                     sort_keys=True))


def build_verify_request(finding: Finding, excerpts: Sequence[str], effort: str | None,
                         system: str | None = None) -> CompletionRequest:
    body = (f"Claim: {finding.title}\nCategory: {finding.category}\n"
            f"Severity claimed: {finding.severity}\nSummary: {finding.summary}\n"
            f"Impact: {finding.impact}\n\nEvidence:\n\n" + "\n\n".join(excerpts))
    return CompletionRequest(system=system or build_verify_system(),
                             messages=[Message(role="user", content=body)],
                             schema_name="Verdict", max_tokens=1024, effort=effort,
                             cache_system=True)
```

- [ ] **Step 4: Write the phase**

`src/unvarnish/phases/verify.py`:

```python
from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.prompts.verify import (
    VERIFY_PROMPT_VERSION,
    build_verify_request,
    build_verify_system,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.cost import CostEntry
from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
    Evidence,
    Finding,
    Severity,
    Source,
    Verification,
)
from unvarnish.schemas.rollup import Module
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings, Verdict

log = logging.getLogger("unvarnish.verify")
VERIFY_SEVERITIES = {Severity.critical, Severity.high}
CONTEXT_LINES = 5
MAX_EXCERPT_LINES = 80
MAX_EVIDENCE = 6

VerdictItem = tuple[str, Verdict | None, str | None]  # finding id, verdict, error


def collect_model_findings(ctx: ToolContext) -> list[Finding]:
    out: list[Finding] = []
    for p in sorted(ctx.paths.unit_dir.glob("*.json")) if ctx.paths.unit_dir.exists() else []:
        try:
            out.extend(read_artifact(p, UnitResult).data.findings)
        except Exception:
            log.warning("skipping unreadable unit artifact %s", p.name)
    for p in sorted(ctx.paths.module_dir.glob("*.json")) if ctx.paths.module_dir.exists() else []:
        try:
            out.extend(read_artifact(p, Module).data.findings)
        except Exception:
            log.warning("skipping unreadable module artifact %s", p.name)
    if ctx.paths.tool_model.exists():
        try:
            out.extend(read_artifact(ctx.paths.tool_model, ToolModel).data.findings)
        except Exception:
            log.warning("skipping unreadable tool.json")
    return [f for f in out if f.source == Source.model]


def _norm(title: str) -> str:
    return " ".join(title.lower().split())


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same category, title, and primary path; keep all evidence."""
    by_key: dict[tuple[str, str, str], Finding] = {}
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path,
                                              f.evidence[0].line_start or 0))
    for f in ordered:
        key = (f.category.value, _norm(f.title), f.evidence[0].path)
        kept = by_key.get(key)
        if kept is None:
            by_key[key] = f.model_copy(deep=True)
            continue
        seen = {(e.path, e.line_start, e.line_end) for e in kept.evidence}
        kept.evidence.extend(e for e in f.evidence
                             if (e.path, e.line_start, e.line_end) not in seen)
        kept.confidence = max(kept.confidence or 0.0, f.confidence or 0.0)
    return list(by_key.values())


def evidence_excerpt(source_root: Path, ev: Evidence, context: int = CONTEXT_LINES,
                     max_lines: int = MAX_EXCERPT_LINES) -> str:
    recorded = f"\nrecorded excerpt: {ev.excerpt}" if ev.excerpt else ""
    try:
        lines = (source_root / ev.path).read_text(encoding="utf-8",
                                                  errors="replace").splitlines()
    except OSError:
        return f"{ev.path}: (file not readable){recorded}"
    if ev.line_start is None:
        return f"{ev.path}: (whole file cited){recorded}"
    lo = max(1, ev.line_start - context)
    hi = min(len(lines), (ev.line_end or ev.line_start) + context, lo + max_lines - 1)
    body = "\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(lo, hi + 1))
    return f"{ev.path} lines {lo}-{hi}:\n{body}"


def downgrade(sev: Severity) -> Severity:
    order = list(Severity)
    return order[min(order.index(sev) + 1, len(order) - 1)]


class VerifyPhase:
    name = "verify"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def inputs_hash(self, ctx: ToolContext) -> str:
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files([ctx.paths.extract_state, ctx.paths.modules_index,
                                        ctx.paths.tool_model]),
                            model_part, VERIFY_PROMPT_VERSION])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.model_findings]

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        system = build_verify_system()
        findings = dedupe_findings(collect_model_findings(ctx))
        to_verify = [f for f in findings if f.severity in VERIFY_SEVERITIES]
        for f in findings:
            if f.severity not in VERIFY_SEVERITIES:
                f.verification = Verification.not_required

        def worker(f: Finding, stop: threading.Event) -> ItemOutcome[VerdictItem]:
            excerpts = [evidence_excerpt(ctx.source_root, e) for e in f.evidence[:MAX_EVIDENCE]]
            req = build_verify_request(f, excerpts, effort, system=system)
            res, failure = call_structured(backend, req, Verdict, phase=self.name,
                                           item_id=f.id, path=f.evidence[0].path, stop=stop)
            if res is None:
                return ItemOutcome(result=(f.id, None, failure.error if failure else "?"),
                                   failures=[failure] if failure else [])
            return ItemOutcome(result=(f.id, res.parsed, None), usage=res.usage)

        outcome = run_parallel(to_verify, worker, workers=ctx.config.pipeline.concurrency,
                               budget=budget)
        verdicts: dict[str, tuple[Verdict | None, str | None]] = {
            fid: (v, err) for fid, v, err in outcome.results}
        counts = {"confirmed": 0, "downgraded": 0, "rejected": 0}
        unverified = 0
        for f in to_verify:
            got = verdicts.get(f.id)
            if got is None:
                f.verification_note = "not verified: budget cap reached"
                continue
            verdict, err = got
            if verdict is None:
                unverified += 1
                f.verification_note = f"verification failed: {err}"
                continue
            f.verification = Verification(verdict.verdict)
            f.verification_note = verdict.reason
            counts[verdict.verdict] += 1
            if verdict.verdict == "downgraded":
                f.severity = downgrade(f.severity)
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path,
                                     f.evidence[0].line_start or 0))
        mf = ModelFindings(tool=ctx.tool, findings=findings, verified=sum(counts.values()),
                           confirmed=counts["confirmed"], downgraded=counts["downgraded"],
                           rejected=counts["rejected"], unverified=unverified,
                           usage=outcome.usage, stopped_for_budget=outcome.stopped_for_budget)
        write_artifact(ctx.paths.model_findings, mf, produced_by=self.name,
                       inputs_hash="" if outcome.stopped else self.inputs_hash(ctx))
        if outcome.usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=outcome.usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, outcome.failures)
        if outcome.fatal is not None:
            raise outcome.fatal
        msg = (f"{len(findings)} model findings, {len(to_verify)} needed verification: "
               f"{counts['confirmed']} confirmed, {counts['downgraded']} downgraded, "
               f"{counts['rejected']} rejected, {unverified} unverified, "
               f"{outcome.usage.total():,} tokens")
        status = PhaseStatus.stopped if outcome.stopped_for_budget else PhaseStatus.ok
        if outcome.stopped_for_budget:
            msg = "budget cap reached: " + msg
        log.info("verify %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in outcome.failures])
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_verify.py -q 2>&1 | tail -3`
Expected: all PASS.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/model/prompts/verify.py src/unvarnish/phases/verify.py tests/test_verify.py
git add src/unvarnish/model/prompts/verify_system.md src/unvarnish/model/prompts/verify.py src/unvarnish/phases/verify.py tests/test_verify.py
git commit -m "feat: verify phase with deduplication, independent evidence-only verification, findings.json"
```

---

### Task 7: Diagram model and Mermaid emitter

**Files:**
- Create: `src/unvarnish/render/diagram.py`
- Test: `tests/test_diagram.py`

**Interfaces:**
- Consumes: `ToolModel` and its parts.
- Produces: `Node(id, label, kind: Literal["actor","tool","module","store","external"])`, `Edge(source, target, label: str | None)`, `Group(id, label, nodes: list[str])`, `Diagram(title, nodes, edges, groups, note: str | None)`, `to_mermaid(d: Diagram) -> str`, `context_diagram(tm: ToolModel) -> Diagram`, `module_diagram(tm: ToolModel, max_nodes: int = 30) -> Diagram`.

- [ ] **Step 1: Write the failing tests**

`tests/test_diagram.py`:

```python
from unvarnish.render.diagram import (
    Diagram,
    Edge,
    Group,
    Node,
    context_diagram,
    module_diagram,
    to_mermaid,
)
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.toolmodel import (
    Actor,
    DataStore,
    ExternalSystem,
    ModuleMapEntry,
    ToolModel,
)


def _tm(module_map=None, externals=None) -> ToolModel:
    return ToolModel(
        tool="expense-bot", purpose="p", actors=[Actor(name="admin", description="d")],
        entry_points=[], data_stores=[DataStore(name="expenses db", kind="db", description="d")],
        external_systems=externals or [
            ExternalSystem(name="AWS S3", kind="storage", direction="outbound", description="d"),
            ExternalSystem(name="Slack", kind="http", direction="both", description="d"),
            ExternalSystem(name="Webhook", kind="http", direction="inbound", description="d")],
        internal_stack=[], module_map=module_map or [], data_flows=[],
        deployment_assumptions=[], capabilities=[], business_rules=[], open_questions=[],
        confidence=0.5, backend="b", model="m", usage=Usage(), prompt_version="v",
    )


def test_to_mermaid_shapes_groups_and_escaping():
    d = Diagram(title="t", nodes=[
        Node(id="a", label='Say "hi"', kind="actor"), Node(id="t", label="tool", kind="tool"),
        Node(id="s", label="db", kind="store"), Node(id="x", label="ext", kind="external"),
        Node(id="m", label="mod", kind="module")],
        edges=[Edge(source="a", target="t", label="uses"), Edge(source="t", target="s"),
               Edge(source="t", target="missing")],
        groups=[Group(id="g1", label="apps", nodes=["m"])])
    out = to_mermaid(d)
    assert out.splitlines()[0] == "flowchart LR"
    assert "n0([\"Say 'hi'\"])" in out and 'n1[["tool"]]' in out
    assert 'n2[("db")]' in out and 'n3{{"ext"}}' in out
    assert 'subgraph g1["apps"]' in out and 'n4["mod"]' in out and "    end" in out
    assert 'n0 -->|"uses"| n1' in out and "n1 --> n2" in out
    assert "missing" not in out


def test_context_diagram_edges_follow_direction():
    d = context_diagram(_tm())
    ids = {n.label: n.id for n in d.nodes}
    edges = {(e.source, e.target) for e in d.edges}
    assert (ids["admin"], ids["expense-bot"]) in edges
    assert (ids["expense-bot"], ids["expenses db"]) in edges
    assert (ids["expense-bot"], ids["AWS S3"]) in edges
    assert (ids["Webhook"], ids["expense-bot"]) in edges
    assert (ids["Slack"], ids["expense-bot"]) in edges and (ids["expense-bot"], ids["Slack"]) in edges
    assert {n.kind for n in d.nodes} == {"actor", "tool", "store", "external"}


def test_module_diagram_caps_and_groups():
    entries = [ModuleMapEntry(path=f"apps/{'ab'[i % 2]}/m{i}.py", role="r",
                              depends_on=[f"apps/{'ab'[(i + 1) % 2]}/m{i + 1}.py"])
               for i in range(40)]
    d = module_diagram(_tm(module_map=entries), max_nodes=25)
    assert len(d.nodes) == 25 and d.note and "25 of 40" in d.note
    assert {g.label for g in d.groups} == {"apps/a", "apps/b"}
    shown = {n.id for n in d.nodes}
    assert all(e.source in shown and e.target in shown for e in d.edges)
    small = module_diagram(_tm(module_map=entries[:3]))
    assert small.note is None and len(small.nodes) == 3
    assert {n.label for n in small.nodes} == {"a/m0.py", "b/m1.py", "a/m2.py"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_diagram.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.render.diagram'`.

- [ ] **Step 3: Write the module**

`src/unvarnish/render/diagram.py`:

```python
from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.toolmodel import ToolModel

Kind = Literal["actor", "tool", "module", "store", "external"]
SHAPES: dict[str, tuple[str, str]] = {
    "actor": ("([", "])"), "tool": ("[[", "]]"), "module": ("[", "]"),
    "store": ("[(", ")]"), "external": ("{{", "}}"),
}


class Node(BaseModel):
    id: str
    label: str
    kind: Kind = "module"


class Edge(BaseModel):
    source: str
    target: str
    label: str | None = None


class Group(BaseModel):
    id: str
    label: str
    nodes: list[str]


class Diagram(BaseModel):
    title: str
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)
    note: str | None = None


def _label(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def to_mermaid(d: Diagram) -> str:
    ids = {n.id: f"n{i}" for i, n in enumerate(d.nodes)}
    by_id = {n.id: n for n in d.nodes}

    def decl(n: Node) -> str:
        open_, close = SHAPES[n.kind]
        return f'{ids[n.id]}{open_}"{_label(n.label)}"{close}'

    grouped = {nid for g in d.groups for nid in g.nodes}
    lines = ["flowchart LR"]
    lines += [f"    {decl(n)}" for n in d.nodes if n.id not in grouped]
    for g in d.groups:
        lines.append(f'    subgraph {g.id}["{_label(g.label)}"]')
        lines += [f"        {decl(by_id[nid])}" for nid in g.nodes if nid in by_id]
        lines.append("    end")
    for e in d.edges:
        if e.source in ids and e.target in ids:
            label = f'|"{_label(e.label)}"|' if e.label else ""
            lines.append(f"    {ids[e.source]} -->{label} {ids[e.target]}")
    return "\n".join(lines)


def context_diagram(tm: ToolModel) -> Diagram:
    nodes = [Node(id="tool", label=tm.tool, kind="tool")]
    edges: list[Edge] = []
    for i, a in enumerate(tm.actors):
        nodes.append(Node(id=f"actor{i}", label=a.name, kind="actor"))
        edges.append(Edge(source=f"actor{i}", target="tool", label="uses"))
    for i, s in enumerate(tm.data_stores):
        nodes.append(Node(id=f"store{i}", label=s.name, kind="store"))
        edges.append(Edge(source="tool", target=f"store{i}", label=s.kind))
    for i, x in enumerate(tm.external_systems):
        nid = f"ext{i}"
        nodes.append(Node(id=nid, label=x.name, kind="external"))
        if x.direction in ("outbound", "both"):
            edges.append(Edge(source="tool", target=nid, label=x.kind))
        if x.direction in ("inbound", "both"):
            edges.append(Edge(source=nid, target="tool", label=x.kind))
    return Diagram(title=f"{tm.tool}: context", nodes=nodes, edges=edges)


def module_diagram(tm: ToolModel, max_nodes: int = 30) -> Diagram:
    entries = tm.module_map
    inbound = Counter(d for m in entries for d in m.depends_on)
    ranked = sorted(entries, key=lambda m: (-(len(m.depends_on) + inbound[m.path]), m.path))
    chosen = ranked[:max_nodes]
    paths = {m.path for m in chosen}
    nodes = [Node(id=m.path, label="/".join(m.path.split("/")[-2:]), kind="module")
             for m in chosen]
    edges = [Edge(source=m.path, target=d) for m in chosen for d in m.depends_on if d in paths]
    dirs: dict[str, list[str]] = {}
    for m in chosen:
        top = m.path.rsplit("/", 1)[0] if "/" in m.path else ""
        dirs.setdefault(top, []).append(m.path)
    groups = ([Group(id=f"g{i}", label=d, nodes=ns)
               for i, (d, ns) in enumerate(sorted(dirs.items())) if d]
              if len(dirs) > 1 else [])
    note = (f"Showing the {len(chosen)} most connected of {len(entries)} modules."
            if len(entries) > max_nodes else None)
    return Diagram(title=f"{tm.tool}: modules", nodes=nodes, edges=edges, groups=groups,
                   note=note)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_diagram.py -q 2>&1 | tail -3`
Expected: all PASS. (The group label for `apps/a/m0.py` is `apps/a`, the directory; the node label is `a/m0.py`, the last two path segments.)

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/render/diagram.py tests/test_diagram.py
git add src/unvarnish/render/diagram.py tests/test_diagram.py
git commit -m "feat: diagram model with Mermaid emitter, context and module diagrams"
```

---

### Task 8: Prose blocks and the `{% prose %}` tag

**Files:**
- Create: `src/unvarnish/model/prompts/prose_system.md`, `src/unvarnish/render/prose.py`
- Modify: `src/unvarnish/render/markdown.py` (extension, `prose_block_names`)
- Test: `tests/test_prose.py`

**Interfaces:**
- Consumes: `Backend`, `CompletionRequest`, `BudgetTracker`, `FailureRecord`, `Usage`.
- Produces:
  - `unvarnish.render.markdown`: `ProseExtension` (registered by `make_env`), `prose_block_names(env, template_name) -> list[str]`.
  - `unvarnish.render.prose`: `PROSE_PROMPT_VERSION = "2026-10-17.1"`, `TONE_INSTRUCTIONS: dict[str, str]`, `ProseBlock(name, instruction, max_words)`, `BLOCKS: dict[str, ProseBlock]` with keys `executive_summary, purpose_and_users, deployment, build_history, open_questions`, `FALLBACK`, `build_prose_system(tone) -> str`, `build_prose_request(block, facts: dict, tone, effort) -> CompletionRequest` (schema_name `"prose"`, no schema), `clean_prose(text) -> str`, `ProseResult(text: dict[str, str], usage, failures, stopped_for_budget)`, `generate_prose(backend: Backend | None, requested: dict[str, dict], *, tone, effort, budget) -> ProseResult`.

- [ ] **Step 1: Write the failing tests**

`tests/test_prose.py`:

```python
import pytest
from jinja2 import DictLoader, Environment, TemplateRuntimeError

from tests.stub_backend import StubBackend
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionResponse
from unvarnish.model.budget import BudgetTracker
from unvarnish.render.markdown import ProseExtension, make_env, prose_block_names
from unvarnish.render.prose import (
    BLOCKS,
    FALLBACK,
    build_prose_request,
    clean_prose,
    generate_prose,
)
from unvarnish.schemas.cost import Usage


def _env(source: str) -> Environment:
    env = Environment(loader=DictLoader({"t.md.j2": source}), extensions=[ProseExtension])
    return env


def test_prose_tag_renders_from_prose_dict():
    env = _env('A {% prose "executive_summary" %} B')
    out = env.get_template("t.md.j2").render(prose={"executive_summary": "X"})
    assert out == "A X B"


def test_prose_tag_unknown_block_raises():
    env = _env('{% prose "nope" %}')
    with pytest.raises(TemplateRuntimeError, match="nope"):
        env.get_template("t.md.j2").render(prose={})


def test_prose_block_names_from_template_source():
    env = _env('x {% prose "a_block" %} y {%  prose  "b_block"  %} {% prose "a_block" %}')
    assert prose_block_names(env, "t.md.j2") == ["a_block", "b_block"]
    assert "executive_summary" in prose_block_names(make_env(), "findings.md.j2")


def test_prose_request_carries_tone_instruction_and_facts():
    block = BLOCKS["executive_summary"]
    req = build_prose_request(block, {"tool": "x", "critical": 2}, tone="direct", effort="low")
    assert req.schema_name == "prose" and req.output_schema is None
    assert "minor, simply, just" in req.system
    assert '"critical": 2' in req.messages[0].content
    assert f"under {block.max_words} words" in req.messages[0].content
    measured = build_prose_request(block, {}, tone="measured", effort=None)
    assert "acknowledge uncertainty" in measured.system and "minimise" in measured.system


def test_clean_prose_strips_fences_and_whitespace():
    assert clean_prose("```markdown\nHello.\n```\n") == "Hello."
    assert clean_prose("  Plain.  ") == "Plain."


def test_generate_prose_without_backend_falls_back():
    res = generate_prose(None, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert res.text == {"executive_summary": FALLBACK.format(reason="no model configured")}
    assert res.failures == [] and res.usage.total() == 0


def test_generate_prose_with_backend():
    stub = StubBackend({"prose": "A paragraph."})
    res = generate_prose(stub, {"executive_summary": {"a": 1}, "deployment": {}},
                         tone="direct", effort=None, budget=BudgetTracker(None))
    assert res.text == {"executive_summary": "A paragraph.", "deployment": "A paragraph."}
    assert res.usage.total() == 240 and stub.count("prose") == 2


def test_generate_prose_unknown_block_falls_back():
    stub = StubBackend({"prose": "A paragraph."})
    res = generate_prose(stub, {"nonexistent": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert res.text["nonexistent"].startswith("_No model-written text")
    assert "unknown prose block" in res.text["nonexistent"]
    assert res.failures and res.failures[0].unit_id == "nonexistent"
    assert stub.requests == []


def test_generate_prose_failure_and_refusal_fall_back():
    stub = StubBackend({"prose": BackendError("400")})
    res = generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert "model call failed" in res.text["executive_summary"] and len(res.failures) == 1

    def refuse(req):
        return ""
    stub2 = StubBackend({"prose": refuse})
    res2 = generate_prose(stub2, {"executive_summary": {}}, tone="direct", effort=None,
                          budget=BudgetTracker(None))
    assert "empty" in res2.text["executive_summary"] and len(res2.failures) == 1


def test_generate_prose_outage_propagates():
    stub = StubBackend({"prose": BackendUnavailable("down")})
    with pytest.raises(BackendUnavailable):
        generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                       budget=BudgetTracker(None))


def test_generate_prose_budget_stop():
    stub = StubBackend({"prose": "A paragraph."})
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    res = generate_prose(stub, {"executive_summary": {}}, tone="direct", effort=None,
                         budget=tracker)
    assert res.stopped_for_budget and "budget cap" in res.text["executive_summary"]
    assert stub.requests == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_prose.py -q 2>&1 | tail -3`
Expected: FAIL with `ImportError: cannot import name 'ProseExtension'`.

- [ ] **Step 3: Write the Jinja extension**

In `src/unvarnish/render/markdown.py`, add imports and the extension, register it in `make_env`, and add `prose_block_names`:

```python
import re

from jinja2 import (
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
    StrictUndefined,
    TemplateRuntimeError,
    nodes,
)
from jinja2.ext import Extension

PROSE_TAG_RE = re.compile(r"{%-?\s*prose\s+\"([a-z_][a-z0-9_]*)\"\s*-?%}")


class ProseExtension(Extension):
    """`{% prose "name" %}` renders `prose["name"]`, a model-written block, or fails loudly."""

    tags = {"prose"}

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        name = parser.parse_expression()
        call = self.call_method("_lookup", [name, nodes.Name("prose", "load")], lineno=lineno)
        return nodes.Output([call], lineno=lineno)

    @staticmethod
    def _lookup(name: str, prose) -> str:
        if not isinstance(prose, dict) or name not in prose:
            raise TemplateRuntimeError(f"unknown prose block {name!r}")
        return prose[name]


def prose_block_names(env: Environment, template_name: str) -> list[str]:
    """Prose block names a template references, in first-seen order."""
    assert env.loader is not None
    source, _, _ = env.loader.get_source(env, template_name)
    return list(dict.fromkeys(PROSE_TAG_RE.findall(source)))
```

and in `make_env` pass `extensions=[ProseExtension]` to `Environment(...)`.

- [ ] **Step 4: Write the prose prompt and generator**

`src/unvarnish/model/prompts/prose_system.md`:

```markdown
You write one block of prose for a consultant's report on internally built software. The reader
is the organisation's leadership and the engineers who will act on the report; assume the reader
does not code. You receive the block's instruction and the facts as JSON.

Rules:
- Use only the facts given. Never invent numbers, names, files, or findings. If a fact is
  missing, say what is not known rather than guessing.
- Plain English. No headings. No bullet lists unless the instruction asks for a list. No
  Markdown emphasis. No code formatting.
- Do not mention that you are a model, that the facts came as JSON, or restate the instruction.
- Do not open with the tool's name followed by "is a"; lead with what matters to the reader.

Tone: {{TONE}}
```

`src/unvarnish/render/prose.py`:

```python
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

from unvarnish.model.base import (
    Backend,
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    Message,
)
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.prose")
PROSE_PROMPT_VERSION = "2026-10-17.1"  # bump whenever prose_system.md, tones, or blocks change
FALLBACK = "_No model-written text for this section: {reason}._"
FENCE_RE = re.compile(r"^```[a-z]*\n(.*?)\n```$", re.DOTALL)

TONE_INSTRUCTIONS = {
    "direct": (
        "State problems plainly and quantify where possible. Never hedge or soften a scanner "
        "finding. When describing a high or critical finding, do not use minimising words such "
        "as minor, simply, just, slight, or only. Avoid jargon. Say what will happen if nothing "
        "changes."
    ),
    "measured": (
        "State problems accurately with their likelihood and context, and quantify where "
        "possible. Do not minimise high or critical findings, but acknowledge uncertainty where "
        "the facts are incomplete. Avoid jargon."
    ),
}


@dataclass(frozen=True)
class ProseBlock:
    name: str
    instruction: str
    max_words: int


BLOCKS: dict[str, ProseBlock] = {b.name: b for b in (
    ProseBlock("executive_summary", (
        "Write the executive summary for leadership in two to four short paragraphs. First, what "
        "the tool is and who uses it. Then the headline risks, worst first, with the counts of "
        "critical and high findings and what each headline risk means in business terms. Finish "
        "with the consequence of leaving the tool as it is."), 350),
    ProseBlock("purpose_and_users", (
        "Write one or two paragraphs on what the tool does, who the actors are, and how they "
        "reach it. Name the actors and entry points from the facts."), 250),
    ProseBlock("deployment", (
        "Write one paragraph on where and how the tool runs and what it assumes about its "
        "environment, drawn from the deployment assumptions, internal stack, and external "
        "systems. State which assumptions would break it if wrong."), 200),
    ProseBlock("build_history", (
        "Write one paragraph on how the tool was built, from the history facts: over how long, "
        "by how many people, how concentrated the authorship is, how large the commits are, and "
        "what the AI tooling indicators suggest. Neutral: this is evidence, not judgement."), 180),
    ProseBlock("open_questions", (
        "Write the open questions for stakeholder interviews as a numbered list, one line each, "
        "at most twelve. Draw them from the open questions, the implicit capabilities, the "
        "business rules found in code, and anything not analysed. Each question must be "
        "answerable by a person who owns or uses the tool."), 300),
)}


@cache
def build_prose_system(tone: str) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath("prose_system.md")
                .read_text(encoding="utf-8"))
    return template.replace("{{TONE}}", TONE_INSTRUCTIONS[tone])


def build_prose_request(block: ProseBlock, facts: dict, tone: str,
                        effort: str | None) -> CompletionRequest:
    body = (f"{block.instruction}\nKeep it under {block.max_words} words.\n\nFacts (JSON):\n"
            + json.dumps(facts, ensure_ascii=False, indent=1, default=str))
    return CompletionRequest(system=build_prose_system(tone),
                             messages=[Message(role="user", content=body)],
                             schema_name="prose", output_schema=None, max_tokens=2000,
                             effort=effort, cache_system=True)


def clean_prose(text: str) -> str:
    text = text.strip()
    m = FENCE_RE.match(text)
    return m.group(1).strip() if m else text


@dataclass
class ProseResult:
    text: dict[str, str] = field(default_factory=dict)
    usage: Usage = field(default_factory=Usage)
    failures: list[FailureRecord] = field(default_factory=list)
    stopped_for_budget: bool = False


def generate_prose(backend: Backend | None, requested: dict[str, dict], *, tone: str,
                   effort: str | None, budget: BudgetTracker) -> ProseResult:
    """Fill each requested block; every failure except an outage becomes a fallback sentence."""
    out = ProseResult()
    for name, facts in requested.items():
        block = BLOCKS.get(name)
        if block is None:
            out.text[name] = FALLBACK.format(reason=f"unknown prose block {name!r}")
            out.failures.append(FailureRecord(phase="render", unit_id=name,
                                              error=f"unknown prose block {name!r}"))
            continue
        if backend is None:
            out.text[name] = FALLBACK.format(reason="no model configured")
            continue
        try:
            budget.check()
        except BudgetExceeded:
            out.text[name] = FALLBACK.format(reason="budget cap reached")
            out.stopped_for_budget = True
            continue
        try:
            resp = backend.complete(build_prose_request(block, facts, tone, effort))
        except BackendUnavailable:
            raise
        except BackendError as exc:
            out.text[name] = FALLBACK.format(reason="model call failed")
            out.failures.append(FailureRecord(phase="render", unit_id=name,
                                              error=str(exc)[:500]))
            continue
        out.usage = out.usage + resp.usage
        budget.add(resp.usage)
        if resp.refusal_category is not None or not resp.text.strip():
            reason = "model refused" if resp.refusal_category else "model returned empty text"
            out.text[name] = FALLBACK.format(reason=reason)
            out.failures.append(FailureRecord(phase="render", unit_id=name, error=reason))
            continue
        out.text[name] = clean_prose(resp.text)
        log.debug("prose %s: %d tokens", name, resp.usage.total())
    return out
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_prose.py tests/test_render.py -q 2>&1 | tail -3`
Expected: `test_prose_block_names_from_template_source` still FAILS on the `findings.md.j2` assertion (the template gains its prose tag in Task 9); every other test PASSES. Mark that one `xfail(strict=True, reason="findings.md.j2 gets its prose tag in Task 9")` for this commit and remove the marker in Task 9.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/render/markdown.py src/unvarnish/render/prose.py tests/test_prose.py
git add src/unvarnish/model/prompts/prose_system.md src/unvarnish/render/markdown.py src/unvarnish/render/prose.py tests/test_prose.py
git commit -m "feat: prose blocks with tone instructions and a Jinja prose tag"
```

---

### Task 9: Render the three documents

**Files:**
- Create: `src/unvarnish/render/inputs.py`, `src/unvarnish/render/architecture.py`, `src/unvarnish/render/requirements.py`, `src/unvarnish/render/templates/architecture.md.j2`, `src/unvarnish/render/templates/requirements.md.j2`
- Modify: `src/unvarnish/render/findings.py`, `src/unvarnish/render/templates/findings.md.j2`, `src/unvarnish/phases/render.py`, `tests/test_prose.py` (remove the xfail marker)
- Test: `tests/test_render_documents.py`; existing `tests/test_render.py` must keep passing unchanged.

**Interfaces:**
- Consumes: Tasks 1, 6, 7, 8; existing `make_env`, `render_document`, `template_source_hash`, `template_override_dirs`, `RenderState`.
- Produces:
  - `unvarnish.render.inputs`: `RenderInputs` dataclass (`census, metrics, git, deps, scan` required; `units, extract_state, modules, tool_model, requirements, model_findings, failures` optional, default `None`), `load_render_inputs(ctx) -> RenderInputs`.
  - `unvarnish.render.findings`: `build_findings_context(ctx, inp: RenderInputs) -> dict` (new signature), `merged_findings(scan: list[Finding], model: list[Finding]) -> list[Finding]`, `ai_indicators(git: GitStats) -> list[str]`, `analysis_mode(inp) -> str`.
  - `unvarnish.render.architecture.build_architecture_context(ctx, inp) -> dict`, `unvarnish.render.requirements.build_requirements_context(ctx, inp) -> dict`. Every context dict carries `prose_facts: dict[str, dict]` keyed by prose block name.
  - `RenderPhase(backend: Backend | None = None)`; `outputs` lists `render_state`, `findings_doc`, and the other two documents when their inputs exist.

- [ ] **Step 1: Write the failing tests**

`tests/test_render_documents.py`:

```python
import json

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
    verdict = "rejected" if "No auth anywhere" in body else "confirmed"
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
    assert "## Executive summary" in findings
    assert "PROSE Write the executive summary" in findings
    assert "model-assisted analysis (stub/stub-model)" in findings
    assert "verification: confirmed" in findings
    assert "**Verifier.** checked the lines" in findings
    assert "No auth anywhere" not in findings  # rejected: excluded from the document
    assert "rejected on verification and are excluded" in findings
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
        if "File: README.md" in req.messages[-1].content:
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_render_documents.py -q 2>&1 | tail -3`
Expected: FAIL (`RenderPhase.__init__() got an unexpected keyword argument 'backend'`).

- [ ] **Step 3: Write the inputs loader and the findings context**

`src/unvarnish/render/inputs.py`:

```python
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import ToolContext
from unvarnish.schemas.analysis import ExtractState, Failures, UnitsIndex
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.rollup import ModulesIndex
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import RequirementsInventory, ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.render")


@dataclass
class RenderInputs:
    census: Census
    metrics: Metrics
    git: GitStats
    deps: Dependencies
    scan: ScannerFindings
    units: UnitsIndex | None = None
    extract_state: ExtractState | None = None
    modules: ModulesIndex | None = None
    tool_model: ToolModel | None = None
    requirements: RequirementsInventory | None = None
    model_findings: ModelFindings | None = None
    failures: Failures | None = None


def _optional[T: BaseModel](path: Path, cls: type[T]) -> T | None:
    if not path.exists():
        return None
    try:
        return read_artifact(path, cls).data
    except Exception as exc:  # a corrupt optional artifact must not block the documents
        log.warning("ignoring unreadable %s: %r", path.name, exc)
        return None


def load_render_inputs(ctx: ToolContext) -> RenderInputs:
    p = ctx.paths
    return RenderInputs(
        census=read_artifact(p.census, Census).data,
        metrics=read_artifact(p.metrics, Metrics).data,
        git=read_artifact(p.git, GitStats).data,
        deps=read_artifact(p.dependencies, Dependencies).data,
        scan=read_artifact(p.scanner_findings, ScannerFindings).data,
        units=_optional(p.units_index, UnitsIndex),
        extract_state=_optional(p.extract_state, ExtractState),
        modules=_optional(p.modules_index, ModulesIndex),
        tool_model=_optional(p.tool_model, ToolModel),
        requirements=_optional(p.capabilities, RequirementsInventory),
        model_findings=_optional(p.model_findings, ModelFindings),
        failures=_optional(p.failures, Failures),
    )
```

Replace `src/unvarnish/render/findings.py` with:

```python
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from unvarnish.analysis.languages import Classification
from unvarnish.phases.base import ToolContext
from unvarnish.render.inputs import RenderInputs
from unvarnish.schemas.finding import SEVERITY_ORDER, Finding, Severity, Source, Verification
from unvarnish.schemas.git import GitStats

EXAMPLES_PER_REASON = 5
HEADLINE_FINDINGS = 12
FAILED_UNITS_SHOWN = 10


def _severity_groups(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    groups: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.severity].append(f)
    return [(sev.value, groups[sev]) for sev in sorted(groups, key=SEVERITY_ORDER.__getitem__)]


def merged_findings(scan: list[Finding], model: list[Finding]) -> list[Finding]:
    """Scanner and live model findings, by severity; scanner first at equal severity."""
    live = [f for f in model if f.verification != Verification.rejected]
    return sorted([*scan, *live], key=lambda f: (
        SEVERITY_ORDER[f.severity], 0 if f.source == Source.scanner else 1,
        f.evidence[0].path, f.evidence[0].line_start or 0))


def ai_indicators(git: GitStats) -> list[str]:
    ai = git.ai_fingerprints
    out = list(ai.files) + [f"Co-Authored-By {name} ×{n}" for name, n in
                            ai.coauthor_trailers.items()]
    if ai.message_patterns:
        out.append(f"{ai.message_patterns} commit message(s) mention AI generation")
    return out


def analysis_mode(inp: RenderInputs) -> str:
    if inp.extract_state is None:
        return "scanners only"
    return f"{inp.extract_state.backend}/{inp.extract_state.model}"


def generated_at() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def model_gaps(inp: RenderInputs) -> dict:
    units = inp.units
    windowed = [u.path for u in units.units if u.split_method == "windowed"] if units else []
    failed_units = [f for f in (inp.failures.items if inp.failures else [])
                    if f.phase == "extract"]
    return {
        "windowed": {"count": len(windowed),
                     "examples": list(dict.fromkeys(windowed))[:EXAMPLES_PER_REASON]},
        "failed_units": [{"path": f.path, "error": f.error} for f in
                         failed_units[:FAILED_UNITS_SHOWN]],
        "failed_units_count": len(failed_units),
        "failed_modules": list(inp.modules.failed) if inp.modules else [],
        "modules_without_units": list(inp.modules.skipped) if inp.modules else [],
        "skipped_split": [s.model_dump() for s in units.skipped] if units else [],
        "rejected": inp.model_findings.rejected if inp.model_findings else 0,
    }


def build_findings_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    census, metrics, git, deps, scan = inp.census, inp.metrics, inp.git, inp.deps, inp.scan
    live = [f for f in census.files if not f.excluded]
    analysed = [f for f in live if f.classification != Classification.binary]
    source_lines = sum(f.lines for f in live if f.classification == Classification.source)
    largest = sorted(metrics.files, key=lambda m: -m.lines)[:5]
    longest = max((m for m in metrics.files if m.max_function_lines),
                  key=lambda m: m.max_function_lines or 0, default=None)
    languages = sorted(census.languages.items(), key=lambda kv: -kv[1])[:5]

    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    secrets_history = [f for f in secrets if f.title.endswith("in git history")]
    mf = inp.model_findings
    all_findings = merged_findings(scan.findings, mf.findings if mf else [])
    model_live = [f for f in all_findings if f.source == Source.model]
    by_sev = [(sev.value, n) for sev in Severity
              if (n := sum(1 for f in all_findings if f.severity == sev))]

    excluded: dict[str, list[str]] = defaultdict(list)
    for f in census.files:
        if f.excluded and f.exclusion_reason:
            excluded[f.exclusion_reason].append(f.path)
    not_analysed = [
        {"reason": reason, "count": len(paths), "examples": paths[:EXAMPLES_PER_REASON]}
        for reason, paths in sorted(excluded.items())
    ]
    binaries = [f.path for f in live if f.classification == Classification.binary]
    gaps = model_gaps(inp)
    everything_analysed = not (
        not_analysed or binaries or census.failures or scan.skipped or not git.available
        or gaps["windowed"]["count"] or gaps["failed_units_count"] or gaps["failed_modules"]
        or gaps["skipped_split"] or gaps["modules_without_units"]
    )
    indicators = ai_indicators(git)
    numbers = {
        "total_findings": len(all_findings),
        "by_severity": by_sev,
        "critical_or_high": sum(1 for f in all_findings
                                if f.severity in (Severity.critical, Severity.high)),
        "scanner_findings": len(scan.findings),
        "model_findings": None if mf is None else len(model_live),
        "verification": None if mf is None else {
            "confirmed": mf.confirmed, "downgraded": mf.downgraded,
            "rejected": mf.rejected, "unverified": mf.unverified},
        "analysis_mode": analysis_mode(inp),
        "analysed_files": len(analysed),
        "source_lines": source_lines,
        "largest_files": largest,
        "largest_file": largest[0] if largest else None,
        "longest_function": longest,
        "languages": languages,
        "tests_present": any(f.classification == Classification.test for f in live),
        "secrets_current": len(secrets) - len(secrets_history),
        "secrets_history": len(secrets_history),
        "ai_indicators": indicators,
    }
    tm = inp.tool_model
    prose_facts = {"executive_summary": {
        "tool": ctx.meta.name, "client": ctx.config.client,
        "purpose": tm.purpose if tm else None,
        "actors": [a.name for a in tm.actors] if tm else [],
        "size": {"files_analysed": len(analysed), "source_lines": source_lines,
                 "languages": dict(languages),
                 "largest_file": {"path": largest[0].path, "lines": largest[0].lines}
                 if largest else None},
        "findings": {"total": len(all_findings), "by_severity": dict(by_sev),
                     "scanner": len(scan.findings),
                     "model": numbers["model_findings"],
                     "verification": numbers["verification"]},
        "headline_findings": [{
            "title": f.title, "severity": f.severity.value, "category": f.category.value,
            "source": f.source.value, "impact": f.impact,
            "verification": f.verification.value if f.verification else "unverified"}
            for f in all_findings[:HEADLINE_FINDINGS]],
        "tests_present": numbers["tests_present"],
        "secrets": {"current": numbers["secrets_current"],
                    "in_history": numbers["secrets_history"]},
        "bus_factor": git.bus_factor, "top_author_share": git.top_author_share,
        "ai_tooling_indicators": indicators,
        "not_analysed": {"excluded_files": census.totals.excluded_files,
                         "failed_units": gaps["failed_units_count"],
                         "windowed_units": gaps["windowed"]["count"],
                         "failed_modules": len(gaps["failed_modules"])},
    }}
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "census": census, "metrics": metrics, "git": git,
        "deps": deps, "scan": scan, "severity_groups": _severity_groups(all_findings),
        "numbers": numbers, "not_analysed": not_analysed, "binaries": binaries,
        "model_gaps": gaps, "everything_analysed": everything_analysed,
        "prose_facts": prose_facts,
    }
```

- [ ] **Step 4: Write the architecture and requirements contexts**

`src/unvarnish/render/architecture.py`:

```python
from __future__ import annotations

from unvarnish.phases.base import ToolContext
from unvarnish.render.diagram import context_diagram, module_diagram, to_mermaid
from unvarnish.render.findings import ai_indicators, analysis_mode, generated_at
from unvarnish.render.inputs import RenderInputs

TOP_AUTHORS = 5


def build_architecture_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    tm = inp.tool_model
    assert tm is not None, "architecture.md needs tool.json"
    digests = {d.path: d for d in inp.modules.modules} if inp.modules else {}
    module_rows = []
    for m in tm.module_map:
        d = digests.get(m.path)
        module_rows.append({"path": m.path, "role": m.role, "depends_on": m.depends_on,
                            "units": d.units if d else None, "lines": d.lines if d else None,
                            "findings": d.findings if d else None})
    mod_diagram = module_diagram(tm)
    units = inp.units
    st = inp.extract_state
    coverage = {
        "units_total": len(units.units) if units else 0,
        "units_done": st.units_done if st else 0,
        "units_failed": st.units_failed if st else 0,
        "windowed": sum(1 for u in units.units if u.split_method == "windowed") if units else 0,
        "modules_rolled": len(inp.modules.modules) if inp.modules else 0,
        "modules_failed": len(inp.modules.failed) if inp.modules else 0,
        "modules_without_units": len(inp.modules.skipped) if inp.modules else 0,
        "skipped_split": len(units.skipped) if units else 0,
    }
    git = inp.git
    languages = sorted(inp.census.languages.items(), key=lambda kv: -kv[1])[:8]
    indicators = ai_indicators(git)
    prose_facts = {
        "purpose_and_users": {
            "tool": ctx.meta.name, "purpose": tm.purpose,
            "actors": [a.model_dump() for a in tm.actors],
            "entry_points": [e.model_dump() for e in tm.entry_points],
            "capabilities_count": len(tm.capabilities),
        },
        "deployment": {
            "deployment_assumptions": tm.deployment_assumptions,
            "internal_stack": tm.internal_stack,
            "frameworks_detected": inp.census.frameworks, "languages": dict(languages),
            "external_systems": [s.model_dump(exclude={"modules"})
                                 for s in tm.external_systems],
            "data_stores": [s.model_dump(exclude={"modules"}) for s in tm.data_stores],
        },
        "build_history": {
            "available": git.available, "reason": git.reason,
            "commit_count": git.commit_count,
            "first_commit": git.first_commit.date().isoformat() if git.first_commit else None,
            "last_commit": git.last_commit.date().isoformat() if git.last_commit else None,
            "active_days": git.active_days,
            "authors": [{"name": a.name, "commits": a.commits, "share": round(a.share, 2)}
                        for a in git.authors[:TOP_AUTHORS]],
            "author_count": len(git.authors), "bot_count": len(git.bots),
            "bus_factor": git.bus_factor, "top_author_share": git.top_author_share,
            "large_commits": len(git.large_commits),
            "large_commit_threshold": git.large_commit_threshold,
            "ai_tooling_indicators": indicators,
        },
    }
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "tm": tm, "census": inp.census, "deps": inp.deps,
        "git": git, "languages": languages, "module_rows": module_rows,
        "context_mermaid": to_mermaid(context_diagram(tm)),
        "module_mermaid": to_mermaid(mod_diagram), "module_diagram_note": mod_diagram.note,
        "coverage": coverage, "ai_indicators": indicators,
        "analysis_mode": analysis_mode(inp), "prose_facts": prose_facts,
    }
```

`src/unvarnish/render/requirements.py`:

```python
from __future__ import annotations

from unvarnish.phases.base import ToolContext
from unvarnish.render.findings import analysis_mode, generated_at, model_gaps
from unvarnish.render.inputs import RenderInputs


def capability_label(actor: str, action: str, obj: str) -> str:
    return f"{actor} can {action} {obj}"


def build_requirements_context(ctx: ToolContext, inp: RenderInputs) -> dict:
    req = inp.requirements
    assert req is not None, "requirements.md needs capabilities.json"
    caps = sorted(req.capabilities,
                  key=lambda c: (c.actor.lower(), c.action.lower(), c.object.lower()))
    labels = {c.id: capability_label(c.actor, c.action, c.object) for c in caps}
    data_rows = [{"name": r.name, "kind": r.kind, "description": r.description,
                  "used_by": [labels[i] for i in r.used_by if i in labels]}
                 for r in req.data_inventory]
    gaps = model_gaps(inp)
    prose_facts = {"open_questions": {
        "tool": ctx.meta.name,
        "open_questions_from_analysis": req.open_questions,
        "actors": [a.name for a in req.actors],
        "implicit_capabilities": [f"{labels[c.id]}: {c.description}" for c in caps
                                  if c.implicit],
        "capabilities_without_known_module": [labels[c.id] for c in caps if not c.evidence],
        "business_rules": [r.model_dump() for r in req.business_rules],
        "not_analysed": {"failed_units": gaps["failed_units_count"],
                         "windowed_units": gaps["windowed"]["count"],
                         "failed_modules": len(gaps["failed_modules"]),
                         "files_not_split": len(gaps["skipped_split"])},
    }}
    return {
        "tool": ctx.meta, "client": ctx.config.client, "consultant": ctx.config.consultant,
        "generated_at": generated_at(), "req": req, "capabilities": caps,
        "implicit_count": sum(1 for c in caps if c.implicit), "data_rows": data_rows,
        "analysis_mode": analysis_mode(inp), "prose_facts": prose_facts,
    }
```

- [ ] **Step 5: Write the templates**

`trim_blocks` removes the newline after any `{% %}` tag, including `{% prose %}`; every prose tag below is followed by `{{ "" }}` so the paragraph break after it survives.

Replace `src/unvarnish/render/templates/findings.md.j2` with:

```jinja
# {{ tool.name }}: Findings

**Client:** {{ client or "—" }} · **Prepared by:** {{ consultant or "—" }} · **Generated:** {{ generated_at }}
**Source:** {{ tool.origin_kind }} `{{ tool.origin }}`{% if tool.commit %} at `{{ tool.commit[:12] }}`{% endif %}

{{ "" }}
{% if numbers.model_findings is none %}
> Produced by Unvarnish's deterministic scanners. Every finding below is reproducible and traceable to a
> file and line. Model-assisted analysis was not run for this document.
{% else %}
> Produced by Unvarnish's deterministic scanners and model-assisted analysis ({{ numbers.analysis_mode }}).
> Every finding is traceable to a file and line. Model findings rated high or critical were checked by an
> independent verification pass that saw only the claim and the cited lines; each shows its status.
{% endif %}

## Executive summary

{% prose "executive_summary" %}{{ "" }}

## Summary

{{ numbers.total_findings }} finding(s){% if numbers.by_severity %}: {% for sev, n in numbers.by_severity %}{{ n }} {{ sev }}{{ ", " if not loop.last }}{% endfor %}{% endif %}.
{% if numbers.model_findings is not none %}
Scanner findings: {{ numbers.scanner_findings }}. Model findings: {{ numbers.model_findings }} ({{ numbers.verification.confirmed }} confirmed, {{ numbers.verification.downgraded }} downgraded, {{ numbers.verification.unverified }} unverified; {{ numbers.verification.rejected }} rejected on verification and excluded).
{% endif %}
{% if numbers.critical_or_high %}

**{{ numbers.critical_or_high }} finding(s) are critical or high severity and need action before this tool is relied on further.**
{% endif %}

## By the numbers

| Measure | Value |
|---|---|
| Files analysed / total | {{ numbers.analysed_files | fmt_int }} / {{ census.totals.files | fmt_int }} |
| Source lines | {{ numbers.source_lines | fmt_int }} |
{% if numbers.largest_file %}
| Largest file | `{{ numbers.largest_file.path }}` ({{ numbers.largest_file.lines | fmt_int }} lines) |
{% endif %}
{% if numbers.longest_function %}
| Longest function | `{{ numbers.longest_function.max_function_name }}` in `{{ numbers.longest_function.path }}` ({{ numbers.longest_function.max_function_lines | fmt_int }} lines) |
{% endif %}
| Languages (source lines) | {% for lang, n in numbers.languages %}{{ lang }} {{ n | fmt_int }}{{ "; " if not loop.last }}{% else %}—{% endfor %} |
| Frameworks | {{ census.frameworks | join(", ") if census.frameworks else "none detected" }} |
| Automated tests | {{ "present" if numbers.tests_present else "**none**" }} |
| Secrets (current / history only) | {{ numbers.secrets_current }} / {{ numbers.secrets_history }} |
| Dependencies declared | {{ deps.dependencies | length }} |
| Dependency vulnerabilities | {% if deps.advisories_checked %}{{ deps.advisories | length }}{% else %}not checked (advisory database unavailable){% endif %} |
{% if numbers.model_findings is not none %}
| Model findings (after verification) | {{ numbers.model_findings }} ({{ numbers.verification.rejected }} rejected) |
{% endif %}
{% if git.available %}
| Commits · authors · active days | {{ git.commit_count | fmt_int }} · {{ git.authors | length }} · {{ git.active_days }} |
| History span | {{ git.first_commit.date() }} to {{ git.last_commit.date() }} |
| Top author share · bus factor | {{ git.top_author_share | pct }} · {{ git.bus_factor }} |
| Commits over {{ git.large_commit_threshold | fmt_int }} lines | {{ git.large_commits | length }} |
{% else %}
| Git history | unavailable ({{ git.reason }}) |
{% endif %}
| AI tooling indicators | {{ numbers.ai_indicators | join("; ") if numbers.ai_indicators else "none found" }} |

{% if numbers.largest_files %}
### Largest files

| File | Lines | Longest function |
|---|---:|---|
{% for m in numbers.largest_files %}
| `{{ m.path }}` | {{ m.lines | fmt_int }} | {% if m.max_function_name %}`{{ m.max_function_name }}` ({{ m.max_function_lines | fmt_int }}){% else %}—{% endif %} |
{% endfor %}
{% endif %}

## Findings

{% if not severity_groups %}
No findings.
{% endif %}
{% for sev, group in severity_groups %}
### {{ sev | capitalize }} ({{ group | length }})

{% for f in group %}
#### {{ f.title }}

`{{ f.category }}` · source: {% if f.source == "scanner" %}scanner ({{ f.scanner }}){% else %}model{% if f.verification %} · verification: {{ f.verification }}{% else %} · **unverified**{% endif %}{% endif %} · id `{{ f.id }}`

{{ f.summary }}

**Impact.** {{ f.impact }}

**Remediation.** {{ f.remediation }}
{% if f.verification_note %}

**Verifier.** {{ f.verification_note }}
{% endif %}

**Evidence.**
{% for e in f.evidence %}
- `{{ e.path }}{% if e.line_start %}:{{ e.line_start }}{% if e.line_end and e.line_end != e.line_start %}-{{ e.line_end }}{% endif %}{% endif %}`{% if e.excerpt %} — `{{ e.excerpt }}`{% endif %}{% if e.note %} ({{ e.note }}){% endif %}
{% endfor %}
{{ "" }}
{% endfor %}
{% endfor %}
## Not analysed

{% if not_analysed %}
Excluded from analysis but counted in totals:

{% for group in not_analysed %}
- **{{ group.reason }}**: {{ group.count }} file(s){% if group.examples %} — e.g. {% for p in group.examples %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}{% endif %}{{ "" }}
{% endfor %}

{% endif %}
{% if binaries %}
Binary files ({{ binaries | length }}): {% for p in binaries[:10] %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}{% if binaries | length > 10 %}, …{% endif %}{{ "" }}

{% endif %}
{% if census.failures %}
Files that could not be read or measured:

{% for f in census.failures %}
- {{ f }}
{% endfor %}

{% endif %}
{% if scan.skipped %}
Scanners that failed and were skipped:

{% for s in scan.skipped %}
- **{{ s.name }}**: `{{ s.error }}`
{% endfor %}

{% endif %}
{% if model_gaps.skipped_split %}
Files not split for model analysis ({{ model_gaps.skipped_split | length }}):

{% for s in model_gaps.skipped_split %}
- `{{ s.path }}`: {{ s.reason }}
{% endfor %}

{% endif %}
{% if model_gaps.windowed.count %}
Windowed regions: {{ model_gaps.windowed.count }} unit(s) were analysed as fixed-size windows because no structural boundary fit, so findings there may lack context — e.g. {% for p in model_gaps.windowed.examples %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}.

{% endif %}
{% if model_gaps.failed_units %}
Units the model could not analyse ({{ model_gaps.failed_units_count }}{% if model_gaps.failed_units_count > model_gaps.failed_units | length %}, first {{ model_gaps.failed_units | length }} shown{% endif %}):

{% for u in model_gaps.failed_units %}
- `{{ u.path }}`: {{ u.error }}
{% endfor %}

{% endif %}
{% if model_gaps.failed_modules %}
Files whose module rollup failed: {% for p in model_gaps.failed_modules %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}.

{% endif %}
{% if model_gaps.modules_without_units %}
Files with no analysed units (every unit failed or was skipped): {% for p in model_gaps.modules_without_units %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}.

{% endif %}
{% if model_gaps.rejected %}
{{ model_gaps.rejected }} model finding(s) were rejected on verification and are excluded above; they remain in `analysis/findings.json` for inspection.

{% endif %}
{% if not git.available %}
Git history was not analysed: {{ git.reason }}.
{% endif %}
{% if everything_analysed %}
Everything in the source tree was analysed.
{% endif %}
```

`src/unvarnish/render/templates/architecture.md.j2`:

```jinja
# {{ tool.name }}: Architecture

**Client:** {{ client or "—" }} · **Prepared by:** {{ consultant or "—" }} · **Generated:** {{ generated_at }}
**Source:** {{ tool.origin_kind }} `{{ tool.origin }}`{% if tool.commit %} at `{{ tool.commit[:12] }}`{% endif %}

{{ "" }}
> Rendered from Unvarnish's analysis artifacts. Prose sections are model-written from those artifacts
> ({{ analysis_mode }}); every table, list, and diagram is generated directly from the data.

## 1. Purpose and users

{% prose "purpose_and_users" %}{{ "" }}

**Actors**

{% for a in tm.actors %}
- **{{ a.name }}**: {{ a.description }}
{% else %}
- None identified.
{% endfor %}

**Entry points**

| Entry point | Kind | Module | Description |
|---|---|---|---|
{% for e in tm.entry_points %}
| {{ e.name }} | {{ e.kind }} | `{{ e.module }}` | {{ e.description }} |
{% else %}
| — | — | — | None identified |
{% endfor %}

## 2. Context

```mermaid
{{ context_mermaid }}
```

**External systems**

| System | Kind | Direction | Description | Modules |
|---|---|---|---|---|
{% for s in tm.external_systems %}
| {{ s.name }} | {{ s.kind }} | {{ s.direction }} | {{ s.description }} | {% for m in s.modules %}`{{ m }}`{{ ", " if not loop.last }}{% else %}—{% endfor %} |
{% else %}
| — | — | — | None identified | — |
{% endfor %}

## 3. Internal stack

| Layer | Value |
|---|---|
| Languages (source lines) | {% for lang, n in languages %}{{ lang }} {{ n | fmt_int }}{{ "; " if not loop.last }}{% else %}—{% endfor %} |
| Frameworks (detected) | {{ census.frameworks | join(", ") if census.frameworks else "none detected" }} |
| Stack (from code) | {{ tm.internal_stack | join("; ") if tm.internal_stack else "—" }} |
| Dependencies declared | {{ deps.dependencies | length }} |

## 4. Module map and interactions

```mermaid
{{ module_mermaid }}
```
{% if module_diagram_note %}

{{ module_diagram_note }}
{% endif %}

| Module | Role | Depends on | Units | Lines | Findings |
|---|---|---|---:|---:|---:|
{% for m in module_rows %}
| `{{ m.path }}` | {{ m.role }} | {% for d in m.depends_on %}`{{ d }}`{{ ", " if not loop.last }}{% else %}—{% endfor %} | {{ m.units | fmt_int }} | {{ m.lines | fmt_int }} | {{ m.findings | fmt_int }} |
{% else %}
| — | None identified | — | — | — | — |
{% endfor %}

## 5. Data stores and flows

| Store | Kind | Description | Modules |
|---|---|---|---|
{% for s in tm.data_stores %}
| {{ s.name }} | {{ s.kind }} | {{ s.description }} | {% for m in s.modules %}`{{ m }}`{{ ", " if not loop.last }}{% else %}—{% endfor %} |
{% else %}
| — | — | None identified | — |
{% endfor %}

| From | To | Data | Via |
|---|---|---|---|
{% for f in tm.data_flows %}
| {{ f.source }} | {{ f.target }} | {{ f.data }} | {{ f.via or "—" }} |
{% else %}
| — | — | No data flows identified | — |
{% endfor %}

## 6. Deployment and runtime assumptions

{% prose "deployment" %}{{ "" }}

{% for a in tm.deployment_assumptions %}
- {{ a }}
{% else %}
- No deployment assumptions were identified in the code.
{% endfor %}

## 7. How this was built

{% prose "build_history" %}{{ "" }}

{% if git.available %}
| Measure | Value |
|---|---|
| Commits · authors · active days | {{ git.commit_count | fmt_int }} · {{ git.authors | length }} · {{ git.active_days }} |
| History span | {{ git.first_commit.date() }} to {{ git.last_commit.date() }} |
| Top author share · bus factor | {{ git.top_author_share | pct }} · {{ git.bus_factor }} |
| Commits over {{ git.large_commit_threshold | fmt_int }} lines | {{ git.large_commits | length }} |
| AI tooling indicators | {{ ai_indicators | join("; ") if ai_indicators else "none found" }} |
{% else %}
Git history unavailable ({{ git.reason }}).
{% endif %}

## 8. Analysis coverage

| Measure | Value |
|---|---|
| Units analysed / total | {{ coverage.units_done | fmt_int }} / {{ coverage.units_total | fmt_int }} |
| Windowed units | {{ coverage.windowed | fmt_int }} |
| Units failed | {{ coverage.units_failed | fmt_int }} |
| Modules rolled up / failed / without units | {{ coverage.modules_rolled }} / {{ coverage.modules_failed }} / {{ coverage.modules_without_units }} |
| Tool rollup | {% if tm.hierarchical %}hierarchical, {{ tm.chunks }} directory chunks{% else %}single pass{% endif %} covering {{ tm.modules_covered }} modules |
| Files not split | {{ coverage.skipped_split }} |
| Model confidence (tool rollup) | {{ tm.confidence | pct }} |
```

`src/unvarnish/render/templates/requirements.md.j2`:

```jinja
# {{ tool.name }}: Requirements Inventory

**Client:** {{ client or "—" }} · **Prepared by:** {{ consultant or "—" }} · **Generated:** {{ generated_at }}
**Source:** {{ tool.origin_kind }} `{{ tool.origin }}`{% if tool.commit %} at `{{ tool.commit[:12] }}`{% endif %}

{{ "" }}
> Reverse-engineered from the code by Unvarnish ({{ analysis_mode }}). This is what the tool does today,
> not what anyone asked it to do. Capabilities marked *implicit* exist only as hardcoded rules. Treat
> every row as a question for the people who own and use the tool.

## 1. Actors

{% for a in req.actors %}
- **{{ a.name }}**: {{ a.description }}
{% else %}
- None identified.
{% endfor %}

## 2. Capability inventory

{{ capabilities | length }} capabilities, {{ implicit_count }} implicit.

| Actor | Can | Object | Implicit | Implementing modules | Data touched |
|---|---|---|---|---|---|
{% for c in capabilities %}
| {{ c.actor }} | {{ c.action }} | {{ c.object }} | {{ "yes" if c.implicit else "" }} | {% for e in c.evidence %}`{{ e.path }}`{{ ", " if not loop.last }}{% else %}*no implementing module identified*{% endfor %} | {{ c.data_touched | join(", ") if c.data_touched else "—" }} |
{% else %}
| — | — | — | — | None identified | — |
{% endfor %}

{% for c in capabilities %}
- **{{ c.actor }} can {{ c.action }} {{ c.object }}**{% if c.implicit %} *(implicit)*{% endif %}: {{ c.description }}
{% endfor %}

## 3. Data inventory

| Name | Kind | Description | Used by |
|---|---|---|---|
{% for r in data_rows %}
| {{ r.name }} | {{ r.kind }} | {{ r.description }} | {{ r.used_by | join("; ") if r.used_by else "—" }} |
{% else %}
| — | — | No stores or external systems identified | — |
{% endfor %}

## 4. Business rules found in code

| Rule | Kind | Module |
|---|---|---|
{% for r in req.business_rules %}
| {{ r.description }} | {{ r.kind }} | `{{ r.module }}` |
{% else %}
| — | — | None identified |
{% endfor %}

## 5. Open questions for stakeholder interviews

{% prose "open_questions" %}{{ "" }}

{% if req.open_questions %}
Raised directly by the analysis:

{% for q in req.open_questions %}
- {{ q }}
{% endfor %}
{% endif %}
```

- [ ] **Step 6: Rewrite the render phase**

Replace `src/unvarnish/phases/render.py` with:

```python
from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, write_artifact
from unvarnish.config import user_config_path
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import merge_failures
from unvarnish.render.architecture import build_architecture_context
from unvarnish.render.findings import build_findings_context
from unvarnish.render.inputs import RenderInputs, load_render_inputs
from unvarnish.render.markdown import (
    make_env,
    prose_block_names,
    render_document,
    template_source_hash,
)
from unvarnish.render.prose import PROSE_PROMPT_VERSION, generate_prose
from unvarnish.render.requirements import build_requirements_context
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.render import RenderState

log = logging.getLogger("unvarnish.render")

Builder = Callable[[ToolContext, RenderInputs], dict]
# (template, ToolPaths attribute, context builder, RenderInputs field that must be present)
DOCUMENTS: list[tuple[str, str, Builder, str | None]] = [
    ("findings.md.j2", "findings_doc", build_findings_context, None),
    ("architecture.md.j2", "architecture_doc", build_architecture_context, "tool_model"),
    ("requirements.md.j2", "requirements_doc", build_requirements_context, "requirements"),
]


def template_override_dirs(ctx: ToolContext) -> list[Path]:
    dirs = [ctx.engagement.root / "templates"]
    if ctx.config.report.templates_dir:
        dirs.append(Path(ctx.config.report.templates_dir))
    dirs.append(user_config_path().parent / "templates")
    return dirs


class RenderPhase:
    name = "render"

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def _env(self, ctx: ToolContext):
        return make_env(template_override_dirs(ctx))

    def _inputs(self, ctx: ToolContext) -> list[Path]:
        p = ctx.paths
        return [p.census, p.metrics, p.git, p.dependencies, p.scanner_findings, p.units_index,
                p.extract_state, p.modules_index, p.tool_model, p.capabilities,
                p.model_findings, p.failures]

    def inputs_hash(self, ctx: ToolContext) -> str:
        env = self._env(ctx)
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([
            hash_files(self._inputs(ctx)),
            *(template_source_hash(env, t) for t, _, _, _ in DOCUMENTS),
            ctx.config.client or "", ctx.config.consultant or "", ctx.config.report.tone,
            PROSE_PROMPT_VERSION, model_part,
        ])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        p = ctx.paths
        out = [p.render_state, p.findings_doc]
        if p.tool_model.exists():
            out.append(p.architecture_doc)
        if p.capabilities.exists():
            out.append(p.requirements_doc)
        return out

    def run(self, ctx: ToolContext) -> PhaseResult:
        inp = load_render_inputs(ctx)
        env = self._env(ctx)
        backend = self._resolve(ctx)
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        tone = ctx.config.report.tone
        usage = Usage()
        failures: list[FailureRecord] = []
        written: list[str] = []
        hashes: dict[str, str] = {}
        stopped = False
        ctx.paths.docs.mkdir(parents=True, exist_ok=True)
        for template, attr, builder, required in DOCUMENTS:
            if required and getattr(inp, required) is None:
                continue
            context = builder(ctx, inp)
            names = prose_block_names(env, template)
            facts = {n: context["prose_facts"].get(n, {}) for n in names}
            prose = generate_prose(backend, facts, tone=tone, effort=effort, budget=budget)
            usage = usage + prose.usage
            failures.extend(prose.failures)
            stopped = stopped or prose.stopped_for_budget
            doc = render_document(env, template, {**context, "prose": prose.text})
            path: Path = getattr(ctx.paths, attr)
            path.write_text(doc)
            written.append(path.name)
            hashes[path.name] = hashlib.sha256(doc.encode("utf-8")).hexdigest()
        # failures.json is one of this phase's inputs: write it before recording the hash,
        # otherwise the phase would be stale the moment it finished.
        merge_failures(ctx, self.name, failures)
        write_artifact(ctx.paths.render_state, RenderState(tool=ctx.tool, documents=hashes),
                       produced_by=self.name,
                       inputs_hash="" if stopped else self.inputs_hash(ctx))
        if usage.total() and backend is not None:
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=usage, at=datetime.now(UTC)))
        msg = f"wrote {', '.join(written)}"
        if usage.total():
            msg += f" ({usage.total():,} tokens of prose)"
        if stopped:
            msg = "budget cap reached: " + msg
        log.info("render %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name,
                           status=PhaseStatus.stopped if stopped else PhaseStatus.ok,
                           message=msg, failures=[f"{f.unit_id}: {f.error}" for f in failures])
```

Remove the `xfail` marker added in Task 8 from `tests/test_prose.py`.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_render_documents.py tests/test_render.py tests/test_prose.py tests/test_cli_run.py -q 2>&1 | tail -5`
Expected: all PASS. `tests/test_render.py::test_findings_document_content` still passes because the scanner-only path keeps the slice 1 banner and headings.

- [ ] **Step 8: Lint and commit**

```bash
uv run ruff check src/unvarnish/render src/unvarnish/phases/render.py tests/test_render_documents.py tests/test_prose.py
git add src/unvarnish/render src/unvarnish/phases/render.py tests/test_render_documents.py tests/test_prose.py
git commit -m "feat: render architecture, findings, and requirements documents with prose blocks and diagrams"
```

---

### Task 10: Pipeline wiring, CLI estimates and status, fake autofill, README

**Files:**
- Modify: `src/unvarnish/phases/__init__.py`, `src/unvarnish/model/estimate.py`, `src/unvarnish/cli.py`, `tests/fake_llm.py`, `README.md`
- Test: `tests/test_cli_slice3.py`

**Interfaces:**
- Consumes: every phase class; `UnitsIndex`, `UnitResult`, `Module`; `build_module_rollup_system`, `build_tool_rollup_system`, `build_verify_system`.
- Produces:
  - `default_phases()` order: inventory, git, scan, split, extract, rollup_modules, rollup_tool, verify, render.
  - `unvarnish.model.estimate`: `MODEL_PHASES = ("extract", "rollup_modules", "rollup_tool", "verify", "render")`, `estimate_rollup_modules(index) -> Usage`, `estimate_rollup_tool(n_modules, rollup_input_tokens) -> Usage`, `estimate_verify(n_high) -> Usage`, `estimate_render() -> Usage`, `count_high_findings(ctx) -> int`, `estimate_phase(ctx, phase) -> tuple[Usage, str] | None` (usage and a short note).
  - `tests.fake_llm`: `fill_schema(schema: dict, root: dict | None = None) -> Any`, `FakeLLM.autofill: bool` (when the queue is empty, answer with schema-filled JSON for structured requests and `"Model-written paragraph."` otherwise).

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_slice3.py`:

```python
import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import fill_schema
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.model.estimate import (
    estimate_render,
    estimate_rollup_tool,
    estimate_verify,
)
from unvarnish.model.structured import strict_schema
from unvarnish.phases import default_phases
from unvarnish.schemas.analysis import UnitExtraction
from unvarnish.schemas.toolmodel import ToolRollup
from unvarnish.schemas.verify import Verdict

runner = CliRunner()


def test_default_phase_order():
    assert [p.name for p in default_phases()] == [
        "inventory", "git", "scan", "split", "extract", "rollup_modules", "rollup_tool",
        "verify", "render"]


def test_fill_schema_produces_valid_instances():
    for cls in (UnitExtraction, ToolRollup, Verdict):
        filled = fill_schema(strict_schema(cls))
        cls.model_validate(filled)
    assert fill_schema({"type": "string", "enum": ["a", "b"]}) == "a"
    assert fill_schema({"anyOf": [{"type": "string"}, {"type": "null"}]}) == "stub"


def test_estimates_scale_with_inputs():
    assert estimate_rollup_tool(10, 40_000).total() < estimate_rollup_tool(2000, 40_000).total()
    assert estimate_verify(0).total() == 0 and estimate_verify(3).total() > 0
    assert estimate_render().total() > 0


def _configure(eng, fake):
    conf = model_config(fake)
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **conf})
    eng.save_config()


def test_dry_run_estimates_every_model_phase(ingested, fake_llm):
    eng, _ = ingested
    _configure(eng, fake_llm)
    out = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    for phase in ("extract", "rollup_modules", "rollup_tool", "verify", "render"):
        assert phase in out.output
    assert out.output.count("estimate") >= 5


def test_full_run_through_cli_with_autofill(ingested, fake_llm):
    eng, tool = ingested
    _configure(eng, fake_llm)
    fake_llm.autofill = True
    out = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    docs = eng.tool_paths(tool).docs
    assert {p.name for p in docs.glob("*.md")} == {"findings.md", "architecture.md",
                                                   "requirements.md"}
    status = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert status.exit_code == 0, status.output
    assert "modules" in status.output and "3 docs" in status.output
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    for phase in ("extract", "rollup_modules", "rollup_tool", "render"):
        assert phase in cost.output
    tool_json = json.loads((eng.tool_paths(tool).analysis / "tool.json").read_text())
    assert tool_json["data"]["purpose"] == "stub"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli_slice3.py -q 2>&1 | tail -3`
Expected: FAIL (`ImportError: cannot import name 'fill_schema'`).

- [ ] **Step 3: Wire the phases and estimates**

`src/unvarnish/phases/__init__.py`:

```python
from __future__ import annotations

from unvarnish.phases.base import Phase


def default_phases() -> list[Phase]:
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.rollup_modules import RollupModulesPhase
    from unvarnish.phases.rollup_tool import RollupToolPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.phases.split import SplitPhase
    from unvarnish.phases.verify import VerifyPhase

    return [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(),
            RollupModulesPhase(), RollupToolPhase(), VerifyPhase(), RenderPhase()]
```

Replace `src/unvarnish/model/estimate.py` with:

```python
from __future__ import annotations

import math
from collections.abc import Collection

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.artifacts import read_artifact
from unvarnish.model.prompts.extract import build_system_prompt
from unvarnish.model.prompts.rollup import build_module_rollup_system, build_tool_rollup_system
from unvarnish.model.prompts.verify import build_verify_system
from unvarnish.phases.base import ToolContext
from unvarnish.render.prose import BLOCKS
from unvarnish.schemas.analysis import UnitResult, UnitsIndex
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.rollup import Module

MODEL_PHASES = ("extract", "rollup_modules", "rollup_tool", "verify", "render")

SYSTEM_PROMPT_TOKENS: int = estimate_tokens(build_system_prompt())
NEIGHBOURHOOD_TOKENS = 300
OUTPUT_TOKENS_PER_UNIT = 700

MODULE_SYSTEM_TOKENS: int = estimate_tokens(build_module_rollup_system())
UNIT_SUMMARY_TOKENS = 300
MODULE_OUTPUT_TOKENS = 600
TOOL_SYSTEM_TOKENS: int = estimate_tokens(build_tool_rollup_system())
DIGEST_TOKENS = 150
CHUNK_OUTPUT_TOKENS = 1500
TOOL_OUTPUT_TOKENS = 6000
VERIFY_SYSTEM_TOKENS: int = estimate_tokens(build_verify_system())
VERIFY_INPUT_TOKENS = 1500
VERIFY_OUTPUT_TOKENS = 150
PROSE_INPUT_TOKENS = 3000
PROSE_OUTPUT_TOKENS = 500


def estimate_extract(index: UnitsIndex, done_ids: Collection[str] = frozenset()) -> Usage:
    remaining = [u for u in index.units if u.id not in done_ids]
    return Usage(
        input_tokens=sum(SYSTEM_PROMPT_TOKENS + u.token_estimate + NEIGHBOURHOOD_TOKENS
                         for u in remaining),
        output_tokens=OUTPUT_TOKENS_PER_UNIT * len(remaining),
    )


def estimate_rollup_modules(index: UnitsIndex) -> Usage:
    n_modules = len(index.modules)
    return Usage(
        input_tokens=n_modules * MODULE_SYSTEM_TOKENS + len(index.units) * UNIT_SUMMARY_TOKENS,
        output_tokens=n_modules * MODULE_OUTPUT_TOKENS,
    )


def estimate_rollup_tool(n_modules: int, rollup_input_tokens: int) -> Usage:
    digests = n_modules * DIGEST_TOKENS
    chunks = 0 if digests <= rollup_input_tokens else math.ceil(digests / rollup_input_tokens)
    chunk_input = chunks * (TOOL_SYSTEM_TOKENS + rollup_input_tokens)
    final_input = TOOL_SYSTEM_TOKENS + (chunks * CHUNK_OUTPUT_TOKENS if chunks else digests)
    return Usage(input_tokens=chunk_input + final_input,
                 output_tokens=TOOL_OUTPUT_TOKENS + chunks * CHUNK_OUTPUT_TOKENS)


def estimate_verify(n_high: int) -> Usage:
    return Usage(input_tokens=n_high * (VERIFY_SYSTEM_TOKENS + VERIFY_INPUT_TOKENS),
                 output_tokens=n_high * VERIFY_OUTPUT_TOKENS)


def estimate_render() -> Usage:
    return Usage(input_tokens=len(BLOCKS) * PROSE_INPUT_TOKENS,
                 output_tokens=len(BLOCKS) * PROSE_OUTPUT_TOKENS)


def count_high_findings(ctx: ToolContext) -> int:
    """High/critical model findings recorded so far in unit and module artifacts."""
    n = 0
    high = (Severity.critical, Severity.high)
    for d, cls in ((ctx.paths.unit_dir, UnitResult), (ctx.paths.module_dir, Module)):
        if not d.exists():
            continue
        for p in d.glob("*.json"):
            try:
                n += sum(1 for f in read_artifact(p, cls).data.findings if f.severity in high)
            except Exception:
                continue
    return n


def estimate_phase(ctx: ToolContext, phase: str) -> tuple[Usage, str] | None:
    """Token estimate and a short note for one model phase, or None when not estimable yet."""
    if phase == "render":
        return estimate_render(), f"{len(BLOCKS)} prose blocks"
    if phase == "verify":
        n = count_high_findings(ctx)
        return estimate_verify(n), f"{n} high/critical model findings recorded so far"
    if not ctx.paths.units_index.exists():
        return None
    index = read_artifact(ctx.paths.units_index, UnitsIndex).data
    if phase == "extract":
        done: set[str] = set()
        if ctx.paths.unit_dir.exists():
            done = {p.stem for p in ctx.paths.unit_dir.glob("*.json")}
        remaining = sum(1 for u in index.units if u.id not in done)
        return estimate_extract(index, done), f"{remaining} units remaining"
    if phase == "rollup_modules":
        return estimate_rollup_modules(index), f"{len(index.modules)} modules"
    if phase == "rollup_tool":
        return (estimate_rollup_tool(len(index.modules), ctx.config.pipeline.rollup_input_tokens),
                f"{len(index.modules)} module digests")
    return None
```

- [ ] **Step 4: Update the CLI**

In `src/unvarnish/cli.py`:

1. Replace the import `from unvarnish.model.estimate import estimate_extract` with `from unvarnish.model.estimate import MODEL_PHASES, estimate_phase`, add `from unvarnish.schemas.rollup import ModulesIndex` and `from unvarnish.schemas.verify import ModelFindings`, and delete the `_extract_estimate` function and the now-unused `UnitsIndex`/`Usage` imports if ruff reports them (keep `Usage` if `_usd` still uses it).

2. In `run`, replace the dry-run block:

```python
            if dry_run:
                planned = runner.plan(ctx, force=force, only=phase)
                for p in planned:
                    table.add_row(name, p.name, "would run", "")
                prices = eng.config.budget.prices
                for p in planned:
                    if p.name not in MODEL_PHASES:
                        continue
                    est = estimate_phase(ctx, p.name)
                    if est is None:
                        table.add_row(name, p.name, "estimate", "run split first for a token estimate")
                        continue
                    usage, note = est
                    table.add_row(name, p.name, "estimate",
                                  f"≈ {usage.total():,} tokens{_usd(usage, prices)} · {note}")
                continue
```

3. In `status`, extend the per-phase cell logic with three more branches before the generic freshness check:

```python
            if p.name == "rollup_modules" and ctx.paths.modules_index.exists():
                mi = read_artifact(ctx.paths.modules_index, ModulesIndex).data
                cell = f"{len(mi.modules)} modules"
                if mi.failed:
                    cell += f" ({len(mi.failed)} failed)"
                if mi.stopped_for_budget:
                    cell += " budget-stopped"
                colour = "yellow" if (mi.failed or mi.stopped_for_budget) else "green"
                cells.append(f"[{colour}]{cell}[/{colour}]")
                continue
            if p.name == "verify" and ctx.paths.model_findings.exists():
                mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
                cell = f"{len(mf.findings)} findings, {mf.verified} verified"
                if mf.unverified:
                    cell += f" ({mf.unverified} unverified)"
                colour = "yellow" if (mf.unverified or mf.stopped_for_budget) else "green"
                cells.append(f"[{colour}]{cell}[/{colour}]")
                continue
            if p.name == "render" and ctx.paths.render_state.exists():
                n_docs = sum(1 for d in (ctx.paths.findings_doc, ctx.paths.architecture_doc,
                                         ctx.paths.requirements_doc) if d.exists())
                fresh = is_fresh(p, ctx)
                cells.append(f"[{'green' if fresh else 'yellow'}]{n_docs} docs"
                             f"{'' if fresh else ' (stale)'}[/{'green' if fresh else 'yellow'}]")
                continue
```

4. In `config_check`, the probed phases list stays as is: `["extract", *[p for p in eng.config.models.phases if p != "extract"]]` already covers per-phase overrides for the new phases.

- [ ] **Step 5: Add schema autofill to the fake server**

In `tests/fake_llm.py`:

```python
def fill_schema(schema: dict, root: dict | None = None) -> Any:
    """A minimal instance of a JSON schema: first enum value, empty arrays, 'stub' strings."""
    root = root or schema
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return fill_schema(root["$defs"][name], root)
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    if "anyOf" in schema:
        options = [o for o in schema["anyOf"] if o.get("type") != "null"]
        return fill_schema(options[0], root) if options else None
    t = schema.get("type")
    if t == "object":
        return {k: fill_schema(v, root) for k, v in schema.get("properties", {}).items()}
    if t == "array":
        return []
    if t == "string":
        return "stub"
    if t == "integer":
        return 1
    if t == "number":
        return 0.5
    if t == "boolean":
        return False
    if t == "null":
        return None
    return "stub"


def _request_schema(body: dict) -> dict | None:
    fmt = (body.get("output_config") or {}).get("format") or {}
    if fmt.get("schema"):
        return fmt["schema"]
    rf = (body.get("response_format") or {}).get("json_schema") or {}
    return rf.get("schema")
```

In `FakeLLM.__init__` add `self.autofill = False`. Change `_next` to return `None` when the queue is empty:

```python
    def _next(self) -> Scripted | None:
        with self._lock:
            return self._queue.popleft() if self._queue else None
```

and in `do_POST`, right after `scripted = fake._next()`:

```python
                if scripted is None:
                    schema = _request_schema(body)
                    if fake.autofill and schema:
                        scripted = json.dumps(fill_schema(schema))
                    elif fake.autofill:
                        scripted = "Model-written paragraph."
                    else:
                        scripted = '{"echo": true}'
```

Run `uv run pytest tests/test_fake_llm.py -q` to confirm the default behaviour (no autofill) is unchanged.

- [ ] **Step 6: Update the README**

In `README.md`, replace the pipeline/phase list with the nine phases and add, after the model configuration section:

```markdown
## Documents

`unvarnish run` renders three documents per tool into `tools/<name>/docs/`:

- `findings.md`: executive summary, by-the-numbers table, every scanner and model finding by
  severity (scanner findings first at equal severity, model findings with their verification
  status), and a "Not analysed" appendix listing excluded files, windowed regions, failed units
  and modules, and rejected findings.
- `architecture.md`: purpose and users, context diagram, internal stack, module map and
  interaction diagram (Mermaid), data stores and flows, deployment assumptions, build history,
  and analysis coverage.
- `requirements.md`: actors, the "actor can action object" capability inventory with implicit
  capabilities flagged, data inventory, business rules found in code, and open questions for
  stakeholder interviews.

Every number, table, list, and diagram comes from the JSON under `analysis/`. The model writes
only the prose blocks marked `{% prose "name" %}` in the templates (`executive_summary`,
`purpose_and_users`, `deployment`, `build_history`, `open_questions`), from a facts payload
drawn from the same JSON. Without a model configured, `findings.md` is still produced with
scanner findings and a fallback sentence in each prose block.

### Tone and templates

`report.tone` is `direct` (default) or `measured`. Override any template by placing a copy of
`src/unvarnish/render/templates/<name>.md.j2` under `templates/` in the engagement, under
`report.templates_dir`, or under `~/.config/unvarnish/templates/`. A prose block the template
names but Unvarnish does not know renders a fallback sentence and records a failure.

### Model phases and cost

| Phase | Calls | Notes |
|---|---|---|
| `extract` | one per unit | parallel across files; cached and resumable |
| `rollup_modules` | one per file with analysed units | parallel; per-module artifacts are resumable |
| `rollup_tool` | one, or one per directory chunk plus one | chunks when the module digests exceed `pipeline.rollup_input_tokens` (default 40,000) |
| `verify` | one per high or critical model finding | the verifier sees only the claim and the cited lines |
| `render` | five prose blocks per tool | |

`unvarnish run --dry-run` prints an estimate per model phase. `budget.max_tokens` caps the whole
run across phases and tools; a capped run exits 3 and resumes on the next `run`.
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest -q 2>&1 | tail -3`
Expected: the whole suite PASSES (the new CLI test runs the full pipeline against the fake server with autofill).

- [ ] **Step 8: Lint and commit**

```bash
uv run ruff check .
git add src/unvarnish/phases/__init__.py src/unvarnish/model/estimate.py src/unvarnish/cli.py tests/fake_llm.py tests/test_cli_slice3.py README.md
git commit -m "feat: nine-phase pipeline, per-phase dry-run estimates, status cells, fake-server autofill, docs"
```

---

### Task 11: Scale test against ESCAPESUITE

**Files:**
- Create: `tests/test_scale.py`

**Interfaces:**
- Consumes: `FakeLLM.autofill`, `default_phases`, `PhaseRunner`, `ingest_tool(..., "link")`.
- Produces: an env-gated test (`UNVARNISH_SCALE_REPO`) that runs every phase on a real repository with fake replies and reports wall-clock time per phase.

- [ ] **Step 1: Write the test**

`tests/test_scale.py`:

```python
"""Scale test: the full pipeline on a real repository with schema-filled fake replies.

Skipped unless UNVARNISH_SCALE_REPO points at a repository. It exercises the machinery (splitting,
thousands of unit and module artifacts, hierarchical rollup, three documents) without spending
tokens; run it before a large engagement to catch pipeline regressions:

    UNVARNISH_SCALE_REPO=~/Projects/ESCAPESUITE uv run pytest tests/test_scale.py -s -v
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.conftest import model_config
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases import default_phases
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.ingest import ingest_tool

REPO = os.environ.get("UNVARNISH_SCALE_REPO")
pytestmark = pytest.mark.skipif(not REPO, reason="set UNVARNISH_SCALE_REPO=/path/to/repo")


def test_full_pipeline_on_real_repo(tmp_path: Path, fake_llm):
    fake_llm.autofill = True
    eng = Engagement.create(tmp_path / "scale", client="Scale")
    conf = model_config(fake_llm)
    conf["pipeline"] = {"concurrency": 8}
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **conf})
    eng.save_config()
    ingest_tool(eng, "scale", str(Path(REPO).expanduser()), "link")
    ctx = build_context(eng, "scale", budget=BudgetTracker(None))
    timings: list[tuple[str, float, str]] = []
    for phase in default_phases():
        t0 = time.monotonic()
        result = phase.run(ctx)
        timings.append((phase.name, time.monotonic() - t0, result.message or ""))
        assert result.status == PhaseStatus.ok, (phase.name, result.model_dump())
    print()
    for name, secs, msg in timings:
        print(f"{name:16s} {secs:8.1f}s  {msg}")
    print(f"requests served: {len(fake_llm.requests)}")
    for doc in (ctx.paths.findings_doc, ctx.paths.architecture_doc, ctx.paths.requirements_doc):
        assert doc.exists() and doc.stat().st_size > 1000, doc
```

- [ ] **Step 2: Run it against the synthetic repo first**

Run: `UNVARNISH_SCALE_REPO=$(uv run python -c "import tempfile;print(tempfile.gettempdir())")/nonexistent uv run pytest tests/test_scale.py -q 2>&1 | tail -3`
Expected: FAIL in `ingest_tool` (path does not exist). This confirms the gate opens when the variable is set. Then run without the variable: `uv run pytest tests/test_scale.py -q` → `1 skipped`.

- [ ] **Step 3: Run it against ESCAPESUITE**

Run: `UNVARNISH_SCALE_REPO=~/Projects/ESCAPESUITE uv run pytest tests/test_scale.py -s -v 2>&1 | tail -20`
Expected: PASS. Expect roughly: split under a minute, extract a few minutes (about 1,000 files, every unit answered locally), rollup_modules about 1,000 requests, rollup_tool hierarchical with several directory chunks (`modules.json` digests exceed 40,000 tokens), verify 0 findings (autofill emits no candidate findings), render three documents. Record the per-phase timings and the request count in the ledger. If any phase exceeds ten minutes, record it as a finding for the user rather than tuning in this task.

- [ ] **Step 4: Inspect the ESCAPESUITE documents**

Run: `ls -la "$(ls -d /private/tmp/pytest-of-*/pytest-*/scale*/scale/tools/scale/docs 2>/dev/null | tail -1)"` (or the tmp path pytest printed) and `head -60 .../architecture.md`.
Expected: `architecture.md` section 8 says "hierarchical, N directory chunks covering 1,0xx modules"; the module diagram note says "most connected of"; `findings.md` lists the slice 1 scanner findings (the 73 known from the earlier report) and the "Not analysed" appendix lists the files not split (none expected over 5 MB) and vendored exclusions. Copy the three documents to `~/Projects/unvarnish-reports/escapesuite-2026-10-17/fake-model/` for the user to look at the structure (the prose is placeholder text).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check tests/test_scale.py
git add tests/test_scale.py
git commit -m "test: env-gated full-pipeline scale test on a real repository"
```

---

## Self-review notes

**Spec coverage.** 6.7 rollup_modules (Task 4), hierarchical rollup_tool with capabilities (Task 5), 6.8 verify with dedupe, evidence-only verification, downgrade, retained rejects (Task 6), 6.9 render from JSON with prose blocks (Tasks 8, 9), 8.1 prose tag and template overrides (Tasks 8, 9), 8.2 tone (Task 8), 8.3 architecture.md all eight sections (Task 9), 8.4 findings.md four sections with scanner-first ordering and verification badges (Task 9), 8.5 requirements.md five sections (Task 9), 8.7 diagram model with Mermaid emitter (Task 7; the Graphviz SVG emitter is slice 6 export), 6.11 estimates for every model phase (Task 10), 6.12 caching and resumability (per-module artifacts, Task 4; response cache covers verify and prose), 13 failures surfaced in status, coverage section, and appendix (Tasks 9, 10), 14 end-to-end offline test through the CLI (Task 10) and the scale test (Task 11), 4 workspace files `modules/`, `tool.json`, `findings.json`, `capabilities.json`, three docs (Task 1).

**Known deviations, to ledger at execution.** `Capability.evidence` may be empty (the spec's shape has no "unknown module" case; the template flags it). `build_history_summary` is a prose block rather than a `ToolModel` field. Prose blocks are declared in Python with their facts; templates choose which to render. The run budget is now per run (spec 6.11), closing a slice 2 ruling.

**Type consistency checked.** `ItemOutcome`/`run_parallel` signatures match across Tasks 2, 4, 5, 6. `StubBackend.count` used in Tasks 4-9. `ModuleDigest` fields in Tasks 1, 3, 4, 5, 9. `prose_facts` key names match `BLOCKS` names (Tasks 8, 9). `RenderPhase(backend=)` in Task 9 tests and Task 10 default phases (no argument). `estimate_phase` note strings used verbatim in the CLI (Task 10).
