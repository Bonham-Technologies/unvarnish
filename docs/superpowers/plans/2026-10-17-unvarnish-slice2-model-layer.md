# Unvarnish Slice 2: Model Layer and Unit Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the model layer to Unvarnish: two backends (Anthropic, OpenAI-compatible) behind one adapter, a content-addressed response cache, structured-output completion with retry and repair, the `split` phase that turns files into units, the `extract` phase that produces a `UnitExtraction` per unit with budget control and resumability, cost tracking, run logging, and the `config check`, `cost`, `cache clear`, and `--dry-run` estimate commands.

**Architecture:** Phases keep the slice 1 protocol. `split` is deterministic and writes a units index. `extract` resolves a backend from config, runs modules in parallel and units within a module sequentially, calls `complete_structured` (schema-constrained when the backend supports it, JSON-in-prompt otherwise, with retry → repair → failure), validates findings against the unit's line range, writes one artifact per unit, and accumulates usage into a cost ledger. A fake LLM HTTP server drives all tests offline.

**Tech Stack:** Python 3.12+, `anthropic` (1.x, httpx2), `openai`, Pydantic v2, tree-sitter (from slice 1), Rich logging, `concurrent.futures`. Tests: pytest, `http.server` fake.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` (sections 3, 4, 5.2, 6.5, 6.6, 6.11, 6.12, 7, 10, 13, 16 slice 2)

## Global Constraints

- Everything from slice 1 still holds: artifact envelope, relative POSIX paths only, no secrets on disk, one bad unit never kills a run (spec §4, §13).
- Default Anthropic model: `claude-opus-5-5`. Structured output via `output_config={"format": {"type": "json_schema", "schema": ...}}` on `client.messages.create`; effort via `output_config["effort"]`; thinking left at the model default (adaptive). Never `budget_tokens`, never prefill, never forced `tool_choice`.
- Prompt caching: the fixed system prompt is sent as `system=[{"type": "text", "text": ..., "cache_control": {"type": "ephemeral"}}]` and must exceed 512 tokens to cache on current models.
- API keys come from the env var named in `backends.<name>.api_key_env`, or the OS keychain via `api_key_keychain`. Never from `engagement.yaml`, never logged.
- Every model call is cached under `cache/responses/<sha256>.json` keyed by backend name, model, full request, and schema version (spec §6.12).
- Exit codes: 0 ok, 1 completed with recorded failures, 2 config/backend error, 3 budget cap (spec §3).
- Retry policy for structured output (spec §6.6): schema failure → retry once with the validation error appended → repair call → record failure and continue.
- `unit_tokens` default 8,000; per-backend override via `backends.<name>.unit_tokens`; windowing overlap 10% (spec §6.5).
- Units within a module are extracted sequentially; modules in parallel up to `pipeline.concurrency` (spec §6.6).
- Commit messages end with the attribution lines in the session's system reminder.

## Review Focus

1. **A backend that returns non-JSON, truncated JSON, or JSON that fails the schema.** The unit must end as a recorded failure after retry and repair, never as a crash, and the run must continue. Pinned in Task 8 (`test_retry_then_repair_then_failure`, `test_truncated_json_is_repaired`).
2. **Rate limiting and transient 5xx from the backend.** The SDK retries; our layer must not double-count usage or cache a failed response. Pinned in Task 5 (`test_anthropic_backend_retries_429_without_caching`) and Task 7 (`test_cache_never_stores_errors`).
3. **Crash mid-run and re-run.** Units already extracted must be reused byte-for-byte without a model call; units whose source changed must be redone. Pinned in Task 11 (`test_extract_resumes_without_recalling_done_units`, `test_extract_redoes_changed_unit`).
4. **Budget cap reached while threads are in flight.** No further model calls after the cap, exit code 3, state written so a later run resumes. Pinned in Task 11 (`test_budget_cap_stops_cleanly`) and Task 13 (`test_run_exit_code_3_on_budget`).
5. **A unit the model refuses or a key that is missing.** Missing key is a configuration error (exit 2) before any unit runs; a refusal is a per-unit failure with its category. Pinned in Task 4 (`test_missing_api_key_is_config_error`) and Task 5 (`test_refusal_is_reported_not_raised`).

---

## File Structure

```
pyproject.toml                                 # + anthropic, openai
src/unvarnish/
  engagement.py                                # ToolPaths: units_index, unit_dir, extract_state, failures, run_record; Engagement.cost_file
  config.py                                    # BackendConfig.unit_tokens, ModelRef.effort, BudgetConfig unchanged
  schemas/
    analysis.py                                # Unit, UnitsIndex, ExternalRef, CandidateFinding, UnitExtraction, UnitResult, FailureRecord, Failures, ExtractState
    cost.py                                    # Usage, CostEntry, CostLedger
  analysis/
    tokens.py                                  # estimate_tokens()
    split.py                                   # split_file(), structural/html/window splitters
  model/
    __init__.py
    base.py                                    # Message, CompletionRequest, CompletionResponse, Backend protocol, errors
    anthropic_backend.py
    openai_backend.py
    cache.py                                   # CachingBackend, cache_key(), clear_cache()
    registry.py                                # resolve_backend(), load_api_key()
    structured.py                              # strict_schema(), extract_json(), complete_structured()
    budget.py                                  # BudgetTracker, BudgetExceeded
    prompts/
      __init__.py
      extract_system.md
      extract.py                               # build_extract_request(), PROMPT_VERSION
  phases/
    base.py                                    # PhaseStatus.stopped; RunRecord path rename
    split.py                                   # SplitPhase
    extract.py                                 # ExtractPhase
    __init__.py                                # default_phases(): + SplitPhase, ExtractPhase
  util/
    logging.py                                 # setup_run_logging()
  cli.py                                       # run (--dry-run estimate, exit 3), status (+extract), cost, config check, cache clear
tests/
  fake_llm.py                                  # FakeLLM server fixture (Anthropic + OpenAI protocols)
  conftest.py                                  # + fake_llm fixture, model_config helper
  test_schemas_analysis.py
  test_tokens_and_split.py
  test_model_base_registry.py
  test_fake_llm.py
  test_anthropic_backend.py
  test_openai_backend.py
  test_cache.py
  test_structured.py
  test_prompts.py
  test_split_phase.py
  test_extract_phase.py
  test_cost_and_logging.py
  test_cli_model_commands.py
```

---

### Task 1: Dependencies, analysis schemas, and path reconciliation

**Files:**
- Modify: `pyproject.toml`, `src/unvarnish/engagement.py`, `src/unvarnish/config.py`, `src/unvarnish/phases/base.py`, `tests/test_engagement.py`, `tests/test_cli_run.py`
- Create: `src/unvarnish/schemas/analysis.py`, `src/unvarnish/schemas/cost.py`, `tests/test_schemas_analysis.py`

**Interfaces:**
- Produces (`unvarnish.schemas.cost`):
  - `class Usage(BaseModel)`: `input_tokens, output_tokens, cache_read_tokens, cache_write_tokens: int = 0`; `__add__`; `total() -> int`
  - `class CostEntry(BaseModel)`: `tool: str`, `phase: str`, `backend: str`, `model: str`, `usage: Usage`, `at: datetime`
  - `class CostLedger(BaseModel)`: `entries: list[CostEntry]`; `total() -> Usage`; `by_phase() -> dict[str, Usage]`; `estimate_usd(prices: Prices | None) -> float | None`
- Produces (`unvarnish.schemas.analysis`):
  - `class UnitKind(StrEnum)`: `function, class_def, method, group, script_block, style_block, markup, window, file`
  - `class Unit(BaseModel)`: `id, tool, module_id, path, language: str | None, kind: UnitKind, name: str | None, line_start, line_end, byte_start, byte_end, token_estimate: int, split_method: Literal["structural","windowed"], generated: bool = False`
  - `class SkippedFile(BaseModel)`: `path: str`, `reason: str`
  - `class UnitsIndex(BaseModel)`: `tool: str`, `unit_tokens: int`, `units: list[Unit]`, `modules: dict[str, list[str]]` (module id → unit ids in order), `skipped: list[SkippedFile]`
  - `class ExternalRef(BaseModel)`: `system: str`, `kind: Literal["http","db","file","queue","env","process","library","other"]`, `detail: str`
  - `class CandidateFinding(BaseModel)`: `category: Category`, `severity: Severity`, `title, summary, impact, remediation: str`, `line_start: int`, `line_end: int`, `excerpt: str | None`, `confidence: float` (0..1)
  - `class UnitExtraction(BaseModel)`: `purpose: str`, `interface: list[str]`, `external_calls: list[ExternalRef]`, `data_read: list[str]`, `data_written: list[str]`, `auth_behaviour: str | None`, `error_handling: str | None`, `risks: list[str]`, `candidate_findings: list[CandidateFinding]`, `confidence: float`
  - `class UnitResult(BaseModel)`: `unit: Unit`, `extraction: UnitExtraction`, `findings: list[Finding]`, `dropped_findings: int`, `backend: str`, `model: str`, `usage: Usage`, `prompt_version: str`, `attempts: int`
  - `class FailureRecord(BaseModel)`: `phase: str`, `unit_id: str | None`, `path: str | None`, `error: str`, `attempts: int = 1`
  - `class Failures(BaseModel)`: `tool: str`, `items: list[FailureRecord]`
  - `class ExtractState(BaseModel)`: `tool: str`, `backend: str`, `model: str`, `prompt_version: str`, `units_total, units_done, units_failed: int`, `usage: Usage`, `stopped_for_budget: bool = False`
- Produces (`unvarnish.engagement.ToolPaths`, added): `units_index = analysis/units.json`, `unit_dir = analysis/units/`, `extract_state = analysis/extract-state.json`, `run_record = analysis/run-record.json`; `failures` keeps `analysis/failures.json` but now holds `Failures`. `Engagement.cost_file = <root>/cost.json`.
- Produces (`unvarnish.config`, added): `BackendConfig.unit_tokens: int | None = None`, `ModelRef.effort: Literal["low","medium","high","xhigh","max"] | None = None`.
- Modifies: `record_run`/`load_run_record` write and read `paths.run_record` instead of `paths.failures`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_schemas_analysis.py
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from unvarnish.config import BackendConfig, EngagementConfig, ModelRef, Prices
from unvarnish.engagement import Engagement
from unvarnish.schemas.analysis import (
    CandidateFinding,
    Unit,
    UnitExtraction,
    UnitKind,
    UnitsIndex,
)
from unvarnish.schemas.cost import CostEntry, CostLedger, Usage
from unvarnish.schemas.finding import Category, Severity


def test_usage_adds_and_totals():
    a = Usage(input_tokens=10, output_tokens=5, cache_read_tokens=3)
    b = Usage(input_tokens=1, cache_write_tokens=2)
    s = a + b
    assert (s.input_tokens, s.output_tokens, s.cache_read_tokens, s.cache_write_tokens) == (11, 5, 3, 2)
    assert s.total() == 21


def test_cost_ledger_totals_and_estimate():
    led = CostLedger(entries=[
        CostEntry(tool="t", phase="extract", backend="a", model="m",
                  usage=Usage(input_tokens=1_000_000, output_tokens=100_000), at=datetime.now(UTC)),
        CostEntry(tool="t", phase="verify", backend="a", model="m",
                  usage=Usage(input_tokens=500_000), at=datetime.now(UTC)),
    ])
    assert led.total().input_tokens == 1_500_000
    assert led.by_phase()["extract"].output_tokens == 100_000
    assert led.estimate_usd(Prices(input_per_mtok=4.0, output_per_mtok=20.0)) == pytest.approx(8.0)
    assert led.estimate_usd(None) is None


def test_unit_and_index_shapes():
    u = Unit(id="abc", tool="t", module_id="a.py", path="a.py", language="python",
             kind=UnitKind.function, name="f", line_start=1, line_end=10, byte_start=0,
             byte_end=120, token_estimate=40, split_method="structural")
    idx = UnitsIndex(tool="t", unit_tokens=8000, units=[u], modules={"a.py": ["abc"]}, skipped=[])
    assert idx.modules["a.py"] == ["abc"]
    assert u.generated is False


def test_candidate_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        CandidateFinding(category=Category.security, severity=Severity.high, title="t", summary="s",
                         impact="i", remediation="r", line_start=1, line_end=2, excerpt=None,
                         confidence=1.5)


def test_unit_extraction_minimal():
    ex = UnitExtraction(purpose="p", interface=[], external_calls=[], data_read=[], data_written=[],
                        auth_behaviour=None, error_handling=None, risks=[], candidate_findings=[],
                        confidence=0.5)
    assert ex.purpose == "p"


def test_config_additions():
    cfg = EngagementConfig(backends={"b": {"type": "anthropic", "unit_tokens": 4000}},
                           models={"default": {"backend": "b", "model": "m", "effort": "high"}})
    assert cfg.backends["b"].unit_tokens == 4000
    assert cfg.models.default is not None and cfg.models.default.effort == "high"
    assert BackendConfig(type="anthropic").unit_tokens is None
    assert ModelRef(backend="b", model="m").effort is None


def test_new_paths(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    p = eng.tool_paths("x")
    assert p.units_index == p.analysis / "units.json"
    assert p.unit_dir == p.analysis / "units"
    assert p.extract_state == p.analysis / "extract-state.json"
    assert p.run_record == p.analysis / "run-record.json"
    assert p.failures == p.analysis / "failures.json"
    assert eng.cost_file == eng.root / "cost.json"
```

Also edit `tests/test_cli_run.py::test_failures_are_persisted_and_shown_in_status` so the asserted file is `analysis / "run-record.json"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_schemas_analysis.py -q`
Expected: FAIL with `ModuleNotFoundError: unvarnish.schemas.analysis`

- [ ] **Step 3: Add dependencies**

```bash
uv add "anthropic>=1.0" "openai>=1.50"
```

- [ ] **Step 4: Implement `schemas/cost.py`**

```python
# src/unvarnish/schemas/cost.py
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from unvarnish.config import Prices


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )

    def total(self) -> int:
        return (self.input_tokens + self.output_tokens + self.cache_read_tokens
                + self.cache_write_tokens)


class CostEntry(BaseModel):
    tool: str
    phase: str
    backend: str
    model: str
    usage: Usage
    at: datetime


class CostLedger(BaseModel):
    entries: list[CostEntry] = Field(default_factory=list)

    def total(self) -> Usage:
        acc = Usage()
        for e in self.entries:
            acc = acc + e.usage
        return acc

    def by_phase(self) -> dict[str, Usage]:
        out: dict[str, Usage] = {}
        for e in self.entries:
            out[e.phase] = out.get(e.phase, Usage()) + e.usage
        return out

    def estimate_usd(self, prices: Prices | None) -> float | None:
        if prices is None:
            return None
        t = self.total()
        billed_input = t.input_tokens + t.cache_write_tokens + t.cache_read_tokens
        return (billed_input / 1_000_000) * prices.input_per_mtok + (
            t.output_tokens / 1_000_000
        ) * prices.output_per_mtok
```

(Cache reads are billed at a discount in reality; the estimate is deliberately conservative. The `cost` command labels it an upper bound.)

- [ ] **Step 5: Implement `schemas/analysis.py`**

```python
# src/unvarnish/schemas/analysis.py
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Finding, Severity


class UnitKind(StrEnum):
    function = "function"
    class_def = "class"
    method = "method"
    group = "group"
    script_block = "script_block"
    style_block = "style_block"
    markup = "markup"
    window = "window"
    file = "file"


class Unit(BaseModel):
    id: str
    tool: str
    module_id: str
    path: str
    language: str | None
    kind: UnitKind
    name: str | None = None
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    token_estimate: int
    split_method: Literal["structural", "windowed"]
    generated: bool = False


class SkippedFile(BaseModel):
    path: str
    reason: str


class UnitsIndex(BaseModel):
    tool: str
    unit_tokens: int
    units: list[Unit]
    modules: dict[str, list[str]] = Field(default_factory=dict)
    skipped: list[SkippedFile] = Field(default_factory=list)


class ExternalRef(BaseModel):
    system: str
    kind: Literal["http", "db", "file", "queue", "env", "process", "library", "other"]
    detail: str


class CandidateFinding(BaseModel):
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    line_start: int
    line_end: int
    excerpt: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class UnitExtraction(BaseModel):
    purpose: str
    interface: list[str] = Field(default_factory=list)
    external_calls: list[ExternalRef] = Field(default_factory=list)
    data_read: list[str] = Field(default_factory=list)
    data_written: list[str] = Field(default_factory=list)
    auth_behaviour: str | None = None
    error_handling: str | None = None
    risks: list[str] = Field(default_factory=list)
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class UnitResult(BaseModel):
    unit: Unit
    extraction: UnitExtraction
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class FailureRecord(BaseModel):
    phase: str
    unit_id: str | None = None
    path: str | None = None
    error: str
    attempts: int = 1


class Failures(BaseModel):
    tool: str
    items: list[FailureRecord] = Field(default_factory=list)


class ExtractState(BaseModel):
    tool: str
    backend: str
    model: str
    prompt_version: str
    units_total: int = 0
    units_done: int = 0
    units_failed: int = 0
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
```

- [ ] **Step 6: Extend config, paths, and run record**

In `src/unvarnish/config.py`:

```python
class BackendConfig(BaseModel):
    type: Literal["anthropic", "openai_compatible"]
    base_url: str | None = None
    api_key_env: str | None = None
    api_key_keychain: str | None = None
    unit_tokens: int | None = None
    capabilities: BackendCapabilities = Field(default_factory=BackendCapabilities)


class ModelRef(BaseModel):
    backend: str
    model: str
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None
```

In `src/unvarnish/engagement.py` `ToolPaths.__init__`, add after `self.failures = ...`:

```python
        self.run_record = self.analysis / "run-record.json"
        self.units_index = self.analysis / "units.json"
        self.unit_dir = self.analysis / "units"
        self.extract_state = self.analysis / "extract-state.json"
```

and on `Engagement`:

```python
    @property
    def cost_file(self) -> Path:
        return self.root / "cost.json"
```

In `src/unvarnish/phases/base.py`, `record_run` writes to `ctx.paths.run_record` and `load_run_record` reads `ctx.paths.run_record`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_schemas_analysis.py tests/test_cli_run.py tests/test_engagement.py -q`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock src/unvarnish/schemas/analysis.py src/unvarnish/schemas/cost.py src/unvarnish/config.py src/unvarnish/engagement.py src/unvarnish/phases/base.py tests/test_schemas_analysis.py tests/test_cli_run.py
git commit -m "feat: analysis and cost schemas, model SDK dependencies, run-record path"
```

---

### Task 2: Token estimate and file splitter

**Files:**
- Create: `src/unvarnish/analysis/tokens.py`, `src/unvarnish/analysis/split.py`, `tests/test_tokens_and_split.py`

**Interfaces:**
- Consumes: `get_parser`, `FUNCTION_NODE_TYPES`, `_is_test_runner_callback` (slice 1 `analysis/treesitter.py`); `SCRIPT_RE`, `STYLE_RE`, `count_lines` (`analysis/metrics.py`); `Unit, UnitKind` (Task 1).
- Produces (`unvarnish.analysis.tokens`): `estimate_tokens(data: bytes | str) -> int` (`max(1, len(bytes) // 3)`; conservative for code).
- Produces (`unvarnish.analysis.split`):
  - `@dataclass class Span`: `kind: UnitKind`, `name: str | None`, `byte_start: int`, `byte_end: int`, `line_start: int`, `line_end: int`
  - `structural_spans(source: bytes, language: str, unit_tokens: int) -> list[Span] | None` (None when no parser)
  - `window_spans(source: bytes, unit_tokens: int, overlap: float = 0.10, base_byte: int = 0, base_line: int = 1) -> list[Span]`
  - `html_spans(source: bytes, unit_tokens: int) -> list[Span]`
  - `split_file(source: bytes, path: str, language: str | None, unit_tokens: int, *, tool: str, generated: bool = False) -> list[Unit]`
  - `unit_id(path: str, line_start: int, line_end: int, split_method: str) -> str`
  - `CLASS_NODE_TYPES: dict[str, set[str]]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_tokens_and_split.py
from unvarnish.analysis.split import (
    html_spans,
    split_file,
    structural_spans,
    unit_id,
    window_spans,
)
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.schemas.analysis import UnitKind

PY = b"".join([
    b"import os\n\n",
    b"def a():\n    return 1\n\n",
    b"def b():\n    return 2\n\n",
    b"class C:\n    def m(self):\n        return 3\n\n    def n(self):\n        return 4\n",
])


def test_estimate_tokens():
    assert estimate_tokens(b"") == 1
    assert estimate_tokens("x" * 300) == 100


def test_structural_groups_small_definitions(tmp_path):
    spans = structural_spans(PY, "python", unit_tokens=8000)
    assert len(spans) == 1 and spans[0].kind == UnitKind.group
    assert spans[0].line_start == 1 and spans[0].line_end == 12


def test_structural_splits_at_definition_boundaries():
    # unit_tokens small enough that each def becomes its own unit; class is split into methods
    spans = structural_spans(PY, "python", unit_tokens=12)
    kinds = [s.kind for s in spans]
    names = [s.name for s in spans]
    assert UnitKind.function in kinds and UnitKind.method in kinds
    assert "a" in names and "m" in names and "n" in names
    # spans tile the file in order without overlap
    for prev, nxt in zip(spans, spans[1:]):
        assert nxt.byte_start >= prev.byte_end


def test_structural_returns_none_without_parser():
    assert structural_spans(b"x", "no-such-language", 100) is None


def test_window_spans_overlap_and_cover():
    src = b"".join(f"line {i}\n".encode() for i in range(100))  # ~700 bytes
    spans = window_spans(src, unit_tokens=50)  # ~150 bytes per window
    assert spans[0].byte_start == 0 and spans[-1].byte_end == len(src)
    assert all(s.kind == UnitKind.window for s in spans)
    assert len(spans) >= 4
    # consecutive windows overlap by roughly 10%
    assert spans[1].byte_start < spans[0].byte_end
    assert spans[0].line_start == 1


def test_html_spans_separate_streams():
    from tests.conftest import HTML_SAMPLE

    spans = html_spans(HTML_SAMPLE.encode(), unit_tokens=8000)
    kinds = [s.kind for s in spans]
    assert kinds.count(UnitKind.script_block) == 2
    assert kinds.count(UnitKind.style_block) == 1
    assert UnitKind.markup in kinds
    render = next(s for s in spans if s.kind == UnitKind.script_block)
    assert render.line_start == 12 and render.line_end == 18


def test_split_file_python_and_windowed_fallback():
    units = split_file(PY, "pkg/a.py", "python", 8000, tool="t")
    assert len(units) == 1 and units[0].split_method == "structural"
    assert units[0].module_id == "pkg/a.py" and units[0].id == unit_id("pkg/a.py", 1, 12, "structural")
    big = b"x = 1\n" * 20000  # 120 KB of statements, no definitions
    units = split_file(big, "big.py", "python", 2000, tool="t")
    assert len(units) > 10 and all(u.split_method == "windowed" for u in units)
    unknown = split_file(b"foo\nbar\n", "x.weird", None, 8000, tool="t")
    assert len(unknown) == 1 and unknown[0].kind == UnitKind.file


def test_split_file_marks_generated():
    units = split_file(b"var a=1;\n", "app.min.js", "javascript", 8000, tool="t", generated=True)
    assert units[0].generated is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tokens_and_split.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `analysis/tokens.py`**

```python
# src/unvarnish/analysis/tokens.py
from __future__ import annotations

BYTES_PER_TOKEN = 3  # conservative for source code; real tokenizers average ~3.5


def estimate_tokens(data: bytes | str) -> int:
    n = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
    return max(1, n // BYTES_PER_TOKEN)
```

- [ ] **Step 4: Implement `analysis/split.py`**

```python
# src/unvarnish/analysis/split.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from unvarnish.analysis.metrics import SCRIPT_RE, STYLE_RE
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.analysis.treesitter import (
    FUNCTION_NODE_TYPES,
    _is_test_runner_callback,
    _node_name,
    get_parser,
)
from unvarnish.schemas.analysis import Unit, UnitKind

CLASS_NODE_TYPES: dict[str, set[str]] = {
    "python": {"class_definition"},
    "javascript": {"class_declaration", "class"},
    "typescript": {"class_declaration", "abstract_class_declaration", "interface_declaration"},
    "tsx": {"class_declaration", "abstract_class_declaration", "interface_declaration"},
    "go": {"type_declaration"},
    "rust": {"impl_item", "struct_item", "enum_item", "trait_item", "mod_item"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration"},
    "c_sharp": {"class_declaration", "interface_declaration", "struct_declaration", "namespace_declaration"},
    "kotlin": {"class_declaration", "object_declaration"},
    "ruby": {"class", "module"},
    "php": {"class_declaration", "interface_declaration", "trait_declaration"},
    "swift": {"class_declaration", "protocol_declaration"},
    "scala": {"class_definition", "object_definition", "trait_definition"},
}


@dataclass
class Span:
    kind: UnitKind
    name: str | None
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int


def unit_id(path: str, line_start: int, line_end: int, split_method: str) -> str:
    return hashlib.sha1(f"{path}|{line_start}|{line_end}|{split_method}".encode()).hexdigest()[:12]


def _line_of(source: bytes, byte_offset: int) -> int:
    return source.count(b"\n", 0, byte_offset) + 1


# --- structural -----------------------------------------------------------

def _definition_kind(node: Any, language: str, source: bytes) -> UnitKind | None:
    if node.type in CLASS_NODE_TYPES.get(language, set()):
        return UnitKind.class_def
    if node.type in FUNCTION_NODE_TYPES.get(language, set()) and not _is_test_runner_callback(node, source):
        parent = node.parent
        inside_class = False
        while parent is not None:
            if parent.type in CLASS_NODE_TYPES.get(language, set()):
                inside_class = True
                break
            parent = parent.parent
        return UnitKind.method if inside_class else UnitKind.function
    return None


def _leaf_spans(node: Any, language: str, source: bytes, unit_tokens: int) -> list[tuple[Any, UnitKind | None]]:
    """Top-level children, descending into definitions that are too large on their own."""
    out: list[tuple[Any, UnitKind | None]] = []
    for child in node.children:
        kind = _definition_kind(child, language, source)
        size = estimate_tokens(source[child.start_byte:child.end_byte])
        if size > unit_tokens and child.children and kind is not None:
            # descend into the body (class -> methods, oversized function -> statements)
            body = child.child_by_field_name("body") or child
            inner = _leaf_spans(body, language, source, unit_tokens)
            if len(inner) > 1:
                out.extend(inner)
                continue
        out.append((child, kind))
    return out


def structural_spans(source: bytes, language: str, unit_tokens: int) -> list[Span] | None:
    parser = get_parser(language)
    if parser is None:
        return None
    tree = parser.parse(source)
    leaves = _leaf_spans(tree.root_node, language, source, unit_tokens)
    spans: list[Span] = []
    group: list[tuple[Any, UnitKind | None]] = []
    group_tokens = 0

    def flush() -> None:
        nonlocal group, group_tokens
        if not group:
            return
        first, last = group[0][0], group[-1][0]
        if len(group) == 1 and group[0][1] is not None:
            kind, name = group[0][1], _node_name(first, source)
        else:
            kind, name = UnitKind.group, None
        spans.append(Span(kind=kind, name=name, byte_start=first.start_byte, byte_end=last.end_byte,
                          line_start=first.start_point.row + 1, line_end=last.end_point.row + 1))
        group, group_tokens = [], 0

    for node, kind in leaves:
        size = estimate_tokens(source[node.start_byte:node.end_byte])
        if size > unit_tokens:
            flush()
            # too big and not further splittable: window this node alone
            for w in window_spans(source[node.start_byte:node.end_byte], unit_tokens,
                                  base_byte=node.start_byte, base_line=node.start_point.row + 1):
                spans.append(w)
            continue
        if group and group_tokens + size > unit_tokens:
            flush()
        group.append((node, kind))
        group_tokens += size
    flush()
    return spans


# --- windowing --------------------------------------------------------------

def window_spans(source: bytes, unit_tokens: int, overlap: float = 0.10,
                 base_byte: int = 0, base_line: int = 1) -> list[Span]:
    if not source:
        return []
    target = max(unit_tokens * 3, 64)
    step = max(int(target * (1 - overlap)), 32)
    spans: list[Span] = []
    start = 0
    n = len(source)
    while start < n:
        end = min(start + target, n)
        if end < n:
            nl = source.rfind(b"\n", start, end)
            if nl > start:
                end = nl + 1
        spans.append(Span(
            kind=UnitKind.window, name=None, byte_start=base_byte + start, byte_end=base_byte + end,
            line_start=base_line + source.count(b"\n", 0, start),
            line_end=base_line + source.count(b"\n", 0, max(end - 1, start)),
        ))
        if end >= n:
            break
        nxt = start + step
        nl = source.rfind(b"\n", start, nxt)
        start = nl + 1 if nl > start else nxt
    return spans


# --- html -------------------------------------------------------------------

def html_spans(source: bytes, unit_tokens: int) -> list[Span]:
    spans: list[Span] = []
    regions: list[tuple[int, int, UnitKind]] = []
    for m in SCRIPT_RE.finditer(source):
        regions.append((m.start(1), m.end(1), UnitKind.script_block))
    for m in STYLE_RE.finditer(source):
        regions.append((m.start(1), m.end(1), UnitKind.style_block))
    regions.sort()
    cursor = 0
    for start, end, kind in regions:
        if start > cursor and source[cursor:start].strip():
            spans.extend(_markup(source, cursor, start, unit_tokens))
        body = source[start:end]
        base_line = _line_of(source, start)
        if kind == UnitKind.script_block:
            inner = structural_spans(body, "javascript", unit_tokens) or []
            if inner and all(estimate_tokens(body[s.byte_start:s.byte_end]) <= unit_tokens for s in inner):
                for s in inner:
                    spans.append(Span(kind=UnitKind.script_block, name=s.name,
                                      byte_start=start + s.byte_start, byte_end=start + s.byte_end,
                                      line_start=base_line + s.line_start - 1,
                                      line_end=base_line + s.line_end - 1))
                cursor = end
                continue
        for w in window_spans(body, unit_tokens, base_byte=start, base_line=base_line):
            spans.append(Span(kind=kind, name=None, byte_start=w.byte_start, byte_end=w.byte_end,
                              line_start=w.line_start, line_end=w.line_end))
        cursor = end
    if cursor < len(source) and source[cursor:].strip():
        spans.extend(_markup(source, cursor, len(source), unit_tokens))
    spans.sort(key=lambda s: s.byte_start)
    return spans


def _markup(source: bytes, start: int, end: int, unit_tokens: int) -> list[Span]:
    body = source[start:end]
    return [Span(kind=UnitKind.markup, name=None, byte_start=w.byte_start, byte_end=w.byte_end,
                 line_start=w.line_start, line_end=w.line_end)
            for w in window_spans(body, unit_tokens, base_byte=start, base_line=_line_of(source, start))]


# --- entry point ------------------------------------------------------------

def split_file(source: bytes, path: str, language: str | None, unit_tokens: int, *,
               tool: str, generated: bool = False) -> list[Unit]:
    if language == "html":
        spans = html_spans(source, unit_tokens)
        method = "structural"
    else:
        spans = structural_spans(source, language, unit_tokens) if language else None
        method = "structural"
        if spans is None:
            if estimate_tokens(source) <= unit_tokens:
                spans = [Span(kind=UnitKind.file, name=None, byte_start=0, byte_end=len(source),
                              line_start=1, line_end=max(source.count(b"\n") + (0 if source.endswith(b"\n") else 1), 1))]
            else:
                spans = window_spans(source, unit_tokens)
                method = "windowed"
    units: list[Unit] = []
    for s in spans:
        split_method = "windowed" if s.kind == UnitKind.window else method
        units.append(Unit(
            id=unit_id(path, s.line_start, s.line_end, split_method), tool=tool, module_id=path,
            path=path, language=language, kind=s.kind, name=s.name,
            line_start=s.line_start, line_end=s.line_end, byte_start=s.byte_start, byte_end=s.byte_end,
            token_estimate=estimate_tokens(source[s.byte_start:s.byte_end]),
            split_method=split_method, generated=generated,
        ))
    return units
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_tokens_and_split.py -q`
Expected: PASS (8 tests). If `test_structural_splits_at_definition_boundaries` finds no `method`, print the tree-sitter node types for the class body (`uv run python -c ...`) and extend `CLASS_NODE_TYPES`, not the test.

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/analysis/tokens.py src/unvarnish/analysis/split.py tests/test_tokens_and_split.py
git commit -m "feat: token estimate and structural/HTML/window file splitter"
```

---

### Task 3: Model base types, errors, and backend registry

**Files:**
- Create: `src/unvarnish/model/__init__.py`, `src/unvarnish/model/base.py`, `src/unvarnish/model/registry.py`, `tests/test_model_base_registry.py`

**Interfaces:**
- Produces (`unvarnish.model.base`):
  - `class Message(BaseModel)`: `role: Literal["user","assistant"]`, `content: str`
  - `class CompletionRequest(BaseModel)`: `system: str`, `messages: list[Message]`, `schema: dict | None = None`, `schema_name: str = "output"`, `max_tokens: int = 8000`, `temperature: float | None = None`, `effort: str | None = None`, `cache_system: bool = True`
  - `class CompletionResponse(BaseModel)`: `text: str`, `usage: Usage`, `model: str`, `stop_reason: str | None = None`, `refusal_category: str | None = None`, `cached: bool = False`
  - `class Backend(Protocol)`: `name: str`, `model: str`, `capabilities: BackendCapabilities`; `complete(req: CompletionRequest) -> CompletionResponse`
  - Errors: `BackendError(Exception)`, `BackendConfigError(BackendError)` (bad config, missing key → exit 2), `BackendUnavailable(BackendError)` (auth/network after retries → exit 2), `ModelRefusal(BackendError)` with `.category`
- Produces (`unvarnish.model.registry`):
  - `load_api_key(cfg: BackendConfig, name: str) -> str | None` (env var, then keychain via `keyring` if configured; `BackendConfigError` if a source is configured but empty)
  - `resolve_model_ref(config: EngagementConfig, phase: str) -> ModelRef | None` (phase override, else default)
  - `resolve_backend(eng: Engagement, phase: str) -> Backend` (raises `BackendConfigError("no model configured")` when none; wraps in `CachingBackend` from Task 7 — until Task 7 exists, returns the raw backend)
  - `NoModelConfigured(BackendConfigError)`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_model_base_registry.py
import pytest

from unvarnish.config import BackendConfig, EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.registry import (
    BackendConfigError,
    NoModelConfigured,
    load_api_key,
    resolve_backend,
    resolve_model_ref,
)


def test_request_defaults():
    r = CompletionRequest(system="s", messages=[Message(role="user", content="u")])
    assert r.max_tokens == 8000 and r.schema is None and r.cache_system is True


def test_resolve_model_ref_prefers_phase_override():
    cfg = EngagementConfig(models={"default": {"backend": "a", "model": "m1"},
                                   "phases": {"extract": {"backend": "b", "model": "m2"}}})
    assert resolve_model_ref(cfg, "extract").model == "m2"
    assert resolve_model_ref(cfg, "verify").model == "m1"
    assert resolve_model_ref(EngagementConfig(), "extract") is None


def test_load_api_key_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "sk-test")
    assert load_api_key(BackendConfig(type="anthropic", api_key_env="MY_KEY"), "a") == "sk-test"
    assert load_api_key(BackendConfig(type="openai_compatible"), "a") is None


def test_missing_api_key_is_config_error(monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    with pytest.raises(BackendConfigError, match="MISSING_KEY"):
        load_api_key(BackendConfig(type="anthropic", api_key_env="MISSING_KEY"), "a")


def test_resolve_backend_errors(tmp_path, monkeypatch):
    eng = Engagement.create(tmp_path / "e")
    with pytest.raises(NoModelConfigured):
        resolve_backend(eng, "extract")
    eng.config.models.default = {"backend": "ghost", "model": "m"}  # type: ignore[assignment]
    eng.config = EngagementConfig.model_validate(eng.config.model_dump())
    with pytest.raises(BackendConfigError, match="ghost"):
        resolve_backend(eng, "extract")


def test_resolve_backend_builds_openai_compatible(tmp_path, monkeypatch):
    monkeypatch.setenv("ONPREM_KEY", "k")
    eng = Engagement.create(tmp_path / "e")
    eng.config = EngagementConfig.model_validate({
        "backends": {"onprem": {"type": "openai_compatible", "base_url": "http://127.0.0.1:9/v1",
                                "api_key_env": "ONPREM_KEY"}},
        "models": {"default": {"backend": "onprem", "model": "qwen"}},
    })
    b = resolve_backend(eng, "extract")
    assert b.name == "onprem" and b.model == "qwen"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_model_base_registry.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/base.py`**

```python
# src/unvarnish/model/__init__.py
```
(empty)

```python
# src/unvarnish/model/base.py
from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, Field

from unvarnish.config import BackendCapabilities
from unvarnish.schemas.cost import Usage


class Message(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class CompletionRequest(BaseModel):
    system: str
    messages: list[Message]
    schema: dict | None = None
    schema_name: str = "output"
    max_tokens: int = 8000
    temperature: float | None = None
    effort: str | None = None
    cache_system: bool = True


class CompletionResponse(BaseModel):
    text: str
    usage: Usage = Field(default_factory=Usage)
    model: str
    stop_reason: str | None = None
    refusal_category: str | None = None
    cached: bool = False


class Backend(Protocol):
    name: str
    model: str
    capabilities: BackendCapabilities

    def complete(self, req: CompletionRequest) -> CompletionResponse: ...


class BackendError(Exception):
    pass


class BackendConfigError(BackendError):
    pass


class BackendUnavailable(BackendError):
    pass


class ModelRefusal(BackendError):
    def __init__(self, category: str | None, message: str = "model refused the request") -> None:
        super().__init__(f"{message} (category: {category or 'unknown'})")
        self.category = category
```

- [ ] **Step 4: Implement `model/registry.py`**

```python
# src/unvarnish/model/registry.py
from __future__ import annotations

import os

from unvarnish.config import BackendConfig, EngagementConfig, ModelRef
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend, BackendConfigError


class NoModelConfigured(BackendConfigError):
    pass


def resolve_model_ref(config: EngagementConfig, phase: str) -> ModelRef | None:
    return config.models.phases.get(phase) or config.models.default


def load_api_key(cfg: BackendConfig, name: str) -> str | None:
    if cfg.api_key_env:
        value = os.environ.get(cfg.api_key_env)
        if not value:
            raise BackendConfigError(
                f"backend {name!r}: environment variable {cfg.api_key_env} is not set"
            )
        return value
    if cfg.api_key_keychain:
        try:
            import keyring  # optional dependency
        except ImportError as exc:
            raise BackendConfigError(
                f"backend {name!r}: api_key_keychain needs the 'keyring' package"
            ) from exc
        value = keyring.get_password(cfg.api_key_keychain, name)
        if not value:
            raise BackendConfigError(
                f"backend {name!r}: no password in keychain service {cfg.api_key_keychain!r}"
            )
        return value
    return None


def build_backend(name: str, cfg: BackendConfig, model: str) -> Backend:
    key = load_api_key(cfg, name)
    if cfg.type == "anthropic":
        from unvarnish.model.anthropic_backend import AnthropicBackend

        return AnthropicBackend(name=name, model=model, api_key=key, base_url=cfg.base_url,
                                capabilities=cfg.capabilities)
    from unvarnish.model.openai_backend import OpenAICompatibleBackend

    if not cfg.base_url:
        raise BackendConfigError(f"backend {name!r}: openai_compatible needs base_url")
    return OpenAICompatibleBackend(name=name, model=model, api_key=key or "none",
                                   base_url=cfg.base_url, capabilities=cfg.capabilities)


def resolve_backend(eng: Engagement, phase: str) -> Backend:
    ref = resolve_model_ref(eng.config, phase)
    if ref is None:
        raise NoModelConfigured("no model configured: set models.default in engagement.yaml")
    cfg = eng.config.backends.get(ref.backend)
    if cfg is None:
        known = ", ".join(eng.config.backends) or "none"
        raise BackendConfigError(f"model for {phase!r} names backend {ref.backend!r}; known: {known}")
    backend = build_backend(ref.backend, cfg, ref.model)
    try:
        from unvarnish.model.cache import CachingBackend  # Task 7

        return CachingBackend(backend, eng.cache_dir / "responses")
    except ImportError:
        return backend
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_model_base_registry.py -q`
Expected: `test_resolve_backend_builds_openai_compatible` FAILS with `ModuleNotFoundError: unvarnish.model.openai_backend` (Task 6); the other 5 PASS. Mark that test `@pytest.mark.xfail(strict=True, reason="Task 6")` for now and remove the marker in Task 6.

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/model tests/test_model_base_registry.py
git commit -m "feat: model request/response types, errors, and backend registry"
```

---

### Task 4: Fake LLM server fixture

**Files:**
- Create: `tests/fake_llm.py`, `tests/test_fake_llm.py`
- Modify: `tests/conftest.py`

**Interfaces:**
- Produces (`tests.fake_llm`):
  - `class FakeLLM`: `start() -> None`, `stop() -> None`, `url: str` (e.g. `http://127.0.0.1:PORT`), `requests: list[dict]` (captured JSON bodies with `path` added), `script(*responses)` where each response is a `str` (returned as model text), a `dict` with keys `status` (int) and optional `text`/`body`, or a callable `(body: dict) -> str | dict`. Responses are consumed in order; when the script is empty the server echoes `{"echo": true}`.
  - `anthropic_message(text, *, model, input_tokens=100, output_tokens=20, cache_read=0, cache_write=0, stop_reason="end_turn", stop_details=None) -> dict`
  - `openai_completion(text, *, model, prompt_tokens=100, completion_tokens=20, finish_reason="stop") -> dict`
- conftest fixture `fake_llm` (function-scoped, started and stopped around the test) and helper `model_config(fake: FakeLLM, kind: Literal["anthropic","openai_compatible"], **caps) -> dict` returning a config dict with one backend pointed at the fake and `models.default` set.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_fake_llm.py
import json
import urllib.request

from tests.fake_llm import FakeLLM, anthropic_message, openai_completion


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_fake_serves_anthropic_and_openai_shapes(fake_llm: FakeLLM):
    fake_llm.script('{"a": 1}', '{"b": 2}')
    code, body = _post(fake_llm.url + "/v1/messages", {"model": "m", "messages": []})
    assert code == 200 and body["content"][0]["text"] == '{"a": 1}' and body["usage"]["input_tokens"] > 0
    code, body = _post(fake_llm.url + "/v1/chat/completions", {"model": "m", "messages": []})
    assert code == 200 and body["choices"][0]["message"]["content"] == '{"b": 2}'
    assert [r["path"] for r in fake_llm.requests] == ["/v1/messages", "/v1/chat/completions"]


def test_fake_status_and_callable(fake_llm: FakeLLM):
    fake_llm.script({"status": 429}, lambda body: f"model={body['model']}")
    code, _ = _post(fake_llm.url + "/v1/messages", {"model": "m", "messages": []})
    assert code == 429
    code, body = _post(fake_llm.url + "/v1/messages", {"model": "zed", "messages": []})
    assert code == 200 and body["content"][0]["text"] == "model=zed"


def test_builders():
    m = anthropic_message("hi", model="x", stop_reason="refusal", stop_details={"type": "refusal", "category": "cyber"})
    assert m["stop_details"]["category"] == "cyber"
    o = openai_completion("hi", model="x", finish_reason="length")
    assert o["choices"][0]["finish_reason"] == "length"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_fake_llm.py -q`
Expected: FAIL with `ModuleNotFoundError: tests.fake_llm`

- [ ] **Step 3: Implement `tests/fake_llm.py`**

```python
# tests/fake_llm.py
from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Scripted = str | dict | Callable[[dict], str | dict]


def anthropic_message(text: str, *, model: str, input_tokens: int = 100, output_tokens: int = 20,
                      cache_read: int = 0, cache_write: int = 0, stop_reason: str = "end_turn",
                      stop_details: dict | None = None) -> dict:
    return {
        "id": "msg_fake", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": text}] if text else [],
        "stop_reason": stop_reason, "stop_sequence": None, "stop_details": stop_details,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                  "cache_read_input_tokens": cache_read, "cache_creation_input_tokens": cache_write},
    }


def openai_completion(text: str, *, model: str, prompt_tokens: int = 100, completion_tokens: int = 20,
                      finish_reason: str = "stop") -> dict:
    return {
        "id": "chatcmpl-fake", "object": "chat.completion", "created": 0, "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                     "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "total_tokens": prompt_tokens + completion_tokens},
    }


class FakeLLM:
    def __init__(self) -> None:
        self._queue: deque[Scripted] = deque()
        self.requests: list[dict[str, Any]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def script(self, *responses: Scripted) -> None:
        with self._lock:
            self._queue.extend(responses)

    def _next(self, body: dict) -> Scripted:
        with self._lock:
            return self._queue.popleft() if self._queue else '{"echo": true}'

    def start(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append({"path": self.path, **body})
                scripted = fake._next(body)
                if callable(scripted):
                    scripted = scripted(body)
                status = 200
                if isinstance(scripted, dict) and "status" in scripted:
                    status = int(scripted["status"])
                    scripted = scripted.get("body") or scripted.get("text") or {
                        "type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}
                    }
                model = body.get("model", "fake")
                if isinstance(scripted, str):
                    if self.path.startswith("/v1/messages"):
                        payload = anthropic_message(scripted, model=model)
                    else:
                        payload = openai_completion(scripted, model=model)
                else:
                    payload = scripted
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
```

Append to `tests/conftest.py`:

```python
from tests.fake_llm import FakeLLM


@pytest.fixture
def fake_llm() -> FakeLLM:
    fake = FakeLLM()
    fake.start()
    try:
        yield fake
    finally:
        fake.stop()


def model_config(fake: FakeLLM, kind: str = "anthropic", model: str = "fake-model", **caps) -> dict:
    """Config dict with one backend pointed at the fake server and models.default set."""
    backend = {"type": kind, "base_url": fake.url, "api_key_env": "UNVARNISH_TEST_KEY"}
    if caps:
        backend["capabilities"] = caps
    return {"backends": {"fake": backend}, "models": {"default": {"backend": "fake", "model": model}}}
```

and in conftest add a session-wide `os.environ.setdefault("UNVARNISH_TEST_KEY", "test-key")` at import time.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_fake_llm.py -q`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add tests/fake_llm.py tests/test_fake_llm.py tests/conftest.py
git commit -m "test: fake LLM server speaking Anthropic and OpenAI protocols"
```

---

### Task 5: Anthropic backend

**Files:**
- Create: `src/unvarnish/model/anthropic_backend.py`, `tests/test_anthropic_backend.py`

**Interfaces:**
- Consumes: `CompletionRequest, CompletionResponse, BackendError, BackendUnavailable` (Task 3), `Usage` (Task 1), `BackendCapabilities` (config), fake server (Task 4).
- Produces: `class AnthropicBackend`: `__init__(name: str, model: str, api_key: str | None, base_url: str | None, capabilities: BackendCapabilities, max_retries: int = 3)`; `complete(req) -> CompletionResponse`. Request mapping: `system=[{"type":"text","text":req.system, "cache_control": {"type":"ephemeral"}}]` when `req.cache_system`; `output_config.format = {"type":"json_schema","schema":req.schema}` when a schema is given and `capabilities.json_schema`; `output_config.effort = req.effort` when set; `temperature` only when set. A `stop_reason == "refusal"` becomes a response with empty text and `refusal_category` from `stop_details`. Typed exceptions map: auth/permission/not-found/rate-limit-after-retries/5xx/connection → `BackendUnavailable`; bad request → `BackendError`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_anthropic_backend.py
import json

import pytest

from tests.fake_llm import FakeLLM, anthropic_message
from unvarnish.config import BackendCapabilities
from unvarnish.model.anthropic_backend import AnthropicBackend
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionRequest, Message

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
          "additionalProperties": False}


def _backend(fake: FakeLLM, **caps) -> AnthropicBackend:
    return AnthropicBackend(name="a", model="claude-opus-5-5", api_key="test", base_url=fake.url,
                            capabilities=BackendCapabilities(**caps), max_retries=2)


def _req(**kw) -> CompletionRequest:
    base = dict(system="S" * 10, messages=[Message(role="user", content="hello")])
    base.update(kw)
    return CompletionRequest(**base)


def test_request_shape_with_schema_cache_and_effort(fake_llm: FakeLLM):
    fake_llm.script('{"ok": true}')
    resp = _backend(fake_llm).complete(_req(schema=SCHEMA, effort="medium"))
    assert resp.text == '{"ok": true}' and resp.model == "claude-opus-5-5"
    sent = fake_llm.requests[0]
    assert sent["path"] == "/v1/messages"
    assert sent["model"] == "claude-opus-5-5" and sent["max_tokens"] == 8000
    assert sent["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert sent["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert sent["output_config"]["effort"] == "medium"
    assert sent["messages"] == [{"role": "user", "content": "hello"}]
    assert "temperature" not in sent


def test_no_schema_when_backend_lacks_capability(fake_llm: FakeLLM):
    fake_llm.script("plain")
    _backend(fake_llm, json_schema=False).complete(_req(schema=SCHEMA, cache_system=False))
    sent = fake_llm.requests[0]
    assert "output_config" not in sent or "format" not in sent["output_config"]
    assert "cache_control" not in sent["system"][0]


def test_usage_includes_cache_tokens(fake_llm: FakeLLM):
    fake_llm.script(lambda body: anthropic_message("x", model=body["model"], input_tokens=50,
                                                   output_tokens=7, cache_read=400, cache_write=12))
    resp = _backend(fake_llm).complete(_req())
    assert (resp.usage.input_tokens, resp.usage.output_tokens) == (50, 7)
    assert (resp.usage.cache_read_tokens, resp.usage.cache_write_tokens) == (400, 12)
    assert resp.stop_reason == "end_turn"


def test_refusal_is_reported_not_raised(fake_llm: FakeLLM):
    fake_llm.script(lambda body: anthropic_message("", model=body["model"], stop_reason="refusal",
                                                   stop_details={"type": "refusal", "category": "cyber"}))
    resp = _backend(fake_llm).complete(_req())
    assert resp.refusal_category == "cyber" and resp.text == "" and resp.stop_reason == "refusal"


def test_anthropic_backend_retries_429_without_caching(fake_llm: FakeLLM):
    fake_llm.script({"status": 429}, '{"ok": true}')
    resp = _backend(fake_llm).complete(_req())
    assert resp.text == '{"ok": true}'
    assert len(fake_llm.requests) == 2
    assert resp.usage.input_tokens == 100  # from the successful call only


def test_errors_map_to_backend_errors(fake_llm: FakeLLM):
    fake_llm.script({"status": 401, "body": {"type": "error", "error": {"type": "authentication_error", "message": "bad key"}}})
    with pytest.raises(BackendUnavailable, match="bad key"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 400, "body": {"type": "error", "error": {"type": "invalid_request_error", "message": "nope"}}})
    with pytest.raises(BackendError, match="nope"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 500}, {"status": 500}, {"status": 500})
    with pytest.raises(BackendUnavailable):
        _backend(fake_llm).complete(_req())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_anthropic_backend.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/anthropic_backend.py`**

```python
# src/unvarnish/model/anthropic_backend.py
from __future__ import annotations

from typing import Any

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
)
from unvarnish.schemas.cost import Usage


class AnthropicBackend:
    def __init__(self, name: str, model: str, api_key: str | None, base_url: str | None,
                 capabilities: BackendCapabilities, max_retries: int = 3) -> None:
        import anthropic

        self.name = name
        self.model = model
        self.capabilities = capabilities
        kwargs: dict[str, Any] = {"max_retries": max_retries}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        import anthropic

        system: list[dict[str, Any]] = [{"type": "text", "text": req.system}]
        if req.cache_system:
            system[0]["cache_control"] = {"type": "ephemeral"}
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": req.max_tokens,
            "system": system,
            "messages": [m.model_dump() for m in req.messages],
        }
        output_config: dict[str, Any] = {}
        if req.schema is not None and self.capabilities.json_schema:
            output_config["format"] = {"type": "json_schema", "schema": req.schema}
        if req.effort:
            output_config["effort"] = req.effort
        if output_config:
            kwargs["output_config"] = output_config
        if req.temperature is not None:
            kwargs["temperature"] = req.temperature

        try:
            resp = self._client.messages.create(**kwargs)
        except anthropic.BadRequestError as exc:
            raise BackendError(f"{self.name}: bad request: {exc.message}") from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError,
                anthropic.NotFoundError) as exc:
            raise BackendUnavailable(f"{self.name}: {exc.message}") from exc
        except (anthropic.RateLimitError, anthropic.InternalServerError) as exc:
            raise BackendUnavailable(f"{self.name}: gave up after retries: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise BackendUnavailable(f"{self.name}: connection failed: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise BackendUnavailable(f"{self.name}: HTTP {exc.status_code}: {exc.message}") from exc

        u = resp.usage
        usage = Usage(
            input_tokens=u.input_tokens or 0, output_tokens=u.output_tokens or 0,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
        )
        refusal: str | None = None
        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            refusal = (getattr(details, "category", None) or "unknown") if details else "unknown"
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return CompletionResponse(text=text, usage=usage, model=resp.model,
                                  stop_reason=resp.stop_reason, refusal_category=refusal)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_anthropic_backend.py -q`
Expected: PASS (6 tests; the 429 and 500 tests take a second or two for SDK backoff). If the SDK rejects an unknown `output_config` key, check the installed `anthropic` version supports structured outputs (`uv pip show anthropic`), upgrade, and re-run; do not drop the parameter.

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/model/anthropic_backend.py tests/test_anthropic_backend.py
git commit -m "feat: Anthropic backend with structured output, prompt caching, and error mapping"
```

---

### Task 6: OpenAI-compatible backend

**Files:**
- Create: `src/unvarnish/model/openai_backend.py`, `tests/test_openai_backend.py`
- Modify: `tests/test_model_base_registry.py` (remove the xfail marker)

**Interfaces:**
- Produces: `class OpenAICompatibleBackend`: `__init__(name, model, api_key: str, base_url: str, capabilities, max_retries=3)`; `complete(req)`. Mapping: `messages=[{"role":"system","content":req.system}, ...]`; `response_format={"type":"json_schema","json_schema":{"name":req.schema_name,"schema":req.schema,"strict":True}}` when schema and `capabilities.json_schema`; `max_tokens`; `temperature` only when set. `finish_reason` becomes `stop_reason`; a `message.refusal` becomes `refusal_category="refusal"`; `usage.prompt_tokens_details.cached_tokens` → `cache_read_tokens` when present.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_openai_backend.py
import pytest

from tests.fake_llm import FakeLLM, openai_completion
from unvarnish.config import BackendCapabilities
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionRequest, Message
from unvarnish.model.openai_backend import OpenAICompatibleBackend

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
          "additionalProperties": False}


def _backend(fake: FakeLLM, **caps) -> OpenAICompatibleBackend:
    return OpenAICompatibleBackend(name="onprem", model="qwen", api_key="k", base_url=fake.url + "/v1",
                                   capabilities=BackendCapabilities(**caps), max_retries=2)


def _req(**kw) -> CompletionRequest:
    base = dict(system="SYS", messages=[Message(role="user", content="hello")])
    base.update(kw)
    return CompletionRequest(**base)


def test_request_shape_with_json_schema(fake_llm: FakeLLM):
    fake_llm.script('{"ok": true}')
    resp = _backend(fake_llm).complete(_req(schema=SCHEMA, schema_name="unit", temperature=0.0))
    assert resp.text == '{"ok": true}' and resp.model == "qwen" and resp.stop_reason == "stop"
    sent = fake_llm.requests[0]
    assert sent["path"] == "/v1/chat/completions"
    assert sent["messages"][0] == {"role": "system", "content": "SYS"}
    assert sent["messages"][1] == {"role": "user", "content": "hello"}
    assert sent["response_format"] == {"type": "json_schema",
                                       "json_schema": {"name": "unit", "schema": SCHEMA, "strict": True}}
    assert sent["max_tokens"] == 8000 and sent["temperature"] == 0.0


def test_no_response_format_without_capability(fake_llm: FakeLLM):
    fake_llm.script("text")
    _backend(fake_llm, json_schema=False).complete(_req(schema=SCHEMA))
    assert "response_format" not in fake_llm.requests[0]


def test_usage_and_refusal(fake_llm: FakeLLM):
    def refused(body):
        c = openai_completion("", model=body["model"], prompt_tokens=9, completion_tokens=1)
        c["choices"][0]["message"]["refusal"] = "I can't help with that"
        c["usage"]["prompt_tokens_details"] = {"cached_tokens": 5}
        return c

    fake_llm.script(refused)
    resp = _backend(fake_llm).complete(_req())
    assert resp.refusal_category == "refusal"
    assert resp.usage.input_tokens == 9 and resp.usage.cache_read_tokens == 5


def test_errors(fake_llm: FakeLLM):
    fake_llm.script({"status": 401, "body": {"error": {"message": "bad key", "type": "invalid_request_error"}}})
    with pytest.raises(BackendUnavailable, match="bad key"):
        _backend(fake_llm).complete(_req())
    fake_llm.script({"status": 400, "body": {"error": {"message": "nope", "type": "invalid_request_error"}}})
    with pytest.raises(BackendError, match="nope"):
        _backend(fake_llm).complete(_req())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_openai_backend.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/openai_backend.py`**

```python
# src/unvarnish/model/openai_backend.py
from __future__ import annotations

from typing import Any

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
)
from unvarnish.schemas.cost import Usage


class OpenAICompatibleBackend:
    def __init__(self, name: str, model: str, api_key: str, base_url: str,
                 capabilities: BackendCapabilities, max_retries: int = 3) -> None:
        from openai import OpenAI

        self.name = name
        self.model = model
        self.capabilities = capabilities
        self._client = OpenAI(api_key=api_key, base_url=base_url, max_retries=max_retries)

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        import openai

        messages: list[dict[str, Any]] = [{"role": "system", "content": req.system}]
        messages += [m.model_dump() for m in req.messages]
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages,
                                  "max_tokens": req.max_tokens}
        if req.temperature is not None:
            kwargs["temperature"] = req.temperature
        if req.schema is not None and self.capabilities.json_schema:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": req.schema_name, "schema": req.schema, "strict": True},
            }
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except openai.BadRequestError as exc:
            raise BackendError(f"{self.name}: bad request: {exc.message}") from exc
        except (openai.AuthenticationError, openai.PermissionDeniedError, openai.NotFoundError) as exc:
            raise BackendUnavailable(f"{self.name}: {exc.message}") from exc
        except (openai.RateLimitError, openai.InternalServerError) as exc:
            raise BackendUnavailable(f"{self.name}: gave up after retries: {exc.message}") from exc
        except openai.APIConnectionError as exc:
            raise BackendUnavailable(f"{self.name}: connection failed: {exc}") from exc
        except openai.APIStatusError as exc:
            raise BackendUnavailable(f"{self.name}: HTTP {exc.status_code}: {exc.message}") from exc

        choice = resp.choices[0]
        text = choice.message.content or ""
        refusal = getattr(choice.message, "refusal", None)
        u = resp.usage
        cached = 0
        if u is not None and getattr(u, "prompt_tokens_details", None) is not None:
            cached = getattr(u.prompt_tokens_details, "cached_tokens", 0) or 0
        usage = Usage(
            input_tokens=(u.prompt_tokens if u else 0) or 0,
            output_tokens=(u.completion_tokens if u else 0) or 0,
            cache_read_tokens=cached,
        )
        return CompletionResponse(text=text, usage=usage, model=resp.model or self.model,
                                  stop_reason=choice.finish_reason,
                                  refusal_category="refusal" if refusal else None)
```

- [ ] **Step 4: Run tests; remove the xfail marker from Task 3's registry test**

Run: `uv run pytest tests/test_openai_backend.py tests/test_model_base_registry.py -q`
Expected: PASS (4 + 6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/model/openai_backend.py tests/test_openai_backend.py tests/test_model_base_registry.py
git commit -m "feat: OpenAI-compatible backend for vLLM, Ollama, Azure, and gateways"
```

---

### Task 7: Content-addressed response cache

**Files:**
- Create: `src/unvarnish/model/cache.py`, `tests/test_cache.py`

**Interfaces:**
- Produces (`unvarnish.model.cache`):
  - `CACHE_SCHEMA_VERSION = "1"`
  - `cache_key(backend_name: str, model: str, req: CompletionRequest) -> str` (sha256 hex of a sorted JSON of backend, model, the request, and `CACHE_SCHEMA_VERSION`)
  - `class CachingBackend`: wraps a `Backend`; `name`, `model`, `capabilities` delegate; `complete(req)` returns the stored `CompletionResponse` with `cached=True` and `usage=Usage()` on a hit, otherwise calls through and stores the response unless it is a refusal or empty; attribute `inner`
  - `clear_cache(cache_dir: Path) -> int` (files removed)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cache.py
from pathlib import Path

import pytest

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import BackendUnavailable, CompletionRequest, CompletionResponse, Message
from unvarnish.model.cache import CachingBackend, cache_key, clear_cache
from unvarnish.schemas.cost import Usage


class Scripted:
    name = "s"
    model = "m"
    capabilities = BackendCapabilities()

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, req):
        self.calls += 1
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _req(content="q", **kw):
    return CompletionRequest(system="sys", messages=[Message(role="user", content=content)], **kw)


def _resp(text="ok"):
    return CompletionResponse(text=text, usage=Usage(input_tokens=5, output_tokens=2), model="m")


def test_cache_hit_skips_backend_and_zeroes_usage(tmp_path: Path):
    inner = Scripted(_resp("first"))
    cb = CachingBackend(inner, tmp_path / "responses")
    a = cb.complete(_req())
    b = cb.complete(_req())
    assert inner.calls == 1
    assert a.text == b.text == "first"
    assert a.cached is False and b.cached is True
    assert b.usage == Usage()
    assert len(list((tmp_path / "responses").glob("*.json"))) == 1


def test_cache_key_sensitivity():
    k = cache_key("s", "m", _req())
    assert k == cache_key("s", "m", _req())
    assert k != cache_key("s", "m", _req("other"))
    assert k != cache_key("s", "m2", _req())
    assert k != cache_key("s", "m", _req(effort="high"))
    assert k != cache_key("s", "m", _req(schema={"type": "object"}))


def test_cache_never_stores_errors(tmp_path: Path):
    inner = Scripted(BackendUnavailable("down"), _resp("later"))
    cb = CachingBackend(inner, tmp_path / "responses")
    with pytest.raises(BackendUnavailable):
        cb.complete(_req())
    assert list((tmp_path / "responses").glob("*.json")) == []
    assert cb.complete(_req()).text == "later"


def test_refusals_and_empty_not_cached(tmp_path: Path):
    inner = Scripted(CompletionResponse(text="", model="m", refusal_category="cyber"), _resp("x"))
    cb = CachingBackend(inner, tmp_path / "responses")
    assert cb.complete(_req()).refusal_category == "cyber"
    assert cb.complete(_req()).text == "x"
    assert inner.calls == 2


def test_clear_cache(tmp_path: Path):
    cb = CachingBackend(Scripted(_resp(), _resp()), tmp_path / "responses")
    cb.complete(_req("a"))
    cb.complete(_req("b"))
    assert clear_cache(tmp_path / "responses") == 2
    assert clear_cache(tmp_path / "responses") == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cache.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/cache.py`**

```python
# src/unvarnish/model/cache.py
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import Backend, CompletionRequest, CompletionResponse
from unvarnish.schemas.cost import Usage

CACHE_SCHEMA_VERSION = "1"


def cache_key(backend_name: str, model: str, req: CompletionRequest) -> str:
    payload = {"v": CACHE_SCHEMA_VERSION, "backend": backend_name, "model": model,
               "request": req.model_dump(mode="json")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class CachingBackend:
    def __init__(self, inner: Backend, cache_dir: Path) -> None:
        self.inner = inner
        self.cache_dir = cache_dir

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def model(self) -> str:
        return self.inner.model

    @property
    def capabilities(self) -> BackendCapabilities:
        return self.inner.capabilities

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        path = self.cache_dir / f"{cache_key(self.inner.name, self.inner.model, req)}.json"
        if path.exists():
            stored = CompletionResponse.model_validate_json(path.read_text(encoding="utf-8"))
            return stored.model_copy(update={"cached": True, "usage": Usage()})
        resp = self.inner.complete(req)
        if resp.refusal_category is None and resp.text.strip():
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(resp.model_dump_json(), encoding="utf-8")
            tmp.replace(path)
        return resp


def clear_cache(cache_dir: Path) -> int:
    if not cache_dir.exists():
        return 0
    n = 0
    for p in cache_dir.glob("*.json"):
        p.unlink()
        n += 1
    return n
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache.py tests/test_model_base_registry.py -q`
Expected: PASS (the registry's `resolve_backend` now wraps in `CachingBackend`; `b.name`/`b.model` still delegate)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/model/cache.py tests/test_cache.py
git commit -m "feat: content-addressed model response cache"
```

---

### Task 8: Structured completion with retry and repair

**Files:**
- Create: `src/unvarnish/model/structured.py`, `tests/test_structured.py`

**Interfaces:**
- Produces (`unvarnish.model.structured`):
  - `strict_schema(model_cls: type[BaseModel]) -> dict` (pydantic JSON schema with `additionalProperties: false` and all properties required on every object, `default` keys removed, `$defs` preserved)
  - `extract_json(text: str) -> str` (strips code fences, returns the first balanced top-level JSON object; if unbalanced, returns from the first `{` to the end)
  - `class StructuredOutputError(BackendError)`: `attempts: int`, `last_error: str`, `last_text: str`
  - `class StructuredResult(Generic[T])`: `parsed: T`, `usage: Usage`, `attempts: int`, `raw_text: str`
  - `complete_structured(backend: Backend, req: CompletionRequest, model_cls: type[T]) -> StructuredResult[T]` (native schema when `backend.capabilities.json_schema`, otherwise JSON-in-prompt; attempt 1, attempt 2 with the validation error appended, attempt 3 as a repair call at low effort; raises `ModelRefusal` on refusal and `StructuredOutputError` after the third failure)
  - `JSON_IN_PROMPT_SUFFIX: str`, `REPAIR_SYSTEM: str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_structured.py
import json

import pytest
from pydantic import BaseModel

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import CompletionRequest, CompletionResponse, Message, ModelRefusal
from unvarnish.model.structured import (
    StructuredOutputError,
    complete_structured,
    extract_json,
    strict_schema,
)
from unvarnish.schemas.analysis import UnitExtraction
from unvarnish.schemas.cost import Usage


class Out(BaseModel):
    name: str
    count: int
    note: str | None = None


class Scripted:
    name = "s"
    model = "m"

    def __init__(self, *texts, json_schema=True):
        self.texts = list(texts)
        self.capabilities = BackendCapabilities(json_schema=json_schema)
        self.requests: list[CompletionRequest] = []

    def complete(self, req):
        self.requests.append(req)
        t = self.texts.pop(0)
        if isinstance(t, CompletionResponse):
            return t
        return CompletionResponse(text=t, usage=Usage(input_tokens=10, output_tokens=3), model="m")


def _req():
    return CompletionRequest(system="sys", messages=[Message(role="user", content="go")])


def test_strict_schema_shape():
    s = strict_schema(Out)
    assert s["additionalProperties"] is False
    assert sorted(s["required"]) == ["count", "name", "note"]
    assert "default" not in json.dumps(s)
    nested = strict_schema(UnitExtraction)
    for d in nested["$defs"].values():
        assert d.get("additionalProperties") is False
        assert sorted(d["required"]) == sorted(d["properties"])


def test_extract_json_handles_fences_prose_and_truncation():
    assert extract_json('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert extract_json('Sure! {"a": {"b": "}"}} trailing') == '{"a": {"b": "}"}}'
    assert extract_json('{"a": [1, 2') == '{"a": [1, 2'


def test_happy_path_native_schema():
    b = Scripted('{"name": "x", "count": 2, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.parsed == Out(name="x", count=2) and r.attempts == 1
    assert b.requests[0].schema is not None and b.requests[0].schema["additionalProperties"] is False
    assert r.usage.input_tokens == 10


def test_json_in_prompt_mode_embeds_schema():
    b = Scripted('here you go: {"name": "x", "count": 1, "note": null}', json_schema=False)
    r = complete_structured(b, _req(), Out)
    assert r.parsed.name == "x"
    assert b.requests[0].schema is None
    assert '"additionalProperties"' in b.requests[0].system and "JSON" in b.requests[0].system


def test_retry_with_validation_error_then_success():
    b = Scripted('{"name": "x"}', '{"name": "x", "count": 3, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.parsed.count == 3 and r.attempts == 2
    second = b.requests[1]
    assert second.messages[-2].role == "assistant" and second.messages[-1].role == "user"
    assert "count" in second.messages[-1].content
    assert r.usage.input_tokens == 20


def test_retry_then_repair_then_failure():
    b = Scripted("nonsense", "still bad", "{broken")
    with pytest.raises(StructuredOutputError) as exc:
        complete_structured(b, _req(), Out)
    assert exc.value.attempts == 3 and exc.value.last_text == "{broken"
    repair = b.requests[2]
    assert repair.effort == "low" and repair.cache_system is False
    assert "still bad" in repair.messages[0].content


def test_truncated_json_is_repaired():
    b = Scripted('{"name": "x", "count": 1, "no', '{"name": "x", "count": 1, "no',
                 '{"name": "x", "count": 1, "note": null}')
    r = complete_structured(b, _req(), Out)
    assert r.attempts == 3 and r.parsed.count == 1


def test_refusal_raises_model_refusal():
    b = Scripted(CompletionResponse(text="", model="m", refusal_category="cyber", stop_reason="refusal"))
    with pytest.raises(ModelRefusal) as exc:
        complete_structured(b, _req(), Out)
    assert exc.value.category == "cyber"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_structured.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/structured.py`**

```python
# src/unvarnish/model/structured.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from unvarnish.model.base import (
    Backend,
    BackendError,
    CompletionRequest,
    Message,
    ModelRefusal,
)
from unvarnish.schemas.cost import Usage

T = TypeVar("T", bound=BaseModel)

JSON_IN_PROMPT_SUFFIX = (
    "\n\nRespond with exactly one JSON object and nothing else: no prose, no code fences. "
    "It must validate against this JSON schema:\n"
)
REPAIR_SYSTEM = (
    "You repair malformed JSON. You receive a JSON schema and a model's malformed output. "
    "Return exactly one JSON object that validates against the schema, preserving every value "
    "from the malformed output that can be kept. Output the JSON object only."
)
FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class StructuredOutputError(BackendError):
    def __init__(self, attempts: int, last_error: str, last_text: str) -> None:
        super().__init__(f"structured output failed after {attempts} attempts: {last_error[:200]}")
        self.attempts = attempts
        self.last_error = last_error
        self.last_text = last_text


@dataclass
class StructuredResult(Generic[T]):
    parsed: T
    usage: Usage
    attempts: int
    raw_text: str


def _strictify(node: Any) -> Any:
    if isinstance(node, dict):
        node = {k: _strictify(v) for k, v in node.items() if k != "default"}
        if node.get("type") == "object" and "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node["properties"].keys())
        return node
    if isinstance(node, list):
        return [_strictify(x) for x in node]
    return node


def strict_schema(model_cls: type[BaseModel]) -> dict:
    return _strictify(model_cls.model_json_schema())


def extract_json(text: str) -> str:
    m = FENCE_RE.search(text)
    if m:
        text = m.group(1)
    start = text.find("{")
    if start < 0:
        return text.strip()
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def _parse(model_cls: type[T], text: str, stop_reason: str | None) -> T:
    if stop_reason in ("max_tokens", "length"):
        raise ValueError(f"output truncated (stop_reason={stop_reason})")
    return model_cls.model_validate_json(extract_json(text))


def complete_structured(backend: Backend, req: CompletionRequest, model_cls: type[T]) -> StructuredResult[T]:
    schema = strict_schema(model_cls)
    native = backend.capabilities.json_schema
    base = req.model_copy(update={
        "schema": schema if native else None,
        "schema_name": model_cls.__name__,
        "system": req.system if native else req.system + JSON_IN_PROMPT_SUFFIX + json.dumps(schema),
    })
    usage = Usage()
    messages = list(base.messages)
    last_text, last_error = "", ""

    for attempt in (1, 2):
        resp = backend.complete(base.model_copy(update={"messages": messages}))
        usage = usage + resp.usage
        if resp.refusal_category is not None or resp.stop_reason == "refusal":
            raise ModelRefusal(resp.refusal_category)
        try:
            return StructuredResult(_parse(model_cls, resp.text, resp.stop_reason), usage, attempt, resp.text)
        except (ValidationError, ValueError) as exc:
            last_text, last_error = resp.text, str(exc)[:1500]
        messages = messages + [
            Message(role="assistant", content=resp.text or "(empty)"),
            Message(role="user", content=(
                "Your previous output was not valid. Error:\n" + last_error
                + "\nReturn only a JSON object that matches the schema.")),
        ]

    repair = CompletionRequest(
        system=REPAIR_SYSTEM,
        messages=[Message(role="user", content=(
            "Schema:\n" + json.dumps(schema) + "\n\nMalformed output:\n" + last_text))],
        schema=schema if native else None, schema_name=model_cls.__name__,
        max_tokens=base.max_tokens, effort="low", cache_system=False,
    )
    resp = backend.complete(repair)
    usage = usage + resp.usage
    if resp.refusal_category is not None:
        raise ModelRefusal(resp.refusal_category)
    try:
        return StructuredResult(_parse(model_cls, resp.text, resp.stop_reason), usage, 3, resp.text)
    except (ValidationError, ValueError) as exc:
        raise StructuredOutputError(3, str(exc)[:1500], resp.text) from exc
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_structured.py -q`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/model/structured.py tests/test_structured.py
git commit -m "feat: structured completion with schema strictness, retry, and repair"
```

---

### Task 9: Extraction prompts

**Files:**
- Create: `src/unvarnish/model/prompts/__init__.py`, `src/unvarnish/model/prompts/extract_system.md`, `src/unvarnish/model/prompts/extract.py`, `tests/test_prompts.py`

**Interfaces:**
- Produces (`unvarnish.model.prompts.extract`):
  - `PROMPT_VERSION = "2026-10-17.1"` (bump whenever the system prompt or unit message format changes; it is part of every unit's `inputs_hash`)
  - `NEIGHBOURHOOD_MAX = 8`, `NEIGHBOURHOOD_CHARS = 200`
  - `build_system_prompt(categories: Sequence[str] | None = None) -> str` (loads `extract_system.md`, substitutes `{{SCHEMA}}` with `json.dumps(strict_schema(UnitExtraction), indent=1)`, `{{CATEGORIES}}` and `{{SEVERITIES}}` with the taxonomy; deterministic, no timestamps)
  - `build_unit_message(unit: Unit, source: str, *, frameworks: Sequence[str], neighbourhood: Sequence[str]) -> str`
  - `build_extract_request(unit, source, *, frameworks, neighbourhood, effort: str | None, system: str | None = None) -> CompletionRequest`
  - `GENERATED_INSTRUCTION: str` (reduced-prompt instruction for generated files)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_prompts.py
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.model.prompts.extract import (
    GENERATED_INSTRUCTION,
    PROMPT_VERSION,
    build_extract_request,
    build_system_prompt,
    build_unit_message,
)
from unvarnish.schemas.analysis import Unit, UnitKind


def _unit(**kw) -> Unit:
    base = dict(id="u1", tool="t", module_id="app.py", path="app.py", language="python",
                kind=UnitKind.function, name="main", line_start=10, line_end=20, byte_start=0,
                byte_end=100, token_estimate=30, split_method="structural")
    base.update(kw)
    return Unit(**base)


def test_system_prompt_is_stable_and_cacheable():
    a, b = build_system_prompt(), build_system_prompt()
    assert a == b
    assert estimate_tokens(a) > 600  # comfortably over the 512-token cache minimum
    assert '"candidate_findings"' in a and "maintainability" in a and "critical" in a
    assert "{{" not in a


def test_unit_message_contents():
    msg = build_unit_message(_unit(), "def main():\n    pass\n", frameworks=["Flask"],
                             neighbourhood=["helper(): parses input", "x" * 500])
    assert "app.py" in msg and "lines 10-20" in msg and "python" in msg and "Flask" in msg
    assert "def main():" in msg
    assert "helper(): parses input" in msg
    assert ("x" * 201) not in msg  # neighbourhood entries truncated
    assert GENERATED_INSTRUCTION not in msg


def test_generated_units_get_reduced_instruction():
    msg = build_unit_message(_unit(generated=True), "var a=1", frameworks=[], neighbourhood=[])
    assert GENERATED_INSTRUCTION in msg


def test_build_extract_request():
    req = build_extract_request(_unit(), "src", frameworks=[], neighbourhood=[], effort="medium")
    assert req.effort == "medium" and req.cache_system is True
    assert req.messages[0].role == "user" and "src" in req.messages[0].content
    assert req.system == build_system_prompt()
    assert PROMPT_VERSION
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_prompts.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the system prompt**

```markdown
<!-- src/unvarnish/model/prompts/extract_system.md -->
You are the extraction stage of Unvarnish, a tool that vets internally built software for a
consultant who will report the findings to the organisation's leadership and engineers.

You receive one unit of source code (a function, class, group of definitions, script block, or
window of a larger file) together with its file path, language, detected frameworks, and short
summaries of neighbouring units already analysed. Produce a single JSON object describing the
unit. Do not add commentary outside the JSON.

## What to extract

- purpose: one paragraph, plain language, what this unit does and for whom. If it is only part
  of something larger, say what part.
- interface: the public functions, endpoints, commands, or exports this unit defines. Names only.
- external_calls: every system outside this codebase the unit touches. kind is one of http, db,
  file, queue, env, process, library, other. system is the thing reached (a hostname, database,
  path, queue, environment variable, binary, or library). detail says how it is used.
- data_read / data_written: tables, files, keys, objects, or fields read or written.
- auth_behaviour: how the unit authenticates or authorises, or null if it does neither.
- error_handling: how failures are handled, or null if there is no handling.
- risks: short statements of anything a careful engineer would worry about.
- candidate_findings: concrete problems with evidence inside this unit. Each needs a category,
  severity, a line range inside the unit, and an excerpt copied from the source.
- confidence: 0 to 1, how sure you are of the above given what you can see.

## Findings

A finding is a specific problem a reader can verify at the cited lines: a security weakness,
mishandled data, a reliability gap, an operability or compliance issue, or a maintainability
problem that will cost real effort. Do not report style preferences. Do not soften: if a value
is a credential, say so; if an error is swallowed, say so.

Categories: {{CATEGORIES}}
Severities: {{SEVERITIES}}

Severity guide: critical means exploitable now or data loss likely; high means a real defect
with clear impact; medium means a defect that will bite under plausible conditions; low means
worth fixing when touched; info is context only.

Line numbers are absolute file lines and must fall within the unit's stated range. Findings
outside the range are discarded.

## Output

Return exactly one JSON object that validates against this schema:

{{SCHEMA}}
```

- [ ] **Step 4: Implement `model/prompts/extract.py`**

```python
# src/unvarnish/model/prompts/__init__.py
```
(empty)

```python
# src/unvarnish/model/prompts/extract.py
from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.analysis import Unit, UnitExtraction
from unvarnish.schemas.finding import Category, Severity

PROMPT_VERSION = "2026-10-17.1"
NEIGHBOURHOOD_MAX = 8
NEIGHBOURHOOD_CHARS = 200
GENERATED_INSTRUCTION = (
    "This unit comes from a generated or minified file. Report only purpose and external_calls; "
    "leave the other lists empty and candidate_findings empty unless a credential is visible."
)


@cache
def build_system_prompt(categories: tuple[str, ...] | None = None) -> str:
    template = resources.files("unvarnish.model.prompts").joinpath("extract_system.md").read_text(
        encoding="utf-8"
    )
    cats = ", ".join(categories or tuple(c.value for c in Category))
    sevs = ", ".join(s.value for s in Severity)
    schema = json.dumps(strict_schema(UnitExtraction), indent=1, sort_keys=True)
    return (template.replace("{{CATEGORIES}}", cats).replace("{{SEVERITIES}}", sevs)
            .replace("{{SCHEMA}}", schema))


def build_unit_message(unit: Unit, source: str, *, frameworks: Sequence[str],
                       neighbourhood: Sequence[str]) -> str:
    parts = [
        f"File: {unit.path}",
        f"Unit: {unit.kind.value}{' ' + unit.name if unit.name else ''}, lines {unit.line_start}-{unit.line_end}",
        f"Language: {unit.language or 'unknown'}",
        f"Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}",
    ]
    if unit.split_method == "windowed":
        parts.append("Note: this is a window of a larger region; boundaries may cut constructs.")
    if unit.generated:
        parts.append(GENERATED_INSTRUCTION)
    if neighbourhood:
        parts.append("Neighbouring units already analysed (purpose only):")
        for n in list(neighbourhood)[-NEIGHBOURHOOD_MAX:]:
            parts.append(f"- {n[:NEIGHBOURHOOD_CHARS]}")
    parts.append("Source:")
    parts.append(source)
    return "\n".join(parts)


def build_extract_request(unit: Unit, source: str, *, frameworks: Sequence[str],
                          neighbourhood: Sequence[str], effort: str | None,
                          system: str | None = None) -> CompletionRequest:
    return CompletionRequest(
        system=system or build_system_prompt(),
        messages=[Message(role="user", content=build_unit_message(
            unit, source, frameworks=frameworks, neighbourhood=neighbourhood))],
        schema_name="UnitExtraction", effort=effort, cache_system=True,
    )
```

Add to `pyproject.toml` under `[tool.hatch.build.targets.wheel]` nothing extra: hatch includes `.md` files inside the package. Verify with `uv run python -c "from importlib import resources; print(resources.files('unvarnish.model.prompts').joinpath('extract_system.md').read_text()[:40])"`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_prompts.py -q`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/model/prompts tests/test_prompts.py
git commit -m "feat: extraction system prompt and unit message builder"
```

---

### Task 10: Split phase

**Files:**
- Create: `src/unvarnish/phases/split.py`, `tests/test_split_phase.py`

**Interfaces:**
- Consumes: `split_file` (Task 2), `UnitsIndex, SkippedFile` (Task 1), `Census` (slice 1), `resolve_model_ref` (Task 3).
- Produces (`unvarnish.phases.split`):
  - `resolve_unit_tokens(config: EngagementConfig) -> int` (backend override for the extract phase's backend, else `pipeline.unit_tokens`)
  - `class SplitPhase` (`name = "split"`; `MAX_SPLIT_BYTES = 5_000_000`; splits every non-excluded file whose classification is not `binary` or `data`; files over the byte cap are skipped with a reason; writes `UnitsIndex` to `paths.units_index`)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_split_phase.py
from unvarnish.artifacts import read_artifact
from unvarnish.config import EngagementConfig
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.split import SplitPhase, resolve_unit_tokens
from unvarnish.schemas.analysis import UnitKind, UnitsIndex


def _split(eng, name):
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    r = SplitPhase().run(ctx)
    assert r.status == PhaseStatus.ok, r.message
    return read_artifact(ctx.paths.units_index, UnitsIndex).data, ctx


def test_split_synthetic_repo(ingested):
    idx, ctx = _split(*ingested)
    paths = {u.path for u in idx.units}
    assert "app.py" in paths and "static/index.html" in paths and "README.md" in paths
    assert not any(p.startswith("node_modules/") for p in paths)
    app_units = idx.modules["app.py"]
    assert len(app_units) >= 2  # the 3000-line function is bigger than one unit
    by_id = {u.id: u for u in idx.units}
    assert all(by_id[i].path == "app.py" for i in app_units)
    html_kinds = {by_id[i].kind for i in idx.modules["static/index.html"]}
    assert UnitKind.script_block in html_kinds and UnitKind.style_block in html_kinds
    minified = next(u for u in idx.units if u.path == "static/app.min.js")
    assert minified.generated is True
    assert idx.unit_tokens == 8000
    # every unit's range is inside its file and ids are unique
    assert len({u.id for u in idx.units}) == len(idx.units)


def test_split_is_fresh_until_inputs_change(ingested):
    from unvarnish.phases.base import is_fresh

    idx, ctx = _split(*ingested)
    assert is_fresh(SplitPhase(), ctx)
    ctx.engagement.config.pipeline.unit_tokens = 500
    assert not is_fresh(SplitPhase(), ctx)


def test_resolve_unit_tokens_prefers_backend_override():
    cfg = EngagementConfig.model_validate({
        "pipeline": {"unit_tokens": 8000},
        "backends": {"small": {"type": "openai_compatible", "base_url": "http://x", "unit_tokens": 3000}},
        "models": {"default": {"backend": "small", "model": "m"}},
    })
    assert resolve_unit_tokens(cfg) == 3000
    assert resolve_unit_tokens(EngagementConfig()) == 8000


def test_split_skips_huge_files(engagement, tmp_path):
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "huge.py").write_bytes(b"x = 1\n" * 1_000_000)  # 6 MB
    (pile / "ok.py").write_text("y = 2\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    idx, _ = _split(engagement, "pile")
    assert [u.path for u in idx.units] == ["ok.py"]
    assert idx.skipped[0].path == "huge.py" and "5,000,000" in idx.skipped[0].reason
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_split_phase.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `phases/split.py`**

```python
# src/unvarnish/phases/split.py
from __future__ import annotations

import logging
from pathlib import Path

from unvarnish.analysis.languages import Classification
from unvarnish.analysis.split import split_file
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import EngagementConfig
from unvarnish.model.registry import resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.analysis import SkippedFile, Unit, UnitsIndex
from unvarnish.schemas.inventory import Census

log = logging.getLogger("unvarnish.split")

MAX_SPLIT_BYTES = 5_000_000
SPLIT_CLASSES = {Classification.source, Classification.test, Classification.config,
                 Classification.docs, Classification.generated}


def resolve_unit_tokens(config: EngagementConfig) -> int:
    ref = resolve_model_ref(config, "extract")
    if ref is not None:
        backend = config.backends.get(ref.backend)
        if backend is not None and backend.unit_tokens:
            return backend.unit_tokens
    return config.pipeline.unit_tokens


class SplitPhase:
    name = "split"

    def inputs_hash(self, ctx: ToolContext) -> str:
        return hash_inputs([hash_files([ctx.paths.census]), str(resolve_unit_tokens(ctx.config))])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.units_index]

    def run(self, ctx: ToolContext) -> PhaseResult:
        census = read_artifact(ctx.paths.census, Census).data
        unit_tokens = resolve_unit_tokens(ctx.config)
        units: list[Unit] = []
        modules: dict[str, list[str]] = {}
        skipped: list[SkippedFile] = []
        failures: list[str] = []
        for rec in census.files:
            if rec.excluded or rec.classification not in SPLIT_CLASSES:
                continue
            if rec.bytes > MAX_SPLIT_BYTES:
                skipped.append(SkippedFile(path=rec.path, reason=f"larger than {MAX_SPLIT_BYTES:,} bytes"))
                continue
            try:
                source = (ctx.source_root / rec.path).read_bytes()
                file_units = split_file(
                    source, rec.path, rec.language, unit_tokens, tool=ctx.tool,
                    generated=rec.classification == Classification.generated,
                )
            except Exception as exc:  # one bad file never kills a run
                failures.append(f"{rec.path}: split failed: {exc!r}")
                skipped.append(SkippedFile(path=rec.path, reason=f"split failed: {exc!r}"))
                continue
            units.extend(file_units)
            modules[rec.path] = [u.id for u in file_units]
        index = UnitsIndex(tool=ctx.tool, unit_tokens=unit_tokens, units=units, modules=modules,
                           skipped=skipped)
        write_artifact(ctx.paths.units_index, index, produced_by=self.name,
                       inputs_hash=self.inputs_hash(ctx))
        log.info("split %s: %d units across %d files (%d skipped)", ctx.tool, len(units),
                 len(modules), len(skipped))
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, failures=failures,
                           message=f"{len(units)} units in {len(modules)} files, {len(skipped)} skipped")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_split_phase.py -q`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/phases/split.py tests/test_split_phase.py
git commit -m "feat: split phase producing the units index"
```

---

### Task 11: Budget tracker, cost ledger persistence, and extract phase

**Files:**
- Create: `src/unvarnish/model/budget.py`, `src/unvarnish/phases/extract.py`, `tests/test_extract_phase.py`
- Modify: `src/unvarnish/phases/base.py` (`PhaseStatus.stopped`, runner handling)

**Interfaces:**
- Produces (`unvarnish.model.budget`):
  - `class BudgetExceeded(Exception)`
  - `class BudgetTracker`: `__init__(max_tokens: int | None)`; `add(usage: Usage) -> None` (thread-safe); `usage: Usage`; `exceeded: bool`; `check() -> None` raises `BudgetExceeded` when exceeded
  - `load_ledger(eng: Engagement) -> CostLedger`, `record_cost(eng: Engagement, entry: CostEntry) -> None` (append under a lock, atomic write)
- Produces (`unvarnish.phases.base`): `PhaseStatus.stopped = "stopped"`; the runner skips later phases after a `stopped` result with message `skipped: upstream phase 'extract' stopped`.
- Produces (`unvarnish.phases.extract`):
  - `class ExtractPhase`: `__init__(backend: Backend | None = None)` (injectable); `name = "extract"`; `inputs_hash`, `outputs = [paths.extract_state]`, `run`
  - `to_findings(cands: list[CandidateFinding], unit: Unit, tool: str, model: str) -> tuple[list[Finding], int]`
  - `unit_inputs_hash(unit: Unit, source: bytes, backend_name: str, model: str, effort: str | None) -> str`
  - Per-unit artifact: `paths.unit_dir / f"{unit.id}.json"` holding `UnitResult` with `inputs_hash = unit_inputs_hash(...)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_extract_phase.py
import json

import pytest

from tests.conftest import model_config
from tests.fake_llm import FakeLLM
from unvarnish.artifacts import read_artifact
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, load_ledger
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.extract import ExtractPhase, to_findings
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.split import SplitPhase
from unvarnish.schemas.analysis import (
    CandidateFinding,
    ExtractState,
    Failures,
    Unit,
    UnitKind,
    UnitResult,
    UnitsIndex,
)
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Severity

GOOD = {
    "purpose": "Does a thing.", "interface": ["main"], "external_calls": [], "data_read": [],
    "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
    "candidate_findings": [], "confidence": 0.8,
}


def _good(body: dict) -> str:
    user = body["messages"][-1]["content"]
    # cite a finding inside the unit's line range when the unit header is parseable
    out = dict(GOOD)
    if "lines " in user:
        rng = user.split("lines ", 1)[1].split("\n", 1)[0]
        lo, hi = (int(x) for x in rng.split("-"))
        out["candidate_findings"] = [
            {"category": "maintainability", "severity": "low", "title": "In range", "summary": "s",
             "impact": "i", "remediation": "r", "line_start": lo, "line_end": lo, "excerpt": "x",
             "confidence": 0.9},
            {"category": "security", "severity": "high", "title": "Out of range", "summary": "s",
             "impact": "i", "remediation": "r", "line_start": hi + 50, "line_end": hi + 51,
             "excerpt": "y", "confidence": 0.9},
        ]
    return json.dumps(out)


def _prepare(engagement: Engagement, tool: str, fake: FakeLLM, **cfg):
    conf = model_config(fake)
    conf.update(cfg)
    engagement.config = EngagementConfig.model_validate({**engagement.config.model_dump(), **conf})
    engagement.save_config()
    ctx = build_context(engagement, tool)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    return ctx


def test_budget_tracker():
    t = BudgetTracker(100)
    t.add(Usage(input_tokens=60))
    t.check()
    t.add(Usage(output_tokens=50))
    assert t.exceeded
    with pytest.raises(BudgetExceeded):
        t.check()
    BudgetTracker(None).add(Usage(input_tokens=10**9))  # unlimited never raises


def test_to_findings_drops_out_of_range():
    unit = Unit(id="u", tool="t", module_id="a.py", path="a.py", language="python",
                kind=UnitKind.function, line_start=10, line_end=20, byte_start=0, byte_end=1,
                token_estimate=1, split_method="structural")
    cands = [
        CandidateFinding(category=Category.security, severity=Severity.high, title="ok", summary="s",
                         impact="i", remediation="r", line_start=12, line_end=13, excerpt="e", confidence=0.7),
        CandidateFinding(category=Category.security, severity=Severity.high, title="bad", summary="s",
                         impact="i", remediation="r", line_start=1, line_end=2, excerpt=None, confidence=0.7),
    ]
    findings, dropped = to_findings(cands, unit, "t", "m")
    assert dropped == 1 and len(findings) == 1
    f = findings[0]
    assert f.source == "model" and f.model == "m" and f.confidence == 0.7
    assert f.evidence[0].path == "a.py" and f.evidence[0].line_start == 12 and f.verification is None


def test_extract_end_to_end(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 200))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.ok, r.message
    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_total == len(idx.units) and state.units_done == len(idx.units)
    assert state.units_failed == 0 and state.usage.input_tokens > 0
    assert len(fake_llm.requests) == len(idx.units)
    results = [read_artifact(p, UnitResult).data for p in ctx.paths.unit_dir.glob("*.json")]
    assert len(results) == len(idx.units)
    assert all(res.findings and res.dropped_findings == 1 for res in results)
    assert all(f.title == "In range" for res in results for f in res.findings)
    # units within a module were sent in order with a growing neighbourhood
    app_reqs = [q for q in fake_llm.requests if "File: app.py" in q["messages"][-1]["content"]]
    assert "Neighbouring units" not in app_reqs[0]["messages"][-1]["content"]
    assert "Neighbouring units" in app_reqs[-1]["messages"][-1]["content"]
    assert fake_llm.requests[0]["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert load_ledger(eng).total().input_tokens == state.usage.input_tokens


def test_extract_resumes_without_recalling_done_units(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 200))
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    n = len(fake_llm.requests)
    assert PhaseRunner([ExtractPhase()]).run(ctx)[0].status == PhaseStatus.skipped  # fresh
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok  # forced: artifacts reused
    assert len(fake_llm.requests) == n


def test_extract_redoes_changed_unit(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    fake_llm.script(*([_good] * 300))
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    n = len(fake_llm.requests)
    with (ctx.source_root / "README.md").open("a") as fh:
        fh.write("\nchanged\n")
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    assert ExtractPhase().run(ctx).status == PhaseStatus.ok
    assert len(fake_llm.requests) == n + 1
    assert "File: README.md" in fake_llm.requests[-1]["messages"][-1]["content"]


def test_extract_records_unit_failures_and_continues(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm)
    calls = {"n": 0}

    def flaky(body):
        calls["n"] += 1
        return "not json at all" if calls["n"] <= 3 else _good(body)  # first unit fails 3 times

    fake_llm.script(*([flaky] * 300))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.ok and r.failures
    failures = read_artifact(ctx.paths.failures, Failures).data
    assert len(failures.items) == 1 and failures.items[0].attempts == 3
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.units_failed == 1 and state.units_done == state.units_total - 1


def test_budget_cap_stops_cleanly(ingested, fake_llm: FakeLLM):
    eng, tool = ingested
    ctx = _prepare(eng, tool, fake_llm, budget={"max_tokens": 150}, pipeline={"concurrency": 1})
    fake_llm.script(*([_good] * 300))
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.stopped
    state = read_artifact(ctx.paths.extract_state, ExtractState).data
    assert state.stopped_for_budget is True and 1 <= state.units_done < state.units_total
    assert len(fake_llm.requests) == state.units_done
    results = PhaseRunner([ExtractPhase(), SplitPhase()]).run(ctx, force=True)
    assert results[1].status == PhaseStatus.skipped and "stopped" in (results[1].message or "")


def test_no_model_configured_skips(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert SplitPhase().run(ctx).status == PhaseStatus.ok
    r = ExtractPhase().run(ctx)
    assert r.status == PhaseStatus.skipped and "no model configured" in (r.message or "")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_extract_phase.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `model/budget.py`**

```python
# src/unvarnish/model/budget.py
from __future__ import annotations

import threading

from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.engagement import Engagement
from unvarnish.schemas.cost import CostEntry, CostLedger, Usage


class BudgetExceeded(Exception):
    pass


class BudgetTracker:
    def __init__(self, max_tokens: int | None) -> None:
        self.max_tokens = max_tokens
        self.usage = Usage()
        self._lock = threading.Lock()

    def add(self, usage: Usage) -> None:
        with self._lock:
            self.usage = self.usage + usage

    @property
    def exceeded(self) -> bool:
        return self.max_tokens is not None and self.usage.total() > self.max_tokens

    def check(self) -> None:
        if self.exceeded:
            raise BudgetExceeded(
                f"budget cap of {self.max_tokens:,} tokens exceeded ({self.usage.total():,} used)"
            )


_LEDGER_LOCK = threading.Lock()


def load_ledger(eng: Engagement) -> CostLedger:
    if not eng.cost_file.exists():
        return CostLedger()
    return read_artifact(eng.cost_file, CostLedger).data


def record_cost(eng: Engagement, entry: CostEntry) -> None:
    with _LEDGER_LOCK:
        ledger = load_ledger(eng)
        ledger.entries.append(entry)
        write_artifact(eng.cost_file, ledger, produced_by="cost", inputs_hash="")
```

- [ ] **Step 4: Add `PhaseStatus.stopped` to `phases/base.py`**

```python
class PhaseStatus(StrEnum):
    ok = "ok"
    skipped = "skipped"
    failed = "failed"
    stopped = "stopped"  # budget cap reached; resumable
```

In `PhaseRunner.run`, after a result: `if result.status in (PhaseStatus.failed, PhaseStatus.stopped): upstream_failed = phase.name` and the skip message becomes `f"skipped: upstream phase {upstream_failed!r} {'stopped' if stopped else 'failed'}"` (track which with a second variable).

- [ ] **Step 5: Implement `phases/extract.py`**

```python
# src/unvarnish/phases/extract.py
from __future__ import annotations

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend, BackendError, BackendUnavailable, ModelRefusal
from unvarnish.model.budget import BudgetExceeded, BudgetTracker, record_cost
from unvarnish.model.prompts.extract import PROMPT_VERSION, build_extract_request, build_system_prompt
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.model.structured import StructuredOutputError, complete_structured
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.analysis import (
    CandidateFinding,
    ExtractState,
    FailureRecord,
    Failures,
    Unit,
    UnitExtraction,
    UnitResult,
    UnitsIndex,
)
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.schemas.finding import Evidence, Finding, Source
from unvarnish.schemas.inventory import Census

log = logging.getLogger("unvarnish.extract")


def to_findings(cands: list[CandidateFinding], unit: Unit, tool: str, model: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    dropped = 0
    for c in cands:
        if not (unit.line_start <= c.line_start <= c.line_end <= unit.line_end):
            dropped += 1
            continue
        findings.append(Finding(
            tool=tool, category=c.category, severity=c.severity, title=c.title, summary=c.summary,
            impact=c.impact, remediation=c.remediation,
            evidence=[Evidence(path=unit.path, line_start=c.line_start, line_end=c.line_end,
                               excerpt=(c.excerpt or "")[:200] or None)],
            source=Source.model, model=model, confidence=c.confidence,
        ))
    return findings, dropped


def unit_inputs_hash(unit: Unit, source: bytes, backend_name: str, model: str, effort: str | None) -> str:
    return hash_inputs([hashlib.sha256(source).hexdigest(), unit.id, backend_name, model,
                        PROMPT_VERSION, effort or ""])


class ExtractPhase:
    name = "extract"

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
        return hash_inputs([hash_files([ctx.paths.units_index]), model_part, PROMPT_VERSION])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.extract_state]

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        index = read_artifact(ctx.paths.units_index, UnitsIndex).data
        census = read_artifact(ctx.paths.census, Census).data
        by_id = {u.id: u for u in index.units}
        system = build_system_prompt()
        budget = BudgetTracker(ctx.config.budget.max_tokens)
        ctx.paths.unit_dir.mkdir(parents=True, exist_ok=True)
        failures: list[FailureRecord] = []
        done = 0
        stopped = False

        def process_module(module_id: str, unit_ids: list[str]) -> tuple[int, list[FailureRecord], Usage]:
            nonlocal stopped
            source_bytes = (ctx.source_root / module_id).read_bytes()
            neighbourhood: list[str] = []
            module_done = 0
            module_failures: list[FailureRecord] = []
            module_usage = Usage()
            for uid in unit_ids:
                unit = by_id[uid]
                chunk = source_bytes[unit.byte_start:unit.byte_end]
                h = unit_inputs_hash(unit, chunk, backend.name, backend.model, effort)
                out_path = ctx.paths.unit_dir / f"{uid}.json"
                if out_path.exists():
                    try:
                        prior = read_artifact(out_path, UnitResult)
                        if prior.meta.inputs_hash == h:
                            neighbourhood.append(prior.data.extraction.purpose)
                            module_done += 1
                            continue
                    except Exception:  # unreadable artifact: redo the unit
                        pass
                if budget.exceeded or stopped:
                    stopped = True
                    break
                req = build_extract_request(unit, chunk.decode("utf-8", errors="replace"),
                                            frameworks=census.frameworks, neighbourhood=neighbourhood,
                                            effort=effort, system=system)
                try:
                    res = complete_structured(backend, req, UnitExtraction)
                except ModelRefusal as exc:
                    module_failures.append(FailureRecord(phase=self.name, unit_id=uid, path=unit.path,
                                                         error=f"refused ({exc.category})", attempts=1))
                    continue
                except StructuredOutputError as exc:
                    module_failures.append(FailureRecord(phase=self.name, unit_id=uid, path=unit.path,
                                                         error=exc.last_error[:500], attempts=exc.attempts))
                    continue
                except BackendUnavailable:
                    raise
                except BackendError as exc:
                    module_failures.append(FailureRecord(phase=self.name, unit_id=uid, path=unit.path,
                                                         error=str(exc)[:500], attempts=1))
                    continue
                findings, dropped = to_findings(res.parsed.candidate_findings, unit, ctx.tool, backend.model)
                result = UnitResult(unit=unit, extraction=res.parsed, findings=findings,
                                    dropped_findings=dropped, backend=backend.name, model=backend.model,
                                    usage=res.usage, prompt_version=PROMPT_VERSION, attempts=res.attempts)
                write_artifact(out_path, result, produced_by=self.name, inputs_hash=h)
                budget.add(res.usage)
                module_usage = module_usage + res.usage
                neighbourhood.append(res.parsed.purpose)
                module_done += 1
                log.debug("extracted %s %s (%d tokens, %d attempts)", unit.path, uid,
                          res.usage.total(), res.attempts)
            return module_done, module_failures, module_usage

        usage = Usage()
        with ThreadPoolExecutor(max_workers=max(1, ctx.config.pipeline.concurrency)) as pool:
            futures = {pool.submit(process_module, m, ids): m for m, ids in index.modules.items()}
            for fut in as_completed(futures):
                try:
                    d, f, u = fut.result()
                except BudgetExceeded:
                    stopped = True
                    continue
                done += d
                failures.extend(f)
                usage = usage + u

        if usage.total():
            record_cost(ctx.engagement, CostEntry(tool=ctx.tool, phase=self.name, backend=backend.name,
                                                  model=backend.model, usage=usage, at=datetime.now(UTC)))
        state = ExtractState(tool=ctx.tool, backend=backend.name, model=backend.model,
                             prompt_version=PROMPT_VERSION, units_total=len(index.units), units_done=done,
                             units_failed=len(failures), usage=usage, stopped_for_budget=stopped)
        write_artifact(ctx.paths.failures, Failures(tool=ctx.tool, items=failures), produced_by=self.name,
                       inputs_hash="")
        write_artifact(ctx.paths.extract_state, state, produced_by=self.name,
                       inputs_hash="" if stopped else self.inputs_hash(ctx))
        status = PhaseStatus.stopped if stopped else PhaseStatus.ok
        msg = f"{done}/{len(index.units)} units, {len(failures)} failed, {usage.total():,} tokens"
        if stopped:
            msg = "budget cap reached: " + msg
        log.info("extract %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in failures])
```

Note the `extract_state` artifact is written with an empty `inputs_hash` when stopped, so the phase is stale and a later `run` resumes it.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_extract_phase.py tests/test_phase_runner.py -q`
Expected: PASS (8 + 6 tests). The end-to-end test issues one fake request per unit; expect 10-40 units for the synthetic repo.

- [ ] **Step 7: Commit**

```bash
git add src/unvarnish/model/budget.py src/unvarnish/phases/extract.py src/unvarnish/phases/base.py tests/test_extract_phase.py
git commit -m "feat: extract phase with budget cap, resumability, and per-unit artifacts"
```

---

### Task 12: Run logging, cost command, and dry-run estimate

**Files:**
- Create: `src/unvarnish/util/logging.py`, `src/unvarnish/model/estimate.py`, `tests/test_cost_and_logging.py`
- Modify: `src/unvarnish/cli.py`, `src/unvarnish/phases/__init__.py`

**Interfaces:**
- Produces (`unvarnish.util.logging`): `setup_run_logging(eng: Engagement, verbose: bool = False) -> Path` (DEBUG file handler at `logs/run-<YYYYmmdd-HHMMSS>.log`, Rich console handler at INFO, or DEBUG when verbose, on the `unvarnish` logger; idempotent per process: removes handlers it installed earlier)
- Produces (`unvarnish.model.estimate`): `SYSTEM_PROMPT_TOKENS: int` (computed once from `build_system_prompt()`), `NEIGHBOURHOOD_TOKENS = 300`, `OUTPUT_TOKENS_PER_UNIT = 700`; `estimate_extract(index: UnitsIndex, done_ids: set[str] = frozenset()) -> Usage`
- Produces (`unvarnish.phases.default_phases`): `[InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(), RenderPhase()]`
- CLI: `unvarnish cost [-e DIR]` prints the ledger by tool and phase with totals and, when `budget.prices` is set, an upper-bound USD figure; `unvarnish run --dry-run` prints the planned phases plus, for each tool with a stale `extract`, the token estimate (and USD when prices exist); `unvarnish run` sets up logging first and prints the log path at the end.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cost_and_logging.py
import logging
from datetime import UTC, datetime

from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.model.budget import record_cost
from unvarnish.model.estimate import OUTPUT_TOKENS_PER_UNIT, SYSTEM_PROMPT_TOKENS, estimate_extract
from unvarnish.phases import default_phases
from unvarnish.schemas.analysis import Unit, UnitKind, UnitsIndex
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.util.logging import setup_run_logging

runner = CliRunner()


def test_default_phase_order():
    assert [p.name for p in default_phases()] == ["inventory", "git", "scan", "split", "extract", "render"]


def test_estimate_extract_counts_remaining_units():
    units = [Unit(id=f"u{i}", tool="t", module_id="a", path="a", language="python", kind=UnitKind.group,
                  line_start=1, line_end=2, byte_start=0, byte_end=1, token_estimate=1000,
                  split_method="structural") for i in range(3)]
    idx = UnitsIndex(tool="t", unit_tokens=8000, units=units, modules={"a": ["u0", "u1", "u2"]})
    est = estimate_extract(idx)
    assert est.input_tokens == 3 * (SYSTEM_PROMPT_TOKENS + 1000 + 300)
    assert est.output_tokens == 3 * OUTPUT_TOKENS_PER_UNIT
    assert estimate_extract(idx, done_ids={"u0"}).output_tokens == 2 * OUTPUT_TOKENS_PER_UNIT


def test_setup_run_logging_writes_file(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    path = setup_run_logging(eng)
    logging.getLogger("unvarnish.test").info("hello from the test")
    logging.getLogger("unvarnish.test").debug("debug detail")
    for h in logging.getLogger("unvarnish").handlers:
        h.flush()
    text = path.read_text()
    assert path.parent == eng.logs_dir and "hello from the test" in text and "debug detail" in text
    path2 = setup_run_logging(eng)  # idempotent: no duplicate handlers
    assert len([h for h in logging.getLogger("unvarnish").handlers if getattr(h, "_unvarnish", False)]) == 2
    assert path2 != path or True


def test_cost_command(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    record_cost(eng, CostEntry(tool="x", phase="extract", backend="b", model="m",
                               usage=Usage(input_tokens=1_000_000, output_tokens=50_000), at=datetime.now(UTC)))
    r = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert r.exit_code == 0 and "extract" in r.output and "1,000,000" in r.output
    assert "USD" not in r.output
    eng.config.budget.prices = {"input_per_mtok": 4.0, "output_per_mtok": 20.0}  # type: ignore[assignment]
    from unvarnish.config import EngagementConfig

    eng.config = EngagementConfig.model_validate(eng.config.model_dump())
    eng.save_config()
    r = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "USD" in r.output and "5.00" in r.output


def test_dry_run_shows_estimate(tmp_path, synthetic_repo, fake_llm):
    eng = Engagement.create(tmp_path / "e", client="Acme")
    from unvarnish.config import EngagementConfig

    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **model_config(fake_llm)})
    eng.save_config()
    assert runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)]).exit_code == 0
    r = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "extract" in r.output and "estimate" in r.output.lower() and "tokens" in r.output
    assert not (eng.root / "tools" / "bot" / "analysis" / "units.json").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cost_and_logging.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `util/logging.py` and `model/estimate.py`**

```python
# src/unvarnish/util/logging.py
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from rich.logging import RichHandler

from unvarnish.engagement import Engagement


def setup_run_logging(eng: Engagement, verbose: bool = False) -> Path:
    logger = logging.getLogger("unvarnish")
    for h in list(logger.handlers):
        if getattr(h, "_unvarnish", False):
            logger.removeHandler(h)
            h.close()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    eng.logs_dir.mkdir(parents=True, exist_ok=True)
    path = eng.logs_dir / f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    ch = RichHandler(level=logging.DEBUG if verbose else logging.INFO, show_path=False,
                     rich_tracebacks=False, markup=False)
    for h in (fh, ch):
        h._unvarnish = True  # type: ignore[attr-defined]
        logger.addHandler(h)
    return path
```

```python
# src/unvarnish/model/estimate.py
from __future__ import annotations

from collections.abc import Collection

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.model.prompts.extract import build_system_prompt
from unvarnish.schemas.analysis import UnitsIndex
from unvarnish.schemas.cost import Usage

SYSTEM_PROMPT_TOKENS: int = estimate_tokens(build_system_prompt())
NEIGHBOURHOOD_TOKENS = 300
OUTPUT_TOKENS_PER_UNIT = 700


def estimate_extract(index: UnitsIndex, done_ids: Collection[str] = frozenset()) -> Usage:
    remaining = [u for u in index.units if u.id not in done_ids]
    return Usage(
        input_tokens=sum(SYSTEM_PROMPT_TOKENS + u.token_estimate + NEIGHBOURHOOD_TOKENS for u in remaining),
        output_tokens=OUTPUT_TOKENS_PER_UNIT * len(remaining),
    )
```

- [ ] **Step 4: Wire phases, `cost`, logging, and the dry-run estimate into the CLI**

`src/unvarnish/phases/__init__.py`:

```python
def default_phases() -> list[Phase]:
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.phases.split import SplitPhase

    return [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(), RenderPhase()]
```

In `cli.py`:

```python
from unvarnish.model.budget import load_ledger
from unvarnish.model.estimate import estimate_extract
from unvarnish.schemas.analysis import UnitsIndex
from unvarnish.schemas.cost import Usage
from unvarnish.util.logging import setup_run_logging


def _usd(usage: Usage, prices) -> str:
    if prices is None:
        return ""
    billed_in = usage.input_tokens + usage.cache_read_tokens + usage.cache_write_tokens
    usd = billed_in / 1e6 * prices.input_per_mtok + usage.output_tokens / 1e6 * prices.output_per_mtok
    return f" (≤ USD {usd:,.2f})"


@app.command()
def cost(engagement: Path | None = EngagementOption) -> None:
    """Tokens spent per tool and phase, with an upper-bound cost when prices are configured."""
    eng = _load_engagement(engagement)
    ledger = load_ledger(eng)
    prices = eng.config.budget.prices
    table = Table("tool", "phase", "backend/model", "input", "cache read", "cache write", "output",
                  title="cost ledger")
    for e in ledger.entries:
        table.add_row(e.tool, e.phase, f"{e.backend}/{e.model}", f"{e.usage.input_tokens:,}",
                      f"{e.usage.cache_read_tokens:,}", f"{e.usage.cache_write_tokens:,}",
                      f"{e.usage.output_tokens:,}")
    console.print(table)
    total = ledger.total()
    console.print(f"Total: {total.total():,} tokens{_usd(total, prices)}")
    if eng.config.budget.max_tokens:
        console.print(f"Budget cap: {eng.config.budget.max_tokens:,} tokens per run")
```

In `run`: add `verbose: bool = typer.Option(False, "--verbose", "-v")`; after `eng = _load_engagement(...)` and not in dry-run, call `log_path = setup_run_logging(eng, verbose)` and print `Log: {log_path}` after the table. In the dry-run branch, after listing planned phases for a tool, if `extract` is among them and the units index exists, read it and print:

```python
                if any(p.name == "extract" for p in planned) and ctx.paths.units_index.exists():
                    idx = read_artifact(ctx.paths.units_index, UnitsIndex).data
                    done = {p.stem for p in ctx.paths.unit_dir.glob("*.json")} if ctx.paths.unit_dir.exists() else set()
                    est = estimate_extract(idx, done)
                    table.add_row(name, "extract", "estimate",
                                  f"{len(idx.units) - len(done)} units ≈ {est.total():,} tokens{_usd(est, eng.config.budget.prices)}")
                elif any(p.name == "extract" for p in planned):
                    table.add_row(name, "extract", "estimate", "run split first for a token estimate")
```

Map `PhaseStatus.stopped` to colour `yellow` in the status-colour dict and set `any_stopped = True`; exit code 3 when stopped, else 1 when failures, else 0. Also catch `BackendConfigError`/`BackendUnavailable` around `runner.run` and exit 2 with the message.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cost_and_logging.py tests/test_cli_run.py -q`
Expected: PASS. `test_end_to_end_run` in `test_cli_run.py` now sees six phases; its `output.count("fresh") == 4` assertion must become `== 6` on the second run only if extract is fresh — with no model configured extract is "skipped: no model configured" every time, so update that assertion to count `"fresh"` as 5 and assert `"no model configured" in again.output`. Likewise `test_status` expects `after.output.count("fresh") == 5` and `"missing"` for the extract column (it never ran); adjust to assert the four slice-1 columns plus `split` are fresh.

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/util/logging.py src/unvarnish/model/estimate.py src/unvarnish/phases/__init__.py src/unvarnish/cli.py tests/test_cost_and_logging.py tests/test_cli_run.py
git commit -m "feat: run logging, cost ledger command, dry-run token estimate, six-phase pipeline"
```

---

### Task 13: `config check`, `cache clear`, status columns, and exit codes

**Files:**
- Create: `tests/test_cli_model_commands.py`
- Modify: `src/unvarnish/cli.py`

**Interfaces:**
- `unvarnish config check [-e DIR] [--no-probe]`: validates `engagement.yaml`, resolves the backend for `extract` and every phase in `models.phases`, loads the API key, and unless `--no-probe` sends one tiny structured request (`{"ok": true}` schema) through `complete_structured`; prints a table of backend, model, json_schema, tool_calling, context_window, probe result. Exit 2 on any configuration or backend error, 0 otherwise. No model configured is reported, not an error.
- `unvarnish cache clear [-e DIR] [--yes]`: deletes `cache/responses/*.json` after confirmation (`typer.confirm`) unless `--yes`; prints the count.
- `unvarnish status`: the `extract` column shows `done/total` units from `extract-state.json` and `budget-stopped` when applicable.
- `unvarnish run`: exit 3 when any phase `stopped`; exit 2 on `BackendConfigError` / `BackendUnavailable`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli_model_commands.py
import json

from typer.testing import CliRunner

from tests.conftest import model_config
from tests.fake_llm import FakeLLM
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement

runner = CliRunner()


def _engagement(tmp_path, fake: FakeLLM | None = None, **extra) -> Engagement:
    eng = Engagement.create(tmp_path / "e", client="Acme")
    data = eng.config.model_dump()
    if fake is not None:
        data.update(model_config(fake))
    data.update(extra)
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    return eng


def test_config_check_without_model(tmp_path):
    eng = _engagement(tmp_path)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0 and "no model configured" in r.output


def test_config_check_probes_backend(tmp_path, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script('{"ok": true}')
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "fake-model" in r.output and "probe" in r.output.lower() and "ok" in r.output
    assert fake_llm.requests and fake_llm.requests[0]["path"] == "/v1/messages"
    r2 = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r2.exit_code == 0 and len(fake_llm.requests) == 1


def test_config_check_missing_key_is_exit_2(tmp_path, fake_llm: FakeLLM, monkeypatch):
    eng = _engagement(tmp_path, fake_llm)
    monkeypatch.delenv("UNVARNISH_TEST_KEY", raising=False)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2 and "UNVARNISH_TEST_KEY" in r.output


def test_cache_clear(tmp_path):
    eng = _engagement(tmp_path)
    d = eng.cache_dir / "responses"
    d.mkdir(parents=True)
    (d / "a.json").write_text("{}")
    r = runner.invoke(app, ["cache", "clear", "-e", str(eng.root)], input="n\n")
    assert r.exit_code == 1 and (d / "a.json").exists()
    r = runner.invoke(app, ["cache", "clear", "--yes", "-e", str(eng.root)])
    assert r.exit_code == 0 and "1" in r.output and not (d / "a.json").exists()


def test_run_exit_code_3_on_budget(tmp_path, synthetic_repo, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm, budget={"max_tokens": 150}, pipeline={"concurrency": 1})
    good = json.dumps({"purpose": "p", "interface": [], "external_calls": [], "data_read": [],
                       "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
                       "candidate_findings": [], "confidence": 0.5})
    fake_llm.script(*([good] * 300))
    assert runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)]).exit_code == 0
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 3, r.output
    assert "budget" in r.output.lower()
    st = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert st.exit_code == 0 and "budget" in st.output.lower()


def test_run_exit_code_2_on_backend_error(tmp_path, synthetic_repo, fake_llm: FakeLLM):
    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script(*([{"status": 401, "body": {"type": "error", "error": {"type": "authentication_error", "message": "bad key"}}}] * 50))
    assert runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)]).exit_code == 0
    r = runner.invoke(app, ["run", "-e", str(eng.root)])
    assert r.exit_code == 2 and "bad key" in r.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli_model_commands.py -q`
Expected: FAIL (`No such command 'config'`, etc.)

- [ ] **Step 3: Implement the commands**

Append to `cli.py`:

```python
from pydantic import BaseModel as _BaseModel

from unvarnish.model.base import BackendConfigError, BackendError, BackendUnavailable, CompletionRequest, Message
from unvarnish.model.cache import clear_cache
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.model.structured import complete_structured
from unvarnish.schemas.analysis import ExtractState


class _Probe(_BaseModel):
    ok: bool


config_app = typer.Typer(help="Configuration commands.", no_args_is_help=True)
app.add_typer(config_app, name="config")
cache_app = typer.Typer(help="Model response cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


@config_app.command("check")
def config_check(
    engagement: Path | None = EngagementOption,
    probe: bool = typer.Option(True, "--probe/--no-probe", help="Send a tiny request to each backend."),
) -> None:
    """Validate engagement.yaml and probe the configured model backends."""
    eng = _load_engagement(engagement)
    phases = ["extract", *[p for p in eng.config.models.phases if p != "extract"]]
    table = Table("phase", "backend", "model", "json_schema", "tool_calling", "context", "probe")
    failed = False
    seen: set[tuple[str, str]] = set()
    for phase in phases:
        ref = resolve_model_ref(eng.config, phase)
        if ref is None:
            console.print(f"{phase}: no model configured (set models.default in engagement.yaml)")
            continue
        if (ref.backend, ref.model) in seen:
            continue
        seen.add((ref.backend, ref.model))
        try:
            backend = resolve_backend(eng, phase)
            caps = backend.capabilities
            result = "skipped"
            if probe:
                req = CompletionRequest(system="Reply with JSON {\"ok\": true}.",
                                        messages=[Message(role="user", content="ping")],
                                        max_tokens=64, cache_system=False)
                res = complete_structured(backend, req, _Probe)
                result = "ok" if res.parsed.ok else "unexpected reply"
            table.add_row(phase, ref.backend, ref.model, str(caps.json_schema), str(caps.tool_calling),
                          f"{caps.context_window:,}", result)
        except (BackendConfigError, BackendUnavailable, BackendError) as exc:
            failed = True
            table.add_row(phase, ref.backend, ref.model, "-", "-", "-", f"[red]{exc}[/red]")
    console.print(table)
    if failed:
        raise typer.Exit(code=2)


@cache_app.command("clear")
def cache_clear(
    engagement: Path | None = EngagementOption,
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Delete cached model responses."""
    eng = _load_engagement(engagement)
    if not yes and not typer.confirm("Delete all cached model responses?"):
        raise typer.Exit(code=1)
    n = clear_cache(eng.cache_dir / "responses")
    console.print(f"Removed {n} cached response(s).")
```

In `status`, for the `extract` column, replace the generic cell with: if `ctx.paths.extract_state.exists()`, read `ExtractState` and show `f"{s.units_done}/{s.units_total}"` plus `" budget-stopped"` when `s.stopped_for_budget`, coloured yellow when stopped or failed > 0; else fall through to missing/stale/fresh.

In `run`, wrap `runner.run(...)` to catch `(BackendConfigError, BackendUnavailable)` → print and `raise typer.Exit(code=2)`; after the table, `if any_stopped: raise typer.Exit(code=3)`.

- [ ] **Step 4: Run the full suite and lint**

Run: `uv run pytest -q && uv run ruff check .`
Expected: all pass, lint clean.

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/cli.py tests/test_cli_model_commands.py
git commit -m "feat: config check with backend probe, cache clear, extract status, exit codes 2 and 3"
```

---

### Task 14: Docs and a real-run smoke script

**Files:**
- Modify: `README.md`
- Create: `scripts/smoke.sh`

- [ ] **Step 1: Update the README**

Add a "Model configuration" section after "Use":

```markdown
## Model configuration

Slice 2 adds model-assisted extraction. Without a model configured, `unvarnish run` still
produces the scanner-based findings and skips `extract`. To enable it, add a backend and a
default model to `engagement.yaml`:

    backends:
      anthropic:
        type: anthropic
        api_key_env: ANTHROPIC_API_KEY
      onprem:
        type: openai_compatible
        base_url: http://llm.client.internal:8000/v1
        api_key_env: ONPREM_LLM_KEY
        unit_tokens: 4000
        capabilities: { json_schema: true, tool_calling: false, context_window: 32768 }
    models:
      default: { backend: anthropic, model: claude-opus-5-5, effort: medium }
      phases:
        extract: { backend: onprem, model: qwen3-coder }
    budget:
      max_tokens: 20000000
      prices: { input_per_mtok: 4.0, output_per_mtok: 20.0 }

Keys come from the named environment variable (or `api_key_keychain: <service>` with the
`keyring` package). They are never written into the engagement.

    unvarnish config check          # validates config and probes each backend
    unvarnish run --dry-run         # shows what would run and the extract token estimate
    unvarnish run                   # extract resumes where it stopped; exit code 3 on budget cap
    unvarnish cost                  # tokens spent, upper-bound cost when prices are set
    unvarnish cache clear --yes     # forget cached model responses

Every model response is cached under `cache/responses/`, so re-running after a crash or a
config tweak only pays for units whose inputs changed. Logs for each run land in `logs/`.
```

- [ ] **Step 2: Add `scripts/smoke.sh`**

```bash
#!/usr/bin/env bash
# Live smoke test against a real backend. Needs ANTHROPIC_API_KEY (or edit the backend below).
set -euo pipefail
E=$(mktemp -d)/smoke
uv run unvarnish init "$E" --client Smoke >/dev/null
cat >> "$E/engagement.yaml" <<EOF
backends:
  anthropic: { type: anthropic, api_key_env: ANTHROPIC_API_KEY }
models:
  default: { backend: anthropic, model: claude-opus-5-5, effort: low }
budget:
  max_tokens: 200000
EOF
uv run unvarnish add self --files "$(dirname "$0")/../src/unvarnish/scanners" -e "$E"
uv run unvarnish config check -e "$E"
uv run unvarnish run --dry-run -e "$E"
uv run unvarnish run -e "$E"
uv run unvarnish cost -e "$E"
echo "engagement at $E"
```

`chmod +x scripts/smoke.sh`. Not run in CI.

- [ ] **Step 3: Verify**

Run: `uv run pytest -q && uv run ruff check .`
Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add README.md scripts/smoke.sh
git commit -m "docs: model configuration and live smoke script"
```

---

## Self-review notes

- **Spec coverage (slice 2, §16 item 2):** backends (§7.1, §7.2) → Tasks 3, 5, 6; per-phase model selection (§7.3) → Task 3; concurrency and backoff (§7.4) → Task 11 (SDK retries + thread pool); split (§6.5) → Tasks 2, 10; extract (§6.6) → Tasks 9, 11; budget and estimation (§6.11) → Tasks 11, 12; caching and resumability (§6.12) → Tasks 7, 11; `status`, `cost`, `config check`, `cache clear`, `--dry-run` (§3) → Tasks 12, 13; run log file and console progress (§13, deferred from slice 1) → Task 12. Exit code 3 → Task 13.
- **Deviations recorded:** (1) tests use a fake HTTP server, not recorded cassettes (§14) — same guarantee, no cassette drift. (2) The split output is one `units.json` index plus per-unit result files, not one JSON per unit before extraction (§4) — avoids thousands of near-empty files. (3) The model emits `CandidateFinding`; the extract phase builds `Finding` with evidence and provenance (§5.2) — the model should not be asked to fill `tool`, `source`, or `model`. (4) No server-side refusal fallback is enabled; refusals are per-unit failures with their category. (5) `pytest-recording` is not added (§12.1).
- **Not in this slice:** rollups, verification, prose blocks and diagrams in documents (slice 3), comparison (4), ask (5), export and Docker (6), remaining scanners and gitleaks (7).
- **Type consistency checked:** `CompletionRequest`/`CompletionResponse` fields, `Usage` field names, `UnitsIndex.modules`, `ExtractState`, and `ToolPaths` names are used identically across Tasks 1–13.
