# Unvarnish Slice 1: Skeleton and Deterministic Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working `unvarnish` CLI that creates an engagement, ingests a tool from a repo or file pile, runs the model-free phases (inventory, git, scan with four scanners), and renders a scanner-only `findings.md`.

**Architecture:** A Typer CLI over an engagement directory on disk. Each pipeline phase is a class that reads inputs, writes a versioned JSON artifact, and declares an `inputs_hash` so the runner can skip fresh work. Scanners are small classes behind a protocol and a registry. Documents are rendered from JSON through Jinja2 templates. No model calls exist in this slice; the model layer arrives in Slice 2 and plugs into the same phase runner.

**Tech Stack:** Python 3.12+, uv + hatchling, Typer, Rich, Pydantic v2, PyYAML, pathspec, tree-sitter + tree-sitter-language-pack, Jinja2, pytest, ruff. Git via subprocess.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` (sections 3, 4, 5.1, 6.1–6.4, 6.9, 10, 12.1, 13, 14, 16 slice 1)

## Global Constraints

- Python `>=3.12`; package name `unvarnish`; console scripts `unvarnish` and `unv`.
- Pydantic v2 for every on-disk schema. Every JSON artifact is wrapped in an envelope with `schema_version`, `produced_by`, `produced_at`, `inputs_hash` (spec §4).
- Evidence paths are relative to the tool source root and POSIX-style. No absolute paths are ever written into an engagement (spec §4).
- Secrets never written to disk by Unvarnish: API keys come from env vars or keychain (spec §4, §10). Secret excerpts in findings are redacted and carry a fingerprint (spec §6.4).
- Scanner findings carry `source: scanner` and `verification: not_required`; no later phase alters or drops them (spec §6.4).
- One bad file never kills a run. Per-scanner exceptions are caught and recorded as skipped (spec §13).
- Exit codes: 0 success, 1 run completed with recorded failures, 2 configuration error, 3 budget cap (spec §3). Only 0, 1, 2 are reachable in this slice.
- Git is invoked through `subprocess`, never GitPython (spec §12.1).
- Category taxonomy: `security, data_handling, maintainability, reliability, operability, compliance, process, dependency`. Severities: `critical, high, medium, low, info` (spec §5.1).
- Default scanner thresholds: `oversized_files {file_lines: 1500, function_lines: 150, html_script_lines: 500}`, `bus_factor {single_author_share: 0.9}`, `generated_bulk {commit_lines: 2000}` (spec §10).
- Commit messages end with the attribution lines in the session's system reminder.

## Review Focus

1. **A tool directory with no files, or a repo with zero commits.** Inventory must write a census with zero files and git must record `available: false` with a reason; nothing may raise. Pinned in Task 9 (`test_inventory_empty_tool`) and Task 10 (`test_git_phase_no_repo`, `test_git_phase_empty_repo`).
2. **Non-UTF-8 or binary content behind a text extension.** Language detection and metrics must operate on bytes, sniff binaries by null byte, and never decode strictly. Pinned in Task 6 (`test_classify_binary_with_text_extension`, `test_detect_language_latin1_bytes`) Task 7 (`test_metrics_non_utf8_file`), and Task 9 (`test_inventory_binary_with_text_extension`).
3. **Symlinks pointing outside the tree, broken symlinks, and dangling links.** Ingest copies symlinks as symlinks and never follows them outside the tree; inventory skips symlinks and counts them. Pinned in Task 5 (`test_ingest_files_preserves_symlink`) and Task 9 (`test_inventory_skips_symlinks`).
4. **Large git history for the secrets history scan.** `git log -p` output must be streamed line by line, never buffered whole. Pinned in Task 5 (`test_git_lines_is_lazy`) and Task 12 (`test_history_scan_uses_streaming`, `test_scan_history_lines_tracks_commit_and_path`).
5. **Unicode and whitespace in file names.** Census paths and evidence paths must round-trip exactly and remain POSIX relative. Pinned in Task 6 (`test_excluder_unicode_path`) and Task 9 (`test_inventory_unicode_filename`).

---

## File Structure

```
pyproject.toml
README.md
.github/workflows/ci.yml
src/unvarnish/
  __init__.py                 # __version__ from package metadata
  cli.py                      # Typer app: init, add, run, status, scanners list
  artifacts.py                # Artifact envelope, write/read, hashing helpers
  config.py                   # EngagementConfig and nested config models; user-default merge
  engagement.py               # Engagement workspace: create/load/find, ToolPaths
  schemas/
    __init__.py
    finding.py                # Category, Severity, Source, Verification, Evidence, Finding
    inventory.py              # FileRecord, Census, FileMetrics, HtmlBreakdown, Metrics, Dependencies
    git.py                    # GitStats and sub-models
    tool.py                   # ToolMeta (tool.yaml)
    scan.py                   # ScannerFindings, SkippedScanner
    render.py                 # RenderState
  util/
    __init__.py
    gitcmd.py                 # git(), git_lines(), is_git_repo()
  analysis/
    __init__.py
    languages.py              # detect_language, classify, is_binary, Excluder
    treesitter.py             # parser cache, function spans, nesting, comments
    metrics.py                # compute_metrics(), HTML breakdown
    dependencies.py           # manifest parsers, framework hints
  phases/
    __init__.py               # DEFAULT_PHASES
    base.py                   # ToolContext, Phase protocol, PhaseResult, PhaseRunner, build_context
    ingest.py                 # ingest_tool(), load_tool_meta(), resolve_source_root()
    inventory.py              # InventoryPhase
    git.py                    # GitPhase
    scan.py                   # ScanPhase
    render.py                 # RenderPhase
  scanners/
    __init__.py               # builtin_scanners(), load_scanners()
    base.py                   # ScanContext, Scanner protocol
    secrets.py                # SecretsScanner
    oversized_files.py        # OversizedFilesScanner
    hygiene.py                # HygieneScanner
    bus_factor.py             # BusFactorScanner
  render/
    __init__.py
    markdown.py               # make_env(), render_document(), filters
    findings.py               # build_findings_context()
    templates/
      findings.md.j2
tests/
  conftest.py                 # synthetic_repo, huge_html, engagement fixtures
  test_cli_version.py
  test_artifacts.py
  test_finding_schema.py
  test_config.py
  test_engagement.py
  test_gitcmd.py
  test_ingest.py
  test_languages.py
  test_metrics.py
  test_phase_runner.py
  test_inventory_phase.py
  test_git_phase.py
  test_scan_phase.py
  test_scanner_secrets.py
  test_scanner_oversized.py
  test_scanner_hygiene.py
  test_scanner_bus_factor.py
  test_render.py
  test_cli_run.py
```

---

### Task 1: Project skeleton and `--version`

**Files:**
- Create: `pyproject.toml`, `src/unvarnish/__init__.py`, `src/unvarnish/cli.py`, `tests/test_cli_version.py`, `.gitignore`

**Interfaces:**
- Produces: `unvarnish.cli.app` (Typer application), `unvarnish.__version__: str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_version.py
from typer.testing import CliRunner

from unvarnish.cli import app

runner = CliRunner()


def test_version_flag_prints_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("unvarnish 0.")
```

- [ ] **Step 2: Create `pyproject.toml`**

```toml
[project]
name = "unvarnish"
version = "0.1.0"
description = "Unattended vetting of vibe-coded internal tools."
readme = "README.md"
requires-python = ">=3.12"
license = { text = "Proprietary" }
dependencies = [
  "typer>=0.12",
  "rich>=13.7",
  "pydantic>=2.7",
  "pyyaml>=6.0",
  "pathspec>=0.12",
  "tree-sitter>=0.23",
  "tree-sitter-language-pack>=0.4",
  "jinja2>=3.1",
]

[project.scripts]
unvarnish = "unvarnish.cli:app"
unv = "unvarnish.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/unvarnish"]

[dependency-groups]
dev = ["pytest>=8.2", "ruff>=0.6"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]
```

- [ ] **Step 3: Create package init and CLI**

```python
# src/unvarnish/__init__.py
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("unvarnish")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "0.0.0"
```

```python
# src/unvarnish/cli.py
from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(
    name="unvarnish",
    help="Unattended vetting of vibe-coded internal tools.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        from unvarnish import __version__

        console.print(f"unvarnish {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit.", callback=_version_callback, is_eager=True
    ),
) -> None:
    """Unvarnish: the unvarnished truth about internally built software."""
```

- [ ] **Step 4: Create `.gitignore`**

```
.venv/
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
dist/
build/
*.egg-info/
```

- [ ] **Step 5: Install and run the test**

Run: `uv sync && uv run pytest tests/test_cli_version.py -v`
Expected: PASS (`unvarnish 0.1.0`)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore src/unvarnish/__init__.py src/unvarnish/cli.py tests/test_cli_version.py uv.lock
git commit -m "feat: project skeleton with unvarnish CLI entry point"
```

---

### Task 2: Artifact envelope and hashing

**Files:**
- Create: `src/unvarnish/artifacts.py`, `tests/test_artifacts.py`

**Interfaces:**
- Produces:
  - `class ArtifactMeta(BaseModel)`: `schema_version: int`, `produced_by: str`, `produced_at: datetime`, `inputs_hash: str`
  - `class Artifact(BaseModel, Generic[T])`: `meta: ArtifactMeta`, `data: T`
  - `write_artifact(path: Path, data: BaseModel, *, produced_by: str, inputs_hash: str, schema_version: int = 1) -> None`
  - `read_artifact(path: Path, model: type[T]) -> Artifact[T]`
  - `hash_inputs(parts: Iterable[str]) -> str` (sha256 hex over strings)
  - `hash_files(paths: Iterable[Path]) -> str` (content hash, missing files hash as `<missing>`)
  - `hash_tree(root: Path) -> str` (stat-based hash of regular files, skips `.git`)
  - `walk_files(root: Path) -> tuple[list[tuple[Path, str]], int]` (sorted regular files as `(path, posix_relpath)` plus count of skipped symlinks; never follows symlinks)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_artifacts.py
import json
import os
from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import (
    hash_files,
    hash_inputs,
    hash_tree,
    read_artifact,
    write_artifact,
)


class Thing(BaseModel):
    name: str
    count: int


def test_write_and_read_round_trip(tmp_path: Path):
    target = tmp_path / "out" / "thing.json"
    write_artifact(target, Thing(name="a", count=2), produced_by="test", inputs_hash="abc")
    art = read_artifact(target, Thing)
    assert art.data == Thing(name="a", count=2)
    assert art.meta.produced_by == "test"
    assert art.meta.inputs_hash == "abc"
    assert art.meta.schema_version == 1
    assert not target.with_suffix(".json.tmp").exists()


def test_written_json_has_envelope(tmp_path: Path):
    target = tmp_path / "thing.json"
    write_artifact(target, Thing(name="a", count=1), produced_by="p", inputs_hash="h")
    raw = json.loads(target.read_text())
    assert set(raw) == {"meta", "data"}
    assert set(raw["meta"]) == {"schema_version", "produced_by", "produced_at", "inputs_hash"}


def test_hash_inputs_is_order_sensitive_and_stable():
    assert hash_inputs(["a", "b"]) == hash_inputs(["a", "b"])
    assert hash_inputs(["a", "b"]) != hash_inputs(["b", "a"])
    assert hash_inputs(["ab"]) != hash_inputs(["a", "b"])


def test_hash_files_changes_with_content_and_tolerates_missing(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text("one")
    h1 = hash_files([f])
    f.write_text("two")
    h2 = hash_files([f])
    assert h1 != h2
    assert hash_files([tmp_path / "missing"]) == hash_files([tmp_path / "missing"])


def test_hash_tree_ignores_git_and_tracks_mtime(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    src = tmp_path / "a.py"
    src.write_text("x = 1")
    h1 = hash_tree(tmp_path)
    (tmp_path / ".git" / "HEAD").write_text("other")
    assert hash_tree(tmp_path) == h1
    os.utime(src, ns=(1, 1))
    assert hash_tree(tmp_path) != h1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_artifacts.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.artifacts'`

- [ ] **Step 3: Implement `artifacts.py`**

```python
# src/unvarnish/artifacts.py
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class ArtifactMeta(BaseModel):
    schema_version: int
    produced_by: str
    produced_at: datetime
    inputs_hash: str


class Artifact(BaseModel, Generic[T]):
    meta: ArtifactMeta
    data: T


def write_artifact(
    path: Path,
    data: BaseModel,
    *,
    produced_by: str,
    inputs_hash: str,
    schema_version: int = 1,
) -> None:
    """Write `data` wrapped in the artifact envelope, atomically."""
    meta = ArtifactMeta(
        schema_version=schema_version,
        produced_by=produced_by,
        produced_at=datetime.now(UTC),
        inputs_hash=inputs_hash,
    )
    payload = {"meta": meta.model_dump(mode="json"), "data": data.model_dump(mode="json")}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    tmp.replace(path)


def read_artifact(path: Path, model: type[T]) -> Artifact[T]:
    raw = json.loads(path.read_text())
    return Artifact[model].model_validate(raw)  # type: ignore[valid-type]


def hash_inputs(parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def hash_files(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths, key=lambda x: str(x)):
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(p.read_bytes() if p.is_file() else b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


def walk_files(root: Path) -> tuple[list[tuple[Path, str]], int]:
    """Regular files under root as (path, posix relpath), sorted. Skips .git.

    Never follows symlinks; returns how many symlinks (files or dirs) were skipped.
    """
    files: list[tuple[Path, str]] = []
    symlinks = 0
    if not root.exists():
        return files, symlinks
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            if d == ".git":
                continue
            if (here / d).is_symlink():
                symlinks += 1
                continue
            kept.append(d)
        dirnames[:] = kept
        for fn in sorted(filenames):
            p = here / fn
            if p.is_symlink():
                symlinks += 1
                continue
            if p.is_file():
                files.append((p, p.relative_to(root).as_posix()))
    files.sort(key=lambda t: t[1])
    return files, symlinks


def hash_tree(root: Path) -> str:
    """Fast stat-based hash of a source tree: relative path, size, mtime. Skips .git."""
    h = hashlib.sha256()
    if not root.exists():
        return hash_inputs(["<missing-root>"])
    files, _ = walk_files(root)
    for p, rel in files:
        st = p.stat()
        h.update(f"{rel}|{st.st_size}|{st.st_mtime_ns}".encode())
        h.update(b"\0")
    return h.hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_artifacts.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/artifacts.py tests/test_artifacts.py
git commit -m "feat: artifact envelope with atomic writes and input hashing"
```

---

### Task 3: Finding schema

**Files:**
- Create: `src/unvarnish/schemas/__init__.py`, `src/unvarnish/schemas/finding.py`, `tests/test_finding_schema.py`

**Interfaces:**
- Produces (all in `unvarnish.schemas.finding`):
  - `class Category(StrEnum)`: `security, data_handling, maintainability, reliability, operability, compliance, process, dependency`
  - `class Severity(StrEnum)`: `critical, high, medium, low, info`; `SEVERITY_ORDER: dict[Severity, int]` (critical=0 … info=4)
  - `class Source(StrEnum)`: `scanner, model`
  - `class Verification(StrEnum)`: `confirmed, downgraded, rejected, not_required`
  - `class Evidence(BaseModel)`: `path: str`, `line_start: int | None`, `line_end: int | None`, `excerpt: str | None`, `fingerprint: str | None`, `note: str | None`
  - `class Finding(BaseModel)`: `id: str` (auto), `tool, category, severity, title, summary, impact, remediation`, `evidence: list[Evidence]` (min 1), `source: Source`, `scanner: str | None`, `model: str | None`, `verification: Verification | None`, `confidence: float | None`, `tags: list[str]`
  - `compute_finding_id(tool: str, category: Category, title: str, evidence: Evidence) -> str` (16 hex chars)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_finding_schema.py
import pytest
from pydantic import ValidationError

from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
    Category,
    Evidence,
    Finding,
    Severity,
    Source,
    Verification,
)


def _finding(**overrides) -> Finding:
    base = dict(
        tool="expense-bot",
        category=Category.security,
        severity=Severity.critical,
        title="AWS access key committed",
        summary="A key is in app.py.",
        impact="Anyone with repo access can use the key.",
        remediation="Rotate and move to a secret store.",
        evidence=[Evidence(path="app.py", line_start=2, line_end=2)],
        source=Source.scanner,
        scanner="secrets",
    )
    base.update(overrides)
    return Finding(**base)


def test_id_is_derived_and_stable():
    a = _finding()
    b = _finding(summary="different prose")
    assert a.id == b.id
    assert len(a.id) == 16


def test_id_changes_with_evidence_location():
    a = _finding()
    b = _finding(evidence=[Evidence(path="app.py", line_start=9)])
    assert a.id != b.id


def test_evidence_required():
    with pytest.raises(ValidationError):
        _finding(evidence=[])


def test_scanner_findings_default_to_not_required_verification():
    assert _finding().verification == Verification.not_required


def test_model_findings_keep_verification_none():
    f = _finding(source=Source.model, scanner=None, model="claude", confidence=0.8)
    assert f.verification is None


def test_evidence_path_must_be_relative_posix():
    with pytest.raises(ValidationError):
        Evidence(path="/abs/app.py")
    with pytest.raises(ValidationError):
        Evidence(path="dir\\app.py")


def test_severity_order():
    assert SEVERITY_ORDER[Severity.critical] < SEVERITY_ORDER[Severity.info]
    assert sorted(Severity, key=SEVERITY_ORDER.__getitem__)[0] == Severity.critical
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_finding_schema.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement the schema**

```python
# src/unvarnish/schemas/__init__.py
```
(empty file)

```python
# src/unvarnish/schemas/finding.py
from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator


class Category(StrEnum):
    security = "security"
    data_handling = "data_handling"
    maintainability = "maintainability"
    reliability = "reliability"
    operability = "operability"
    compliance = "compliance"
    process = "process"
    dependency = "dependency"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_ORDER: dict[Severity, int] = {s: i for i, s in enumerate(Severity)}


class Source(StrEnum):
    scanner = "scanner"
    model = "model"


class Verification(StrEnum):
    confirmed = "confirmed"
    downgraded = "downgraded"
    rejected = "rejected"
    not_required = "not_required"


class Evidence(BaseModel):
    path: str
    line_start: int | None = None
    line_end: int | None = None
    excerpt: str | None = None
    fingerprint: str | None = None
    note: str | None = None

    @field_validator("path")
    @classmethod
    def _relative_posix(cls, v: str) -> str:
        if v.startswith("/") or "\\" in v or v.startswith("../"):
            raise ValueError("evidence path must be a relative POSIX path inside the tool")
        return v


def compute_finding_id(tool: str, category: Category, title: str, evidence: Evidence) -> str:
    key = f"{tool}|{category}|{title}|{evidence.path}|{evidence.line_start}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    id: str = ""
    tool: str
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    evidence: list[Evidence] = Field(min_length=1)
    source: Source
    scanner: str | None = None
    model: str | None = None
    verification: Verification | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _finalise(self) -> Finding:
        if not self.id:
            self.id = compute_finding_id(self.tool, self.category, self.title, self.evidence[0])
        if self.source == Source.scanner and self.verification is None:
            self.verification = Verification.not_required
        return self
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_finding_schema.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/schemas tests/test_finding_schema.py
git commit -m "feat: Finding and Evidence schemas with stable ids"
```

---

### Task 4: Configuration and engagement workspace, `init` command

**Files:**
- Create: `src/unvarnish/config.py`, `src/unvarnish/engagement.py`, `tests/test_config.py`, `tests/test_engagement.py`
- Modify: `src/unvarnish/cli.py`

**Interfaces:**
- Produces (`unvarnish.config`):
  - `class EngagementConfig(BaseModel)` with fields `schema_version: int = 1`, `client: str | None`, `consultant: str | None`, `tools: list[str]`, `backends: dict[str, BackendConfig]`, `models: ModelsConfig`, `pipeline: PipelineConfig`, `budget: BudgetConfig`, `scanners: dict[str, dict[str, Any]]`, `report: ReportConfig`, `ask: AskConfig`
  - `DEFAULT_SCANNER_OPTIONS: dict[str, dict[str, Any]]`
  - `load_config(engagement_file: Path) -> EngagementConfig` (merges user defaults from `user_config_path()` underneath)
  - `user_config_path() -> Path` (`$UNVARNISH_CONFIG_DIR/config.yaml` or `~/.config/unvarnish/config.yaml`)
  - `deep_merge(base: dict, override: dict) -> dict`
- Produces (`unvarnish.engagement`):
  - `class ToolPaths`: `root, source, inventory, analysis, docs, meta_file, census, metrics, dependencies, git, scanner_findings, failures, findings_doc, render_state` (all `Path`)
  - `class Engagement`: `root: Path`, `config: EngagementConfig`; `create(root, client=None, consultant=None) -> Engagement`; `load(root) -> Engagement`; `find(start) -> Engagement`; `save_config() -> None`; `tool_paths(name) -> ToolPaths`; `tool_names() -> list[str]`; `register_tool(name) -> None`; properties `tools_dir, comparison_dir, exports_dir, cache_dir, logs_dir, config_file`
  - `class EngagementError(Exception)`, `class NotAnEngagement(EngagementError)`, `class EngagementExists(EngagementError)`
  - `TOOL_NAME_RE` = `^[a-z0-9][a-z0-9_-]{0,63}$`

- [ ] **Step 1: Write the failing config tests**

```python
# tests/test_config.py
from pathlib import Path

import yaml

from unvarnish.config import DEFAULT_SCANNER_OPTIONS, EngagementConfig, deep_merge, load_config


def test_defaults():
    cfg = EngagementConfig()
    assert cfg.schema_version == 1
    assert cfg.pipeline.unit_tokens == 8000
    assert cfg.pipeline.concurrency == 8
    assert cfg.report.tone == "direct"
    assert cfg.ask.max_tool_calls == 12
    assert cfg.scanners == DEFAULT_SCANNER_OPTIONS


def test_partial_scanner_override_keeps_other_defaults():
    cfg = EngagementConfig(scanners={"oversized_files": {"file_lines": 500}})
    assert cfg.scanners["oversized_files"]["file_lines"] == 500
    assert cfg.scanners["oversized_files"]["function_lines"] == 150
    assert cfg.scanners["bus_factor"]["single_author_share"] == 0.9


def test_deep_merge_nested():
    base = {"a": {"x": 1, "y": 2}, "b": 1}
    override = {"a": {"y": 3}, "c": 4}
    assert deep_merge(base, override) == {"a": {"x": 1, "y": 3}, "b": 1, "c": 4}


def test_load_config_merges_user_defaults(tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "userconf"
    user_dir.mkdir()
    (user_dir / "config.yaml").write_text(
        yaml.safe_dump({"consultant": "Bonham Technologies", "pipeline": {"concurrency": 2}})
    )
    monkeypatch.setenv("UNVARNISH_CONFIG_DIR", str(user_dir))
    eng_file = tmp_path / "engagement.yaml"
    eng_file.write_text(yaml.safe_dump({"client": "Acme", "pipeline": {"unit_tokens": 4000}}))
    cfg = load_config(eng_file)
    assert cfg.client == "Acme"
    assert cfg.consultant == "Bonham Technologies"
    assert cfg.pipeline.concurrency == 2
    assert cfg.pipeline.unit_tokens == 4000


def test_backend_config_shapes():
    cfg = EngagementConfig(
        backends={
            "onprem": {
                "type": "openai_compatible",
                "base_url": "http://llm.internal:8000/v1",
                "api_key_env": "ONPREM_KEY",
                "capabilities": {"tool_calling": False, "context_window": 32768},
            }
        }
    )
    b = cfg.backends["onprem"]
    assert b.type == "openai_compatible"
    assert b.capabilities.tool_calling is False
    assert b.capabilities.json_schema is True
```

- [ ] **Step 2: Write the failing engagement tests**

```python
# tests/test_engagement.py
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.engagement import (
    Engagement,
    EngagementExists,
    NotAnEngagement,
)

runner = CliRunner()


def test_create_makes_layout_and_config(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme", client="Acme")
    assert (eng.root / "engagement.yaml").exists()
    for d in ("tools", "comparison", "exports", "cache", "logs"):
        assert (eng.root / d).is_dir()
    assert eng.config.client == "Acme"


def test_create_refuses_existing_engagement(tmp_path: Path):
    Engagement.create(tmp_path / "acme")
    with pytest.raises(EngagementExists):
        Engagement.create(tmp_path / "acme")


def test_load_round_trip(tmp_path: Path):
    Engagement.create(tmp_path / "acme", client="Acme", consultant="BT")
    eng = Engagement.load(tmp_path / "acme")
    assert eng.config.client == "Acme"
    assert eng.config.consultant == "BT"


def test_load_non_engagement_raises(tmp_path: Path):
    with pytest.raises(NotAnEngagement):
        Engagement.load(tmp_path)


def test_find_walks_up(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    nested = eng.root / "tools" / "x" / "deep"
    nested.mkdir(parents=True)
    assert Engagement.find(nested).root == eng.root


def test_register_tool_validates_and_persists(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    eng.register_tool("expense-bot")
    eng.register_tool("expense-bot")  # idempotent
    assert Engagement.load(eng.root).tool_names() == ["expense-bot"]
    with pytest.raises(ValueError):
        eng.register_tool("Bad Name!")


def test_tool_paths_layout(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    p = eng.tool_paths("expense-bot")
    assert p.root == eng.root / "tools" / "expense-bot"
    assert p.census == p.root / "inventory" / "census.json"
    assert p.scanner_findings == p.root / "inventory" / "scanner-findings.json"
    assert p.findings_doc == p.root / "docs" / "findings.md"
    assert p.meta_file == p.root / "tool.yaml"


def test_cli_init(tmp_path: Path):
    result = runner.invoke(app, ["init", str(tmp_path / "acme"), "--client", "Acme"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme" / "engagement.yaml").exists()
    again = runner.invoke(app, ["init", str(tmp_path / "acme")])
    assert again.exit_code == 2
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py tests/test_engagement.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Implement `config.py`**

```python
# src/unvarnish/config.py
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

DEFAULT_SCANNER_OPTIONS: dict[str, dict[str, Any]] = {
    "oversized_files": {"file_lines": 1500, "function_lines": 150, "html_script_lines": 500},
    "bus_factor": {"single_author_share": 0.9},
    "generated_bulk": {"commit_lines": 2000},
}


class BackendCapabilities(BaseModel):
    json_schema: bool = True
    tool_calling: bool = True
    context_window: int = 200_000
    prompt_caching: bool = False


class BackendConfig(BaseModel):
    type: Literal["anthropic", "openai_compatible"]
    base_url: str | None = None
    api_key_env: str | None = None
    api_key_keychain: str | None = None
    capabilities: BackendCapabilities = Field(default_factory=BackendCapabilities)


class ModelRef(BaseModel):
    backend: str
    model: str


class ModelsConfig(BaseModel):
    default: ModelRef | None = None
    phases: dict[str, ModelRef] = Field(default_factory=dict)


class PipelineConfig(BaseModel):
    unit_tokens: int = 8000
    concurrency: int = 8


class Prices(BaseModel):
    input_per_mtok: float
    output_per_mtok: float


class BudgetConfig(BaseModel):
    max_tokens: int | None = None
    prices: Prices | None = None


class BrandingConfig(BaseModel):
    reference_docx: str | None = None
    html_css: str | None = None


class ReportConfig(BaseModel):
    tone: Literal["direct", "measured"] = "direct"
    templates_dir: str | None = None
    branding: BrandingConfig = Field(default_factory=BrandingConfig)


class AskConfig(BaseModel):
    max_tool_calls: int = 12


class EngagementConfig(BaseModel):
    schema_version: int = 1
    client: str | None = None
    consultant: str | None = None
    tools: list[str] = Field(default_factory=list)
    backends: dict[str, BackendConfig] = Field(default_factory=dict)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scanners: dict[str, dict[str, Any]] = Field(
        default_factory=lambda: copy.deepcopy(DEFAULT_SCANNER_OPTIONS)
    )
    report: ReportConfig = Field(default_factory=ReportConfig)
    ask: AskConfig = Field(default_factory=AskConfig)

    @field_validator("scanners", mode="before")
    @classmethod
    def _merge_scanner_defaults(cls, v: Any) -> dict[str, dict[str, Any]]:
        return deep_merge(copy.deepcopy(DEFAULT_SCANNER_OPTIONS), v or {})


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def user_config_path() -> Path:
    base = os.environ.get("UNVARNISH_CONFIG_DIR")
    root = Path(base) if base else Path.home() / ".config" / "unvarnish"
    return root / "config.yaml"


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping at top level")
    return data


def load_config(engagement_file: Path) -> EngagementConfig:
    merged = deep_merge(_load_yaml(user_config_path()), _load_yaml(engagement_file))
    return EngagementConfig.model_validate(merged)
```

- [ ] **Step 5: Implement `engagement.py`**

```python
# src/unvarnish/engagement.py
from __future__ import annotations

import re
from pathlib import Path

import yaml

from unvarnish.config import EngagementConfig, load_config

TOOL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
CONFIG_NAME = "engagement.yaml"


class EngagementError(Exception):
    pass


class NotAnEngagement(EngagementError):
    pass


class EngagementExists(EngagementError):
    pass


class ToolPaths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.inventory = root / "inventory"
        self.analysis = root / "analysis"
        self.docs = root / "docs"
        self.meta_file = root / "tool.yaml"
        self.census = self.inventory / "census.json"
        self.metrics = self.inventory / "metrics.json"
        self.dependencies = self.inventory / "dependencies.json"
        self.git = self.inventory / "git.json"
        self.scanner_findings = self.inventory / "scanner-findings.json"
        self.failures = self.analysis / "failures.json"
        self.findings_doc = self.docs / "findings.md"
        self.render_state = self.docs / "render-state.json"

    def ensure_dirs(self) -> None:
        for d in (self.root, self.inventory, self.analysis, self.docs):
            d.mkdir(parents=True, exist_ok=True)


class Engagement:
    def __init__(self, root: Path, config: EngagementConfig) -> None:
        self.root = root.resolve()
        self.config = config

    # --- construction -----------------------------------------------------
    @classmethod
    def create(
        cls, root: Path, client: str | None = None, consultant: str | None = None
    ) -> Engagement:
        root = root.resolve()
        if (root / CONFIG_NAME).exists():
            raise EngagementExists(f"{root} already contains {CONFIG_NAME}")
        root.mkdir(parents=True, exist_ok=True)
        eng = cls(root, EngagementConfig(client=client, consultant=consultant))
        for d in (eng.tools_dir, eng.comparison_dir, eng.exports_dir, eng.cache_dir, eng.logs_dir):
            d.mkdir(exist_ok=True)
        eng.save_config()
        return eng

    @classmethod
    def load(cls, root: Path) -> Engagement:
        root = root.resolve()
        cfg_file = root / CONFIG_NAME
        if not cfg_file.exists():
            raise NotAnEngagement(f"{root} has no {CONFIG_NAME}")
        return cls(root, load_config(cfg_file))

    @classmethod
    def find(cls, start: Path) -> Engagement:
        for candidate in [start.resolve(), *start.resolve().parents]:
            if (candidate / CONFIG_NAME).exists():
                return cls.load(candidate)
        raise NotAnEngagement(f"no {CONFIG_NAME} found at or above {start}")

    # --- paths ------------------------------------------------------------
    @property
    def config_file(self) -> Path:
        return self.root / CONFIG_NAME

    @property
    def tools_dir(self) -> Path:
        return self.root / "tools"

    @property
    def comparison_dir(self) -> Path:
        return self.root / "comparison"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    def tool_paths(self, name: str) -> ToolPaths:
        return ToolPaths(self.tools_dir / name)

    # --- tools ------------------------------------------------------------
    def tool_names(self) -> list[str]:
        return list(self.config.tools)

    def register_tool(self, name: str) -> None:
        if not TOOL_NAME_RE.match(name):
            raise ValueError(
                f"tool name {name!r} must match {TOOL_NAME_RE.pattern} (lowercase, digits, - and _)"
            )
        if name not in self.config.tools:
            self.config.tools.append(name)
            self.save_config()

    # --- persistence ------------------------------------------------------
    def save_config(self) -> None:
        data = self.config.model_dump(mode="json")
        self.config_file.write_text(yaml.safe_dump(data, sort_keys=False))
```

- [ ] **Step 6: Add `init` to the CLI**

Append to `src/unvarnish/cli.py`:

```python
from pathlib import Path

from unvarnish.engagement import Engagement, EngagementError


@app.command()
def init(
    directory: Path = typer.Argument(..., help="Directory to create the engagement in."),
    client: str | None = typer.Option(None, "--client", help="Client name."),
    consultant: str | None = typer.Option(None, "--consultant", help="Your firm's name."),
) -> None:
    """Create a new engagement workspace."""
    try:
        eng = Engagement.create(directory, client=client, consultant=consultant)
    except EngagementError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"Created engagement at [bold]{eng.root}[/bold]")
    console.print("Next: [cyan]unvarnish add <name> --repo <url|path>[/cyan] from inside it.")
```

Move the `from pathlib import Path` import to the top of the file with the other imports.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py tests/test_engagement.py -v`
Expected: PASS (13 tests)

- [ ] **Step 8: Commit**

```bash
git add src/unvarnish/config.py src/unvarnish/engagement.py src/unvarnish/cli.py tests/test_config.py tests/test_engagement.py
git commit -m "feat: engagement config, workspace layout, and init command"
```

---

### Task 5: Git wrapper, tool metadata, ingest, `add` command, and test fixtures

**Files:**
- Create: `src/unvarnish/util/__init__.py`, `src/unvarnish/util/gitcmd.py`, `src/unvarnish/schemas/tool.py`, `src/unvarnish/phases/__init__.py`, `src/unvarnish/phases/ingest.py`, `tests/conftest.py`, `tests/test_gitcmd.py`, `tests/test_ingest.py`
- Modify: `src/unvarnish/cli.py`

**Interfaces:**
- Consumes: `Engagement`, `ToolPaths` (Task 4).
- Produces (`unvarnish.util.gitcmd`):
  - `class GitError(RuntimeError)`
  - `git(args: Sequence[str], cwd: Path, check: bool = True) -> str` (stdout)
  - `git_lines(args: Sequence[str], cwd: Path) -> Iterator[str]` (streams stdout lines, raises `GitError` after exhaustion on non-zero exit)
  - `is_git_repo(path: Path) -> bool`
- Produces (`unvarnish.schemas.tool`): `class ToolMeta(BaseModel)`: `name: str`, `origin_kind: Literal["repo","files","link"]`, `origin: str`, `branch: str | None`, `commit: str | None`, `ingested_at: datetime`, `source_path: str | None`, `external: bool = False`
- Produces (`unvarnish.phases.ingest`):
  - `class IngestError(Exception)`
  - `ingest_tool(eng: Engagement, name: str, origin: str, kind: Literal["repo","files","link"], branch: str | None = None) -> ToolMeta`
  - `load_tool_meta(paths: ToolPaths) -> ToolMeta`
  - `resolve_source_root(eng: Engagement, meta: ToolMeta) -> Path`
- Produces (`tests/conftest.py` fixtures): `synthetic_repo: Path` (session), `huge_html: Path` (session), `engagement: Engagement`, `ingested: tuple[Engagement, str]` (synthetic repo ingested as `expense-bot`).

- [ ] **Step 1: Write `tests/conftest.py`**

```python
# tests/conftest.py
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Alice",
    "GIT_AUTHOR_EMAIL": "alice@example.com",
    "GIT_COMMITTER_NAME": "Alice",
    "GIT_COMMITTER_EMAIL": "alice@example.com",
}

LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"
LEAKED_DB_URL = "postgres://admin:hunter2@db.internal:5432/expenses"


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={**os.environ, **GIT_ENV, **(env or {})},
    )


def _commit(root: Path, message: str, author: str, email: str, date: str) -> None:
    env = {
        "GIT_AUTHOR_NAME": author,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": author,
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message, env=env)


HTML_SAMPLE = """<!doctype html>
<html>
<head>
<style>
body { margin: 0; }
.card { padding: 4px; }
</style>
</head>
<body>
<div id="app"></div>
<script>
function render(items) {
  for (const i of items) {
    if (i.ok) {
      console.log(i);
    }
  }
}
</script>
<script>
const total = (a, b) => a + b;
</script>
</body>
</html>
"""


@pytest.fixture(scope="session")
def synthetic_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A git repo with planted problems. See the plan's Task 5 for the expected numbers."""
    root = tmp_path_factory.mktemp("synthetic") / "expense-bot"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")

    # Commit 1 (Alice): leaked secrets in app.py
    (root / "app.py").write_text(
        "import boto3\n"
        f'AWS_ACCESS_KEY_ID = "{LEAKED_KEY}"\n'
        f'DB_URL = "{LEAKED_DB_URL}"\n'
        "\n"
        "def main():\n"
        '    print("hi")\n'
    )
    (root / "README.md").write_text("# Expense bot\n")
    (root / "requirements.txt").write_text("flask==2.3.2\nrequests>=2.31\n")
    (root / ".gitignore").write_text("*.pyc\n.env\n")
    _commit(root, "initial", "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")

    # Commit 2 (Alice, AI co-authored): secrets removed, 3000-line function generated
    big = "def process_everything(data):\n"
    big += "".join(f"    x{i} = data.get('k{i}', 0)\n" for i in range(3000))
    big += "    return 0\n"
    (root / "app.py").write_text(
        "import os\n"
        'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
        "\n"
        "def main():\n"
        '    print("hi")\n'
        "\n" + big
    )
    (root / "CLAUDE.md").write_text("# Instructions for Claude\n")
    _commit(
        root,
        "generate processing\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "Alice",
        "alice@example.com",
        "2026-01-06T10:00:00+00:00",
    )

    # Commit 3 (Alice): vendored node_modules, HTML with inline script/style, minified asset
    (root / "node_modules" / "leftpad").mkdir(parents=True)
    (root / "node_modules" / "leftpad" / "index.js").write_text("module.exports = s => s;\n")
    (root / "static").mkdir()
    (root / "static" / "index.html").write_text(HTML_SAMPLE)
    (root / "static" / "app.min.js").write_text("!function(){var a=1}();\n")
    _commit(root, "add frontend", "Alice", "alice@example.com", "2026-01-07T10:00:00+00:00")

    # Commit 4 (Bob): tiny change
    with (root / "README.md").open("a") as fh:
        fh.write("\nMaintained by finance.\n")
    _commit(root, "tweak readme", "Bob", "bob@example.com", "2026-02-01T10:00:00+00:00")
    return root


@pytest.fixture(scope="session")
def huge_html(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A ~70K-line HTML file: 50 script blocks of ~1,200 lines, 5 style blocks, markup."""
    root = tmp_path_factory.mktemp("huge")
    path = root / "dashboard.html"
    parts = ["<!doctype html>\n<html>\n<head>\n"]
    for s in range(5):
        parts.append("<style>\n" + "".join(f".c{s}-{i} {{ color: red; }}\n" for i in range(200)) + "</style>\n")
    parts.append("</head>\n<body>\n")
    for s in range(50):
        body = "".join(f"  var v{s}_{i} = {i};\n" for i in range(1200))
        parts.append(f"<script>\nfunction block{s}() {{\n{body}}}\n</script>\n")
    parts.append("".join(f"<div class='row'>row {i}</div>\n" for i in range(8000)))
    parts.append("</body>\n</html>\n")
    path.write_text("".join(parts))
    return path


@pytest.fixture
def engagement(tmp_path: Path) -> Engagement:
    return Engagement.create(tmp_path / "acme", client="Acme", consultant="Bonham Technologies")


@pytest.fixture
def ingested(engagement: Engagement, synthetic_repo: Path) -> tuple[Engagement, str]:
    ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    return engagement, "expense-bot"
```

- [ ] **Step 2: Write the failing gitcmd tests**

```python
# tests/test_gitcmd.py
import inspect
import re
from pathlib import Path

import pytest

from unvarnish.util.gitcmd import GitError, git, git_lines, is_git_repo


def test_git_returns_stdout(synthetic_repo: Path):
    out = git(["rev-list", "--count", "HEAD"], cwd=synthetic_repo)
    assert out.strip() == "4"


def test_git_raises_on_failure(tmp_path: Path):
    with pytest.raises(GitError):
        git(["rev-parse", "HEAD"], cwd=tmp_path)


def test_git_lines_is_lazy(synthetic_repo: Path):
    it = git_lines(["log", "--format=%H"], cwd=synthetic_repo)
    assert inspect.isgenerator(it)
    first = next(it)
    assert re.fullmatch(r"[0-9a-f]{40}", first)
    assert len(list(it)) == 3


def test_git_lines_raises_after_exhaustion_on_error(tmp_path: Path):
    with pytest.raises(GitError):
        list(git_lines(["log"], cwd=tmp_path))


def test_is_git_repo(synthetic_repo: Path, tmp_path: Path):
    assert is_git_repo(synthetic_repo)
    assert not is_git_repo(tmp_path)
```

- [ ] **Step 3: Write the failing ingest tests**

```python
# tests/test_ingest.py
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import (
    IngestError,
    ingest_tool,
    load_tool_meta,
    resolve_source_root,
)

runner = CliRunner()


def test_ingest_local_repo_copies_history(engagement: Engagement, synthetic_repo: Path):
    meta = ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    paths = engagement.tool_paths("expense-bot")
    assert (paths.source / ".git").is_dir()
    assert (paths.source / "app.py").exists()
    assert meta.origin_kind == "repo"
    assert meta.commit and len(meta.commit) == 40
    assert meta.branch == "main"
    assert engagement.tool_names() == ["expense-bot"]
    assert load_tool_meta(paths) == meta


def test_ingest_repo_requires_git_dir(engagement: Engagement, tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.py").write_text("x = 1\n")
    with pytest.raises(IngestError, match="--files"):
        ingest_tool(engagement, "plain", str(plain), "repo")


def test_ingest_files_copies_tree(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "sub").mkdir(parents=True)
    (pile / "sub" / "b.js").write_text("let x = 1;\n")
    meta = ingest_tool(engagement, "pile", str(pile), "files")
    paths = engagement.tool_paths("pile")
    assert (paths.source / "sub" / "b.js").read_text() == "let x = 1;\n"
    assert meta.commit is None
    assert resolve_source_root(engagement, meta) == paths.source


def test_ingest_files_preserves_symlink(engagement: Engagement, tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret outside\n")
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "real.txt").write_text("inside\n")
    os.symlink("../outside.txt", pile / "link.txt")
    os.symlink("nowhere", pile / "broken.txt")
    ingest_tool(engagement, "pile", str(pile), "files")
    src = engagement.tool_paths("pile").source
    assert (src / "link.txt").is_symlink()
    assert os.readlink(src / "link.txt") == "../outside.txt"
    assert os.path.lexists(src / "broken.txt")
    assert (src / "real.txt").read_text() == "inside\n"


def test_ingest_link_records_path_without_copy(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.go").write_text("package main\n")
    meta = ingest_tool(engagement, "linked", str(pile), "link")
    paths = engagement.tool_paths("linked")
    assert not paths.source.exists()
    assert meta.external is True
    assert resolve_source_root(engagement, meta) == pile.resolve()


def test_ingest_link_inside_engagement_is_relative(engagement: Engagement):
    inside = engagement.root / "dropzone" / "thing"
    inside.mkdir(parents=True)
    (inside / "a.rs").write_text("fn main() {}\n")
    meta = ingest_tool(engagement, "thing", str(inside), "link")
    assert meta.external is False
    assert meta.source_path == "dropzone/thing"
    assert resolve_source_root(engagement, meta) == inside


def test_ingest_refuses_duplicate(engagement: Engagement, synthetic_repo: Path):
    ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")
    with pytest.raises(IngestError, match="already exists"):
        ingest_tool(engagement, "expense-bot", str(synthetic_repo), "repo")


def test_cli_add(engagement: Engagement, synthetic_repo: Path):
    result = runner.invoke(
        app, ["add", "expense-bot", "--repo", str(synthetic_repo), "-e", str(engagement.root)]
    )
    assert result.exit_code == 0, result.output
    assert (engagement.tool_paths("expense-bot").source / "app.py").exists()


def test_cli_add_requires_exactly_one_origin(engagement: Engagement, tmp_path: Path):
    result = runner.invoke(app, ["add", "x", "-e", str(engagement.root)])
    assert result.exit_code == 2
    both = runner.invoke(
        app, ["add", "x", "--repo", "a", "--files", str(tmp_path), "-e", str(engagement.root)]
    )
    assert both.exit_code == 2
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/test_gitcmd.py tests/test_ingest.py -v`
Expected: FAIL with `ModuleNotFoundError` (conftest import fails)

- [ ] **Step 5: Implement `util/gitcmd.py`**

```python
# src/unvarnish/util/__init__.py
```
(empty file)

```python
# src/unvarnish/util/gitcmd.py
from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path


class GitError(RuntimeError):
    pass


def git(args: Sequence[str], cwd: Path, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True, errors="replace"
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def git_lines(args: Sequence[str], cwd: Path) -> Iterator[str]:
    """Stream stdout lines from a git command without buffering the whole output."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as err:
        proc = subprocess.Popen(
            ["git", *args],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=err,
            text=True,
            errors="replace",
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line.rstrip("\n")
        finally:
            proc.stdout.close()
            rc = proc.wait()
        if rc != 0:
            err.seek(0)
            raise GitError(f"git {' '.join(args)} failed ({rc}): {err.read().strip()}")


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()
```

- [ ] **Step 6: Implement `schemas/tool.py`**

```python
# src/unvarnish/schemas/tool.py
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

OriginKind = Literal["repo", "files", "link"]


class ToolMeta(BaseModel):
    name: str
    origin_kind: OriginKind
    origin: str
    branch: str | None = None
    commit: str | None = None
    ingested_at: datetime
    source_path: str | None = None
    external: bool = False
```

- [ ] **Step 7: Implement `phases/ingest.py`**

```python
# src/unvarnish/phases/__init__.py
```
(empty for now; populated in Task 16)

```python
# src/unvarnish/phases/ingest.py
from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import yaml

from unvarnish.engagement import Engagement, ToolPaths
from unvarnish.schemas.tool import OriginKind, ToolMeta
from unvarnish.util.gitcmd import GitError, git, is_git_repo


class IngestError(Exception):
    pass


def _is_url(origin: str) -> bool:
    return "://" in origin or origin.startswith("git@")


def ingest_tool(
    eng: Engagement,
    name: str,
    origin: str,
    kind: OriginKind,
    branch: str | None = None,
) -> ToolMeta:
    paths = eng.tool_paths(name)
    if paths.root.exists() and any(paths.root.iterdir()):
        raise IngestError(f"tool {name!r} already exists at {paths.root}")
    paths.ensure_dirs()

    meta = ToolMeta(name=name, origin_kind=kind, origin=origin, ingested_at=datetime.now(UTC))

    if kind == "repo":
        if _is_url(origin):
            args = ["clone", "--quiet"]
            if branch:
                args += ["--branch", branch]
            try:
                git([*args, origin, str(paths.source)], cwd=paths.root)
            except GitError as exc:
                raise IngestError(f"clone failed: {exc}") from exc
        else:
            src = Path(origin)
            if not is_git_repo(src):
                raise IngestError(
                    f"{origin} has no .git directory; use --files for a loose file pile"
                )
            shutil.copytree(src, paths.source, symlinks=True)
            if branch:
                try:
                    git(["checkout", "--quiet", branch], cwd=paths.source)
                except GitError as exc:
                    raise IngestError(str(exc)) from exc
        meta.commit = git(["rev-parse", "HEAD"], cwd=paths.source).strip()
        meta.branch = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=paths.source).strip()

    elif kind == "files":
        src = Path(origin)
        if not src.is_dir():
            raise IngestError(f"{origin} is not a directory")
        shutil.copytree(src, paths.source, symlinks=True)

    elif kind == "link":
        target = Path(origin).resolve()
        if not target.is_dir():
            raise IngestError(f"{origin} is not a directory")
        rel = os.path.relpath(target, eng.root)
        if rel.startswith(".."):
            meta.source_path = str(target)
            meta.external = True
        else:
            meta.source_path = Path(rel).as_posix()
            meta.external = False

    paths.meta_file.write_text(yaml.safe_dump(meta.model_dump(mode="json"), sort_keys=False))
    eng.register_tool(name)
    return meta


def load_tool_meta(paths: ToolPaths) -> ToolMeta:
    if not paths.meta_file.exists():
        raise IngestError(f"{paths.meta_file} missing; was the tool added?")
    return ToolMeta.model_validate(yaml.safe_load(paths.meta_file.read_text()))


def resolve_source_root(eng: Engagement, meta: ToolMeta) -> Path:
    if meta.origin_kind == "link":
        assert meta.source_path is not None
        return Path(meta.source_path) if meta.external else eng.root / meta.source_path
    return eng.tool_paths(meta.name).source
```

- [ ] **Step 8: Add `add` to the CLI**

Append to `src/unvarnish/cli.py`:

```python
from unvarnish.engagement import NotAnEngagement
from unvarnish.phases.ingest import IngestError, ingest_tool


def _load_engagement(engagement: Path | None) -> Engagement:
    try:
        return Engagement.find(engagement or Path.cwd())
    except NotAnEngagement as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


EngagementOption = typer.Option(
    None, "--engagement", "-e", help="Engagement directory (default: search upward from cwd)."
)


@app.command()
def add(
    name: str = typer.Argument(..., help="Tool name: lowercase, digits, - and _."),
    repo: str | None = typer.Option(None, "--repo", help="Git URL or local repo path."),
    files: Path | None = typer.Option(None, "--files", help="Directory of loose files."),
    branch: str | None = typer.Option(None, "--branch", help="Branch to check out."),
    link: bool = typer.Option(False, "--link", help="Record the path instead of copying."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Register a tool and ingest its source."""
    if (repo is None) == (files is None):
        err_console.print("[red]error:[/red] pass exactly one of --repo or --files")
        raise typer.Exit(code=2)
    eng = _load_engagement(engagement)
    origin = repo if repo is not None else str(files)
    kind = "link" if link else ("repo" if repo is not None else "files")
    try:
        meta = ingest_tool(eng, name, origin, kind, branch=branch)
    except (IngestError, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    where = meta.source_path if kind == "link" else f"tools/{name}/source"
    console.print(f"Added [bold]{name}[/bold] ({kind}) at {where}")
    if meta.commit:
        console.print(f"  commit {meta.commit[:12]} on {meta.branch}")
```

Consolidate imports at the top of `cli.py` (Path, Engagement, EngagementError, NotAnEngagement, IngestError, ingest_tool).

- [ ] **Step 9: Run tests to verify they pass**

Run: `uv run pytest tests/test_gitcmd.py tests/test_ingest.py -v`
Expected: PASS (14 tests)

- [ ] **Step 10: Commit**

```bash
git add src/unvarnish/util src/unvarnish/schemas/tool.py src/unvarnish/phases src/unvarnish/cli.py tests/conftest.py tests/test_gitcmd.py tests/test_ingest.py
git commit -m "feat: git wrapper, tool ingest (repo/files/link), add command, synthetic fixtures"
```

---

### Task 6: Language detection, classification, and exclusions

**Files:**
- Create: `src/unvarnish/analysis/__init__.py`, `src/unvarnish/analysis/languages.py`, `tests/test_languages.py`

**Interfaces:**
- Produces (`unvarnish.analysis.languages`):
  - `class Classification(StrEnum)`: `source, config, test, docs, generated, vendored, data, binary`
  - `is_binary(sample: bytes) -> bool`
  - `detect_language(relpath: PurePosixPath, sample: bytes) -> str | None` (tree-sitter-language-pack names: `python, javascript, typescript, tsx, go, rust, java, ...`)
  - `classify(relpath: PurePosixPath, language: str | None, sample: bytes) -> Classification`
  - `class Excluder`: `__init__(source_root: Path)`; `reason(relpath: PurePosixPath) -> str | None` (one of `gitignore`, `vendored:<dir>`, `build_output:<dir>`, `lockfile`, or `None`)
  - Constants: `VENDORED_DIRS`, `BUILD_DIRS`, `LOCKFILES`, `EXTENSION_MAP`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_languages.py
from pathlib import Path, PurePosixPath

from unvarnish.analysis.languages import (
    Classification,
    Excluder,
    classify,
    detect_language,
    is_binary,
)

P = PurePosixPath


def test_detect_by_extension():
    assert detect_language(P("src/app.py"), b"x = 1") == "python"
    assert detect_language(P("a/b.ts"), b"") == "typescript"
    assert detect_language(P("a/b.tsx"), b"") == "tsx"
    assert detect_language(P("main.go"), b"") == "go"
    assert detect_language(P("lib.rs"), b"") == "rust"
    assert detect_language(P("App.java"), b"") == "java"
    assert detect_language(P("index.html"), b"") == "html"
    assert detect_language(P("Dockerfile"), b"") == "dockerfile"
    assert detect_language(P("Makefile"), b"") == "make"


def test_detect_by_shebang():
    assert detect_language(P("bin/tool"), b"#!/usr/bin/env python3\nprint(1)\n") == "python"
    assert detect_language(P("bin/run"), b"#!/bin/bash\necho hi\n") == "bash"
    assert detect_language(P("bin/mystery"), b"plain text") is None


def test_detect_language_latin1_bytes():
    sample = "# caf\xe9\nx = 1\n".encode("latin-1")
    assert detect_language(P("caf.py"), sample) == "python"
    assert classify(P("caf.py"), "python", sample) == Classification.source


def test_is_binary_and_classify_binary_with_text_extension():
    sample = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert is_binary(sample)
    assert classify(P("img.txt"), None, sample) == Classification.binary
    assert not is_binary(b"hello\nworld\n")


def test_classify_rules():
    assert classify(P("tests/test_app.py"), "python", b"") == Classification.test
    assert classify(P("src/app.test.ts"), "typescript", b"") == Classification.test
    assert classify(P("src/AppTest.java"), "java", b"") == Classification.test
    assert classify(P("node_modules/x/index.js"), "javascript", b"") == Classification.vendored
    assert classify(P("static/app.min.js"), "javascript", b"") == Classification.generated
    assert classify(P("gen/x.py"), "python", b"# @generated by tool\n") == Classification.generated
    assert classify(P("README.md"), "markdown", b"") == Classification.docs
    assert classify(P("docs/guide.txt"), None, b"") == Classification.docs
    assert classify(P("config.yaml"), "yaml", b"") == Classification.config
    assert classify(P(".env"), None, b"A=1") == Classification.config
    assert classify(P("package.json"), "json", b"{}") == Classification.config
    assert classify(P("requirements.txt"), "text", b"flask") == Classification.config
    assert classify(P("data/rows.csv"), None, b"a,b") == Classification.data
    assert classify(P("app.py"), "python", b"") == Classification.source
    assert classify(P("notes.unknownext"), None, b"text") == Classification.data


def test_excluder_gitignore_and_vendored(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.log\nbuild/\n")
    ex = Excluder(tmp_path)
    assert ex.reason(P("app.log")) == "gitignore"
    assert ex.reason(P("build/out.js")) == "gitignore"
    assert ex.reason(P("node_modules/a/b.js")) == "vendored:node_modules"
    assert ex.reason(P("dist/bundle.js")) == "build_output:dist"
    assert ex.reason(P("package-lock.json")) == "lockfile"
    assert ex.reason(P("src/app.py")) is None


def test_excluder_without_gitignore(tmp_path: Path):
    ex = Excluder(tmp_path)
    assert ex.reason(P("anything.py")) is None


def test_excluder_unicode_path(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("tmp/\n")
    ex = Excluder(tmp_path)
    assert ex.reason(P("données/résumé final.py")) is None
    assert ex.reason(P("tmp/données.py")) == "gitignore"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_languages.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `analysis/languages.py`**

```python
# src/unvarnish/analysis/__init__.py
```
(empty file)

```python
# src/unvarnish/analysis/languages.py
from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path, PurePosixPath

import pathspec


class Classification(StrEnum):
    source = "source"
    config = "config"
    test = "test"
    docs = "docs"
    generated = "generated"
    vendored = "vendored"
    data = "data"
    binary = "binary"


EXTENSION_MAP: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".rb": "ruby", ".php": "php", ".cs": "c_sharp", ".swift": "swift", ".scala": "scala",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".m": "objc",
    ".lua": "lua", ".r": "r", ".R": "r", ".dart": "dart", ".ex": "elixir", ".exs": "elixir",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".css": "css", ".scss": "scss", ".less": "css",
    ".sql": "sql", ".sh": "bash", ".bash": "bash", ".zsh": "bash", ".ps1": "powershell",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml", ".xml": "xml",
    ".ini": "ini", ".cfg": "ini", ".env": "dotenv",
    ".md": "markdown", ".rst": "rst", ".txt": "text",
    ".tf": "hcl", ".hcl": "hcl", ".proto": "proto", ".graphql": "graphql",
}

FILENAME_MAP: dict[str, str] = {
    "Dockerfile": "dockerfile", "Makefile": "make", "Jenkinsfile": "groovy",
    "Gemfile": "ruby", "Rakefile": "ruby", ".env": "dotenv",
}

SHEBANG_MAP: dict[str, str] = {
    "python": "python", "python3": "python", "node": "javascript", "bash": "bash",
    "sh": "bash", "zsh": "bash", "ruby": "ruby", "perl": "perl",
}

CONFIG_LANGS = {"yaml", "json", "toml", "xml", "ini", "dotenv", "hcl"}
DOC_LANGS = {"markdown", "rst", "text"}
DATA_EXTS = {".csv", ".tsv", ".parquet", ".sqlite", ".db", ".xlsx", ".xls", ".pkl",
             ".npy", ".jsonl", ".avro", ".feather"}
MANIFEST_NAMES = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "Pipfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "Gemfile", "tsconfig.json", ".editorconfig", ".prettierrc",
}

VENDORED_DIRS = {"node_modules", "vendor", "venv", ".venv", "site-packages",
                 "bower_components", "third_party", "Pods", ".tox"}
BUILD_DIRS = {"dist", "build", "target", "out", ".next", "__pycache__", ".pytest_cache",
              ".mypy_cache", ".ruff_cache", "bin", "obj", ".gradle", "coverage"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
             "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", "Pipfile.lock",
             "bun.lockb", "flake.lock"}

TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing"}
TEST_FILE_RE = re.compile(
    r"(^test_.*\.py$)|(_test\.(py|go|rs|rb|ts|js)$)|(\.(test|spec)\.(ts|tsx|js|jsx|mjs)$)"
    r"|(Tests?\.(java|kt|cs|swift|scala)$)|(_spec\.rb$)|(^conftest\.py$)"
)
GENERATED_MARKERS = (b"@generated", b"DO NOT EDIT", b"Code generated by", b"auto-generated",
                     b"Autogenerated", b"automatically generated")
GENERATED_NAME_RE = re.compile(r"(\.min\.(js|css)$)|(\.pb\.go$)|(_pb2(_grpc)?\.py$)|(\.g\.dart$)")


def is_binary(sample: bytes) -> bool:
    return b"\0" in sample[:8000]


def detect_language(relpath: PurePosixPath, sample: bytes) -> str | None:
    name = relpath.name
    if name in FILENAME_MAP:
        return FILENAME_MAP[name]
    lang = EXTENSION_MAP.get(relpath.suffix)
    if lang:
        return lang
    if sample.startswith(b"#!"):
        first = sample.split(b"\n", 1)[0].decode("utf-8", errors="replace")
        token = first.split()[-1].rsplit("/", 1)[-1] if first.split() else ""
        return SHEBANG_MAP.get(token)
    return None


def classify(relpath: PurePosixPath, language: str | None, sample: bytes) -> Classification:
    parts = relpath.parts
    name = relpath.name
    if is_binary(sample):
        return Classification.binary
    if any(p in VENDORED_DIRS for p in parts[:-1]):
        return Classification.vendored
    if GENERATED_NAME_RE.search(name) or any(m in sample[:1024] for m in GENERATED_MARKERS):
        return Classification.generated
    if any(p in TEST_DIRS for p in parts[:-1]) or TEST_FILE_RE.search(name):
        return Classification.test
    if name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith(".txt")):
        return Classification.config
    if language in DOC_LANGS or "docs" in parts[:-1] or "doc" in parts[:-1]:
        return Classification.docs
    if language in CONFIG_LANGS or name.startswith("."):
        return Classification.config
    if relpath.suffix.lower() in DATA_EXTS:
        return Classification.data
    if language is not None:
        return Classification.source
    return Classification.data


class Excluder:
    """Decides whether a file is excluded from analysis, and why."""

    def __init__(self, source_root: Path) -> None:
        gitignore = source_root / ".gitignore"
        lines = gitignore.read_text(errors="replace").splitlines() if gitignore.exists() else []
        self._spec = pathspec.PathSpec.from_lines("gitwildmatch", lines)

    def reason(self, relpath: PurePosixPath) -> str | None:
        rel = relpath.as_posix()
        if self._spec.match_file(rel):
            return "gitignore"
        for part in relpath.parts[:-1]:
            if part in VENDORED_DIRS:
                return f"vendored:{part}"
        for part in relpath.parts[:-1]:
            if part in BUILD_DIRS:
                return f"build_output:{part}"
        if relpath.name in LOCKFILES:
            return "lockfile"
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_languages.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/analysis tests/test_languages.py
git commit -m "feat: language detection, file classification, and exclusion rules"
```

---

### Task 7: Tree-sitter metrics and HTML breakdown

**Files:**
- Create: `src/unvarnish/analysis/treesitter.py`, `src/unvarnish/analysis/metrics.py`, `src/unvarnish/schemas/inventory.py` (metrics models only; census models added in Task 9), `tests/test_metrics.py`

**Interfaces:**
- Produces (`unvarnish.schemas.inventory`):
  - `class HtmlBreakdown(BaseModel)`: `markup_lines, script_lines, style_lines, markup_bytes, script_bytes, style_bytes, script_blocks, style_blocks` (all `int`)
  - `class FileMetrics(BaseModel)`: `path: str`, `lines: int`, `bytes: int`, `functions: int | None`, `max_function_lines: int | None`, `max_function_name: str | None`, `max_nesting: int | None`, `comment_lines: int | None`, `html: HtmlBreakdown | None`, `metrics_method: Literal["treesitter","lines"]`
- Produces (`unvarnish.analysis.treesitter`):
  - `get_parser(language: str) -> Parser | None` (cached; `None` when the pack lacks the grammar)
  - `function_spans(tree, language: str, source: bytes) -> list[tuple[str, int, int]]` (name, start line, end line; 1-based)
  - `max_nesting(tree) -> int`
  - `comment_lines(tree) -> int`
  - `FUNCTION_NODE_TYPES: dict[str, set[str]]`, `MAX_PARSE_BYTES = 5_000_000`
- Produces (`unvarnish.analysis.metrics`):
  - `compute_metrics(path: Path, relpath: str, language: str | None) -> FileMetrics`
  - `count_lines(data: bytes) -> int`
  - `html_breakdown(data: bytes) -> tuple[HtmlBreakdown, bytes]` (breakdown and the concatenated script source)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_metrics.py
from pathlib import Path

from unvarnish.analysis.metrics import compute_metrics, count_lines, html_breakdown
from unvarnish.analysis.treesitter import get_parser

PY = b'''"""Module doc."""
import os

def small(a, b):
    # add
    return a + b


class Thing:
    def method(self, items):
        for i in items:
            if i:
                while True:
                    break
        return 1
'''

JS = b"""function outer() {
  const inner = () => {
    if (true) { return 1; }
  };
  return inner();
}
"""


def test_count_lines():
    assert count_lines(b"") == 0
    assert count_lines(b"a\n") == 1
    assert count_lines(b"a\nb") == 2
    assert count_lines(b"a\nb\n") == 2


def test_python_metrics(tmp_path: Path):
    f = tmp_path / "m.py"
    f.write_bytes(PY)
    m = compute_metrics(f, "m.py", "python")
    assert m.metrics_method == "treesitter"
    assert m.functions == 2
    assert m.max_function_name == "method"
    assert m.max_function_lines == 6
    assert m.max_nesting >= 3
    assert m.comment_lines >= 1
    assert m.lines == 15


def test_javascript_metrics(tmp_path: Path):
    f = tmp_path / "m.js"
    f.write_bytes(JS)
    m = compute_metrics(f, "m.js", "javascript")
    assert m.functions == 2
    assert m.max_function_name == "outer"
    assert m.max_function_lines == 6


def test_unknown_language_falls_back_to_lines(tmp_path: Path):
    f = tmp_path / "x.weird"
    f.write_bytes(b"one\ntwo\nthree\n")
    m = compute_metrics(f, "x.weird", None)
    assert m.metrics_method == "lines"
    assert m.lines == 3
    assert m.functions is None


def test_metrics_non_utf8_file(tmp_path: Path):
    f = tmp_path / "latin.py"
    f.write_bytes("# caf\xe9\ndef f():\n    return 1\n".encode("latin-1"))
    m = compute_metrics(f, "latin.py", "python")
    assert m.lines == 3
    assert m.functions == 1


def test_html_breakdown_counts_streams():
    from tests.conftest import HTML_SAMPLE

    bd, scripts = html_breakdown(HTML_SAMPLE.encode())
    assert bd.script_blocks == 2
    assert bd.style_blocks == 1
    assert bd.script_lines == 8
    assert bd.style_lines == 2
    assert bd.markup_lines + bd.script_lines + bd.style_lines <= count_lines(HTML_SAMPLE.encode())
    assert b"function render" in scripts


def test_html_metrics_parse_inline_scripts(tmp_path: Path):
    from tests.conftest import HTML_SAMPLE

    f = tmp_path / "index.html"
    f.write_text(HTML_SAMPLE)
    m = compute_metrics(f, "index.html", "html")
    assert m.html is not None
    assert m.functions == 2
    assert m.max_function_name == "render"


def test_huge_html_completes(huge_html: Path):
    m = compute_metrics(huge_html, "dashboard.html", "html")
    assert m.lines > 65_000
    assert m.html is not None
    assert m.html.script_blocks == 50
    assert m.html.script_lines > 60_000
    assert m.functions == 50
    assert m.max_function_lines > 1000


def test_get_parser_unknown_returns_none():
    assert get_parser("not-a-language") is None
    assert get_parser("python") is not None
```

Also add an empty `tests/__init__.py` so `from tests.conftest import HTML_SAMPLE` works.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_metrics.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement metrics schemas**

```python
# src/unvarnish/schemas/inventory.py
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class HtmlBreakdown(BaseModel):
    markup_lines: int
    script_lines: int
    style_lines: int
    markup_bytes: int
    script_bytes: int
    style_bytes: int
    script_blocks: int
    style_blocks: int


class FileMetrics(BaseModel):
    path: str
    lines: int
    bytes: int
    functions: int | None = None
    max_function_lines: int | None = None
    max_function_name: str | None = None
    max_nesting: int | None = None
    comment_lines: int | None = None
    html: HtmlBreakdown | None = None
    metrics_method: Literal["treesitter", "lines"]
```

- [ ] **Step 4: Implement `analysis/treesitter.py`**

```python
# src/unvarnish/analysis/treesitter.py
from __future__ import annotations

from functools import lru_cache
from typing import Any

MAX_PARSE_BYTES = 5_000_000

# Our language ids -> tree-sitter-language-pack names where they differ.
PACK_NAMES = {"c_sharp": "csharp"}

FUNCTION_NODE_TYPES: dict[str, set[str]] = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function",
                   "function_expression", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition", "arrow_function",
                   "function_expression", "generator_function_declaration"},
    "tsx": {"function_declaration", "method_definition", "arrow_function",
            "function_expression", "generator_function_declaration"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "rust": {"function_item", "closure_expression"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
    "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
    "kotlin": {"function_declaration"},
    "ruby": {"method", "singleton_method"},
    "php": {"function_definition", "method_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "swift": {"function_declaration"},
    "scala": {"function_definition"},
    "lua": {"function_declaration", "function_definition"},
    "bash": {"function_definition"},
}

NESTING_NODE_TYPES = {
    "block", "statement_block", "compound_statement", "class_body", "function_body",
    "if_statement", "for_statement", "for_in_statement", "for_of_statement", "while_statement",
    "do_statement", "try_statement", "switch_statement", "match_statement", "with_statement",
    "elif_clause", "else_clause", "except_clause", "case_clause",
}
COMMENT_NODE_TYPES = {"comment", "line_comment", "block_comment", "doc_comment"}


@lru_cache(maxsize=None)
def get_parser(language: str) -> Any | None:
    try:
        from tree_sitter_language_pack import get_parser as pack_get_parser

        return pack_get_parser(PACK_NAMES.get(language, language))  # type: ignore[arg-type]
    except Exception:
        return None


def _walk(root: Any):
    """Iterative pre-order traversal yielding (node, depth)."""
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        yield node, depth
        for child in reversed(node.children):
            stack.append((child, depth + 1))


def _node_name(node: Any, source: bytes) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace")
    # arrow functions / closures assigned to a variable: look at the parent declarator
    parent = node.parent
    if parent is not None and parent.type in {"variable_declarator", "assignment", "pair",
                                              "assignment_expression", "let_declaration"}:
        for child in parent.children:
            if child.type in {"identifier", "property_identifier", "shorthand_property_identifier"}:
                return source[child.start_byte:child.end_byte].decode("utf-8", "replace")
    return "<anonymous>"


def function_spans(tree: Any, language: str, source: bytes) -> list[tuple[str, int, int]]:
    types = FUNCTION_NODE_TYPES.get(language, set())
    spans: list[tuple[str, int, int]] = []
    for node, _ in _walk(tree.root_node):
        if node.type in types:
            spans.append((_node_name(node, source), node.start_point.row + 1, node.end_point.row + 1))
    return spans


def max_nesting(tree: Any) -> int:
    best = 0
    stack = [(tree.root_node, 0)]
    while stack:
        node, depth = stack.pop()
        here = depth + (1 if node.type in NESTING_NODE_TYPES else 0)
        best = max(best, here)
        for child in node.children:
            stack.append((child, here))
    return best


def comment_lines(tree: Any) -> int:
    total = 0
    for node, _ in _walk(tree.root_node):
        if node.type in COMMENT_NODE_TYPES:
            total += node.end_point.row - node.start_point.row + 1
    return total
```

- [ ] **Step 5: Implement `analysis/metrics.py`**

```python
# src/unvarnish/analysis/metrics.py
from __future__ import annotations

import re
from pathlib import Path

from unvarnish.analysis.treesitter import (
    MAX_PARSE_BYTES,
    comment_lines,
    function_spans,
    get_parser,
    max_nesting,
)
from unvarnish.schemas.inventory import FileMetrics, HtmlBreakdown

SCRIPT_RE = re.compile(rb"<script\b[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
STYLE_RE = re.compile(rb"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)


def count_lines(data: bytes) -> int:
    if not data:
        return 0
    n = data.count(b"\n")
    if not data.endswith(b"\n"):
        n += 1
    return n


def html_breakdown(data: bytes) -> tuple[HtmlBreakdown, bytes]:
    scripts = [m.group(1) for m in SCRIPT_RE.finditer(data)]
    styles = [m.group(1) for m in STYLE_RE.finditer(data)]
    script_bytes = sum(len(s) for s in scripts)
    style_bytes = sum(len(s) for s in styles)
    script_lines = sum(count_lines(s.strip(b"\n")) for s in scripts)
    style_lines = sum(count_lines(s.strip(b"\n")) for s in styles)
    total_lines = count_lines(data)
    bd = HtmlBreakdown(
        markup_lines=max(total_lines - script_lines - style_lines, 0),
        script_lines=script_lines,
        style_lines=style_lines,
        markup_bytes=max(len(data) - script_bytes - style_bytes, 0),
        script_bytes=script_bytes,
        style_bytes=style_bytes,
        script_blocks=len(scripts),
        style_blocks=len(styles),
    )
    return bd, b"\n".join(scripts)


def _treesitter_metrics(source: bytes, language: str) -> dict:
    parser = get_parser(language)
    if parser is None or len(source) > MAX_PARSE_BYTES:
        return {}
    tree = parser.parse(source)
    spans = function_spans(tree, language, source)
    longest = max(spans, key=lambda s: s[2] - s[1], default=None)
    return {
        "functions": len(spans),
        "max_function_lines": (longest[2] - longest[1] + 1) if longest else 0,
        "max_function_name": longest[0] if longest else None,
        "max_nesting": max_nesting(tree),
        "comment_lines": comment_lines(tree),
    }


def compute_metrics(path: Path, relpath: str, language: str | None) -> FileMetrics:
    data = path.read_bytes()
    base = {"path": relpath, "lines": count_lines(data), "bytes": len(data)}

    if language == "html":
        bd, scripts = html_breakdown(data)
        ts = _treesitter_metrics(scripts, "javascript") if scripts else {}
        return FileMetrics(
            **base, html=bd, metrics_method="treesitter" if ts else "lines", **ts
        )

    ts = _treesitter_metrics(data, language) if language else {}
    if ts:
        return FileMetrics(**base, metrics_method="treesitter", **ts)
    return FileMetrics(**base, metrics_method="lines")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_metrics.py -v`
Expected: PASS (10 tests). If `test_python_metrics` reports a different `max_nesting`, inspect with `uv run python -c "..."` and adjust `NESTING_NODE_TYPES`, not the test's `>= 3` bound.

- [ ] **Step 7: Commit**

```bash
git add src/unvarnish/analysis/treesitter.py src/unvarnish/analysis/metrics.py src/unvarnish/schemas/inventory.py tests/__init__.py tests/test_metrics.py
git commit -m "feat: tree-sitter function/nesting metrics and HTML stream breakdown"
```

---

### Task 8: Phase framework and runner

**Files:**
- Create: `src/unvarnish/phases/base.py`, `tests/test_phase_runner.py`

**Interfaces:**
- Consumes: `Engagement`, `ToolPaths`, `ToolMeta`, `load_tool_meta`, `resolve_source_root`, `write_artifact`.
- Produces (`unvarnish.phases.base`):
  - `@dataclass class ToolContext`: `engagement: Engagement`, `tool: str`, `paths: ToolPaths`, `meta: ToolMeta`, `source_root: Path`; property `config -> EngagementConfig`
  - `class PhaseStatus(StrEnum)`: `ok, skipped, failed`
  - `class PhaseResult(BaseModel)`: `phase: str`, `status: PhaseStatus`, `message: str | None`, `failures: list[str]`
  - `class Phase(Protocol)`: `name: str`; `inputs_hash(ctx) -> str`; `outputs(ctx) -> list[Path]`; `run(ctx) -> PhaseResult`
  - `is_fresh(phase: Phase, ctx: ToolContext) -> bool`
  - `class PhaseRunner`: `__init__(phases: Sequence[Phase])`; `plan(ctx, *, force=False, only=None) -> list[Phase]`; `run(ctx, *, force=False, only=None) -> list[PhaseResult]`; attribute `phases`
  - `build_context(eng: Engagement, tool: str) -> ToolContext`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_phase_runner.py
from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import write_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import (
    PhaseResult,
    PhaseRunner,
    PhaseStatus,
    ToolContext,
    build_context,
    is_fresh,
)


class Blob(BaseModel):
    n: int


class CountingPhase:
    name = "counting"

    def __init__(self, hash_value: str = "h1") -> None:
        self.hash_value = hash_value
        self.runs = 0

    def inputs_hash(self, ctx: ToolContext) -> str:
        return self.hash_value

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.inventory / "counting.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        self.runs += 1
        write_artifact(
            self.outputs(ctx)[0], Blob(n=self.runs), produced_by=self.name,
            inputs_hash=self.inputs_hash(ctx),
        )
        return PhaseResult(phase=self.name, status=PhaseStatus.ok)


class ExplodingPhase:
    name = "exploding"

    def inputs_hash(self, ctx: ToolContext) -> str:
        return "x"

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.inventory / "never.json"]

    def run(self, ctx: ToolContext) -> PhaseResult:
        raise RuntimeError("boom")


def test_build_context(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    assert ctx.tool == name
    assert ctx.source_root == eng.tool_paths(name).source
    assert ctx.meta.origin_kind == "repo"
    assert ctx.config.client == "Acme"


def test_runner_skips_fresh_and_force_reruns(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase()
    runner = PhaseRunner([phase])
    first = runner.run(ctx)
    assert [r.status for r in first] == [PhaseStatus.ok]
    assert is_fresh(phase, ctx)
    second = runner.run(ctx)
    assert [r.status for r in second] == [PhaseStatus.skipped]
    assert phase.runs == 1
    runner.run(ctx, force=True)
    assert phase.runs == 2


def test_runner_reruns_when_inputs_change(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase("h1")
    PhaseRunner([phase]).run(ctx)
    phase.hash_value = "h2"
    assert not is_fresh(phase, ctx)
    PhaseRunner([phase]).run(ctx)
    assert phase.runs == 2


def test_runner_marks_failure_and_skips_downstream(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    after = CountingPhase()
    results = PhaseRunner([ExplodingPhase(), after]).run(ctx)
    assert results[0].status == PhaseStatus.failed
    assert "boom" in (results[0].message or "")
    assert results[1].status == PhaseStatus.skipped
    assert "upstream" in (results[1].message or "")
    assert after.runs == 0


def test_runner_only_runs_named_phase(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    a, b = CountingPhase(), CountingPhase()
    b.name = "other"
    results = PhaseRunner([a, b]).run(ctx, only="other")
    assert [r.phase for r in results] == ["other"]
    assert a.runs == 0 and b.runs == 1


def test_plan_lists_stale_phases(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    phase = CountingPhase()
    runner = PhaseRunner([phase])
    assert runner.plan(ctx) == [phase]
    runner.run(ctx)
    assert runner.plan(ctx) == []
    assert runner.plan(ctx, force=True) == [phase]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_phase_runner.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `phases/base.py`**

```python
# src/unvarnish/phases/base.py
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement, ToolPaths
from unvarnish.phases.ingest import load_tool_meta, resolve_source_root
from unvarnish.schemas.tool import ToolMeta


@dataclass
class ToolContext:
    engagement: Engagement
    tool: str
    paths: ToolPaths
    meta: ToolMeta
    source_root: Path

    @property
    def config(self) -> EngagementConfig:
        return self.engagement.config


class PhaseStatus(StrEnum):
    ok = "ok"
    skipped = "skipped"
    failed = "failed"


class PhaseResult(BaseModel):
    phase: str
    status: PhaseStatus
    message: str | None = None
    failures: list[str] = Field(default_factory=list)


class Phase(Protocol):
    name: str

    def inputs_hash(self, ctx: ToolContext) -> str: ...
    def outputs(self, ctx: ToolContext) -> list[Path]: ...
    def run(self, ctx: ToolContext) -> PhaseResult: ...


def _recorded_hash(path: Path) -> str | None:
    if path.suffix != ".json":
        return "<non-artifact>"
    try:
        return json.loads(path.read_text())["meta"]["inputs_hash"]
    except (OSError, ValueError, KeyError):
        return None


def is_fresh(phase: Phase, ctx: ToolContext) -> bool:
    outputs = phase.outputs(ctx)
    if not outputs or not all(p.exists() for p in outputs):
        return False
    current = phase.inputs_hash(ctx)
    for p in outputs:
        recorded = _recorded_hash(p)
        if recorded is None:
            return False
        if recorded != "<non-artifact>" and recorded != current:
            return False
    return True


class PhaseRunner:
    def __init__(self, phases: Sequence[Phase]) -> None:
        self.phases = list(phases)

    def _selected(self, only: str | None) -> list[Phase]:
        if only is None:
            return self.phases
        chosen = [p for p in self.phases if p.name == only]
        if not chosen:
            names = ", ".join(p.name for p in self.phases)
            raise ValueError(f"unknown phase {only!r}; known phases: {names}")
        return chosen

    def plan(self, ctx: ToolContext, *, force: bool = False, only: str | None = None) -> list[Phase]:
        return [p for p in self._selected(only) if force or not is_fresh(p, ctx)]

    def run(self, ctx: ToolContext, *, force: bool = False, only: str | None = None) -> list[PhaseResult]:
        results: list[PhaseResult] = []
        upstream_failed: str | None = None
        for phase in self._selected(only):
            if upstream_failed:
                results.append(PhaseResult(
                    phase=phase.name, status=PhaseStatus.skipped,
                    message=f"skipped: upstream phase {upstream_failed!r} failed",
                ))
                continue
            if not force and is_fresh(phase, ctx):
                results.append(PhaseResult(phase=phase.name, status=PhaseStatus.skipped, message="fresh"))
                continue
            try:
                result = phase.run(ctx)
            except Exception as exc:  # one bad phase never kills the process
                result = PhaseResult(phase=phase.name, status=PhaseStatus.failed, message=repr(exc))
            results.append(result)
            if result.status == PhaseStatus.failed:
                upstream_failed = phase.name
        return results


def build_context(eng: Engagement, tool: str) -> ToolContext:
    paths = eng.tool_paths(tool)
    meta = load_tool_meta(paths)
    return ToolContext(
        engagement=eng, tool=tool, paths=paths, meta=meta,
        source_root=resolve_source_root(eng, meta),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_phase_runner.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/phases/base.py tests/test_phase_runner.py
git commit -m "feat: phase protocol, freshness check, and runner with upstream-failure skipping"
```

---

### Task 9: Inventory phase (census, metrics, dependencies)

**Files:**
- Create: `src/unvarnish/analysis/dependencies.py`, `src/unvarnish/phases/inventory.py`, `tests/test_inventory_phase.py`
- Modify: `src/unvarnish/schemas/inventory.py` (add census and dependency models)

**Interfaces:**
- Consumes: `Classification, detect_language, classify, is_binary, Excluder` (Task 6); `compute_metrics, count_lines` (Task 7); `ToolContext, PhaseResult, PhaseStatus` (Task 8); `write_artifact, hash_tree`.
- Produces (`unvarnish.schemas.inventory`, added):
  - `class FileRecord(BaseModel)`: `path: str`, `bytes: int`, `lines: int`, `language: str | None`, `classification: Classification`, `excluded: bool`, `exclusion_reason: str | None`
  - `class CensusTotals(BaseModel)`: `files, bytes, lines, excluded_files, excluded_bytes, symlinks_skipped: int`; `by_classification: dict[str, int]`
  - `class Census(BaseModel)`: `tool: str`, `files: list[FileRecord]`, `totals: CensusTotals`, `languages: dict[str, int]` (source lines by language), `frameworks: list[str]`, `failures: list[str]`
  - `class Metrics(BaseModel)`: `tool: str`, `files: list[FileMetrics]`
  - `class DependencyRecord(BaseModel)`: `ecosystem: str`, `name: str`, `constraint: str | None`, `manifest: str`, `dev: bool = False`
  - `class Dependencies(BaseModel)`: `tool: str`, `dependencies: list[DependencyRecord]`, `advisories_checked: bool = False`, `advisories: list[dict] = []`
- Produces (`unvarnish.analysis.dependencies`): `parse_manifests(source_root: Path, files: list[FileRecord]) -> tuple[list[DependencyRecord], list[str]]`, `FRAMEWORK_HINTS: dict[str, str]`
- Produces (`unvarnish.phases.inventory`): `class InventoryPhase` (`name = "inventory"`), `SAMPLE_BYTES = 8192`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_inventory_phase.py
import os
from pathlib import Path

from unvarnish.analysis.dependencies import parse_manifests
from unvarnish.analysis.languages import Classification
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.schemas.inventory import Census, Dependencies, FileRecord, Metrics


def _run(eng: Engagement, name: str):
    ctx = build_context(eng, name)
    result = InventoryPhase().run(ctx)
    assert result.status == PhaseStatus.ok, result.message
    census = read_artifact(ctx.paths.census, Census).data
    metrics = read_artifact(ctx.paths.metrics, Metrics).data
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    return census, metrics, deps


def test_census_on_synthetic_repo(ingested: tuple[Engagement, str]):
    census, metrics, deps = _run(*ingested)
    by_path = {f.path: f for f in census.files}
    assert ".git/HEAD" not in by_path
    assert by_path["app.py"].classification == Classification.source
    assert by_path["app.py"].language == "python"
    assert by_path["node_modules/leftpad/index.js"].excluded
    assert by_path["node_modules/leftpad/index.js"].exclusion_reason == "vendored:node_modules"
    assert by_path["node_modules/leftpad/index.js"].classification == Classification.vendored
    assert by_path["static/app.min.js"].classification == Classification.generated
    assert by_path["CLAUDE.md"].classification == Classification.docs
    assert by_path["requirements.txt"].classification == Classification.config
    assert census.totals.excluded_files == 1
    assert census.totals.by_classification["source"] >= 1
    assert census.languages["python"] > 3000
    assert "Flask" in census.frameworks


def test_metrics_cover_source_not_excluded(ingested: tuple[Engagement, str]):
    census, metrics, _ = _run(*ingested)
    paths = {m.path for m in metrics.files}
    assert "app.py" in paths
    assert "static/index.html" in paths
    assert "node_modules/leftpad/index.js" not in paths
    assert "README.md" not in paths
    app = next(m for m in metrics.files if m.path == "app.py")
    assert app.max_function_name == "process_everything"
    assert app.max_function_lines > 2500


def test_dependencies_from_requirements(ingested: tuple[Engagement, str]):
    _, _, deps = _run(*ingested)
    names = {(d.ecosystem, d.name, d.constraint) for d in deps.dependencies}
    assert ("pypi", "flask", "==2.3.2") in names
    assert ("pypi", "requests", ">=2.31") in names
    assert deps.advisories_checked is False


def test_parse_manifests_multi_ecosystem(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "^18.2.0", "express": "4.19.2"}, "devDependencies": {"jest": "^29"}}'
    )
    (tmp_path / "go.mod").write_text(
        "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/text v0.14.0\n)\n"
    )
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\n\n[dependencies]\naxum = "0.7"\nserde = { version = "1.0", features = ["derive"] }\n'
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "y"\ndependencies = ["fastapi>=0.110", "pydantic"]\n'
    )
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.springframework.boot</groupId>"
        "<artifactId>spring-boot-starter-web</artifactId><version>3.2.0</version></dependency>"
        "</dependencies></project>"
    )
    files = [
        FileRecord(path=n, bytes=1, lines=1, language=None, classification=Classification.config,
                   excluded=False, exclusion_reason=None)
        for n in ("package.json", "go.mod", "Cargo.toml", "pyproject.toml", "pom.xml")
    ]
    deps, frameworks = parse_manifests(tmp_path, files)
    tuples = {(d.ecosystem, d.name) for d in deps}
    assert ("npm", "react") in tuples and ("npm", "jest") in tuples
    assert next(d for d in deps if d.name == "jest").dev is True
    assert ("go", "github.com/gin-gonic/gin") in tuples
    assert ("cargo", "axum") in tuples and ("cargo", "serde") in tuples
    assert ("pypi", "fastapi") in tuples
    assert ("maven", "org.springframework.boot:spring-boot-starter-web") in tuples
    assert {"React", "Express", "Gin", "Axum", "FastAPI", "Spring Boot"} <= set(frameworks)


def test_inventory_empty_tool(engagement: Engagement, tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    ingest_tool(engagement, "empty", str(empty), "files")
    census, metrics, deps = _run(engagement, "empty")
    assert census.files == []
    assert census.totals.files == 0
    assert metrics.files == []
    assert deps.dependencies == []


def test_inventory_skips_symlinks(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "real.py").write_text("x = 1\n")
    os.symlink("real.py", pile / "alias.py")
    os.symlink("nowhere", pile / "broken.py")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, _, _ = _run(engagement, "pile")
    assert [f.path for f in census.files] == ["real.py"]
    assert census.totals.symlinks_skipped == 2


def test_inventory_unicode_filename(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "données").mkdir(parents=True)
    (pile / "données" / "résumé final.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, metrics, _ = _run(engagement, "pile")
    assert census.files[0].path == "données/résumé final.py"
    assert metrics.files[0].path == "données/résumé final.py"


def test_inventory_binary_with_text_extension(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "blob.txt").write_bytes(b"\x89PNG\x00\x00binary")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, metrics, _ = _run(engagement, "pile")
    assert census.files[0].classification == Classification.binary
    assert census.files[0].lines == 0
    assert metrics.files == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_inventory_phase.py -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Extend `schemas/inventory.py`**

Append to the file from Task 7:

```python
from pydantic import Field

from unvarnish.analysis.languages import Classification


class FileRecord(BaseModel):
    path: str
    bytes: int
    lines: int
    language: str | None
    classification: Classification
    excluded: bool
    exclusion_reason: str | None


class CensusTotals(BaseModel):
    files: int = 0
    bytes: int = 0
    lines: int = 0
    excluded_files: int = 0
    excluded_bytes: int = 0
    symlinks_skipped: int = 0
    by_classification: dict[str, int] = Field(default_factory=dict)


class Census(BaseModel):
    tool: str
    files: list[FileRecord]
    totals: CensusTotals
    languages: dict[str, int] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)  # files that could not be read or measured


class Metrics(BaseModel):
    tool: str
    files: list[FileMetrics]


class DependencyRecord(BaseModel):
    ecosystem: str
    name: str
    constraint: str | None
    manifest: str
    dev: bool = False


class Dependencies(BaseModel):
    tool: str
    dependencies: list[DependencyRecord]
    advisories_checked: bool = False
    advisories: list[dict] = Field(default_factory=list)
```

Move the `from pydantic import BaseModel` import to `from pydantic import BaseModel, Field` at the top.

- [ ] **Step 4: Implement `analysis/dependencies.py`**

```python
# src/unvarnish/analysis/dependencies.py
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from unvarnish.schemas.inventory import DependencyRecord, FileRecord

FRAMEWORK_HINTS: dict[str, str] = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "streamlit": "Streamlit",
    "gradio": "Gradio", "celery": "Celery", "sqlalchemy": "SQLAlchemy", "langchain": "LangChain",
    "react": "React", "next": "Next.js", "express": "Express", "vue": "Vue",
    "@angular/core": "Angular", "svelte": "Svelte", "nestjs": "NestJS", "@nestjs/core": "NestJS",
    "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber",
    "actix-web": "Actix Web", "axum": "Axum", "rocket": "Rocket", "tokio": "Tokio",
    "spring-boot-starter": "Spring Boot", "rails": "Rails", "laravel/framework": "Laravel",
}

PY_SPLIT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(.*)$")
GO_REQ_RE = re.compile(r"^\s*([\w./\-~]+)\s+(v[\w.+\-]+)")
POM_DEP_RE = re.compile(
    r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>"
    r"(?:.*?<version>(.*?)</version>)?.*?</dependency>",
    re.DOTALL,
)


def _framework_for(name: str) -> str | None:
    key = name.lower()
    if key in FRAMEWORK_HINTS:
        return FRAMEWORK_HINTS[key]
    for hint, label in FRAMEWORK_HINTS.items():
        if ("/" in hint or "-" in hint) and hint in key:
            return label
    return None


def _py_requirement(line: str, manifest: str) -> DependencyRecord | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http")):
        return None
    m = PY_SPLIT_RE.match(line)
    if not m:
        return None
    name = re.split(r"\[", m.group(1), maxsplit=1)[0].lower()
    constraint = m.group(2).strip() or None
    return DependencyRecord(ecosystem="pypi", name=name, constraint=constraint, manifest=manifest)


def _parse_package_json(text: str, manifest: str) -> list[DependencyRecord]:
    data = json.loads(text)
    out = []
    for key, dev in (("dependencies", False), ("devDependencies", True)):
        for name, constraint in (data.get(key) or {}).items():
            out.append(DependencyRecord(ecosystem="npm", name=name, constraint=str(constraint),
                                        manifest=manifest, dev=dev))
    return out


def _parse_pyproject(text: str, manifest: str) -> list[DependencyRecord]:
    data = tomllib.loads(text)
    out = []
    for req in data.get("project", {}).get("dependencies", []) or []:
        rec = _py_requirement(req, manifest)
        if rec:
            out.append(rec)
    for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
        for req in group:
            rec = _py_requirement(req, manifest)
            if rec:
                rec.dev = True
                out.append(rec)
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        constraint = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
        out.append(DependencyRecord(ecosystem="pypi", name=name.lower(), constraint=constraint, manifest=manifest))
    return out


def _parse_go_mod(text: str, manifest: str) -> list[DependencyRecord]:
    out = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        candidate = stripped[len("require "):] if stripped.startswith("require ") else (stripped if in_block else None)
        if candidate is None:
            continue
        m = GO_REQ_RE.match(candidate)
        if m:
            out.append(DependencyRecord(ecosystem="go", name=m.group(1), constraint=m.group(2), manifest=manifest))
    return out


def _parse_cargo(text: str, manifest: str) -> list[DependencyRecord]:
    data = tomllib.loads(text)
    out = []
    for table, dev in (("dependencies", False), ("dev-dependencies", True), ("build-dependencies", True)):
        for name, spec in (data.get(table) or {}).items():
            constraint = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            out.append(DependencyRecord(ecosystem="cargo", name=name, constraint=constraint, manifest=manifest, dev=dev))
    return out


def _parse_pom(text: str, manifest: str) -> list[DependencyRecord]:
    return [
        DependencyRecord(ecosystem="maven", name=f"{g.strip()}:{a.strip()}",
                         constraint=(v.strip() if v else None), manifest=manifest)
        for g, a, v in POM_DEP_RE.findall(text)
    ]


def parse_manifests(source_root: Path, files: list[FileRecord]) -> tuple[list[DependencyRecord], list[str]]:
    deps: list[DependencyRecord] = []
    for rec in files:
        if rec.excluded:
            continue
        name = Path(rec.path).name
        path = source_root / rec.path
        try:
            text = path.read_text(errors="replace")
            if name == "package.json":
                deps += _parse_package_json(text, rec.path)
            elif name == "pyproject.toml":
                deps += _parse_pyproject(text, rec.path)
            elif name.startswith("requirements") and name.endswith(".txt"):
                deps += [r for r in (_py_requirement(l, rec.path) for l in text.splitlines()) if r]
            elif name == "go.mod":
                deps += _parse_go_mod(text, rec.path)
            elif name == "Cargo.toml":
                deps += _parse_cargo(text, rec.path)
            elif name == "pom.xml":
                deps += _parse_pom(text, rec.path)
        except (ValueError, OSError):
            continue  # a malformed manifest is a finding for the hygiene scanner, not a crash
    frameworks = sorted({fw for d in deps if (fw := _framework_for(d.name))})
    return deps, frameworks
```

- [ ] **Step 5: Implement `phases/inventory.py`**

```python
# src/unvarnish/phases/inventory.py
from __future__ import annotations

from pathlib import Path, PurePosixPath

from unvarnish.analysis.dependencies import parse_manifests
from unvarnish.analysis.languages import (
    Classification,
    Excluder,
    classify,
    detect_language,
    is_binary,
)
from unvarnish.analysis.metrics import compute_metrics, count_lines
from unvarnish.artifacts import hash_tree, walk_files, write_artifact
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    FileRecord,
    Metrics,
)

SAMPLE_BYTES = 8192
METRICS_CLASSES = {Classification.source, Classification.test}


class InventoryPhase:
    name = "inventory"

    def inputs_hash(self, ctx: ToolContext) -> str:
        return hash_tree(ctx.source_root)

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.census, ctx.paths.metrics, ctx.paths.dependencies]

    def run(self, ctx: ToolContext) -> PhaseResult:
        root = ctx.source_root
        excluder = Excluder(root)
        records: list[FileRecord] = []
        metrics = []
        totals = CensusTotals()
        languages: dict[str, int] = {}
        failures: list[str] = []

        files, totals.symlinks_skipped = walk_files(root)
        for path, rel_str in files:
            rel = PurePosixPath(rel_str)
            try:
                data = path.read_bytes()
            except OSError as exc:
                failures.append(f"{rel}: {exc}")
                continue
            sample = data[:SAMPLE_BYTES]
            binary = is_binary(sample)
            language = None if binary else detect_language(rel, sample)
            classification = classify(rel, language, sample)
            reason = excluder.reason(rel)
            lines = 0 if binary else count_lines(data)
            rec = FileRecord(
                path=rel.as_posix(), bytes=len(data), lines=lines, language=language,
                classification=classification, excluded=reason is not None, exclusion_reason=reason,
            )
            records.append(rec)
            totals.files += 1
            totals.bytes += len(data)
            totals.lines += lines
            totals.by_classification[classification] = totals.by_classification.get(classification, 0) + 1
            if rec.excluded:
                totals.excluded_files += 1
                totals.excluded_bytes += len(data)
                continue
            if classification == Classification.source and language:
                languages[language] = languages.get(language, 0) + lines
            if classification in METRICS_CLASSES and not binary:
                try:
                    metrics.append(compute_metrics(path, rec.path, language))
                except Exception as exc:  # one bad file never kills a run
                    failures.append(f"{rel}: metrics failed: {exc!r}")

        deps, frameworks = parse_manifests(root, records)
        census = Census(tool=ctx.tool, files=records, totals=totals, languages=languages,
                        frameworks=frameworks, failures=failures)
        h = self.inputs_hash(ctx)
        write_artifact(ctx.paths.census, census, produced_by=self.name, inputs_hash=h)
        write_artifact(ctx.paths.metrics, Metrics(tool=ctx.tool, files=metrics), produced_by=self.name, inputs_hash=h)
        write_artifact(ctx.paths.dependencies, Dependencies(tool=ctx.tool, dependencies=deps), produced_by=self.name, inputs_hash=h)
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, failures=failures,
                           message=f"{totals.files} files, {len(metrics)} measured")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_inventory_phase.py -v`
Expected: PASS (8 tests)

- [ ] **Step 7: Commit**

```bash
git add src/unvarnish/analysis/dependencies.py src/unvarnish/phases/inventory.py src/unvarnish/schemas/inventory.py tests/test_inventory_phase.py
git commit -m "feat: inventory phase with census, metrics, and manifest dependency parsing"
```

---

### Task 10: Git phase

**Files:**
- Create: `src/unvarnish/schemas/git.py`, `src/unvarnish/phases/git.py`, `tests/test_git_phase.py`

**Interfaces:**
- Consumes: `git`, `is_git_repo` (Task 5); `ToolContext, PhaseResult, PhaseStatus` (Task 8); `write_artifact, hash_inputs`.
- Produces (`unvarnish.schemas.git`):
  - `class AuthorStats(BaseModel)`: `name: str`, `email: str`, `commits: int`, `lines_changed: int`, `share: float`
  - `class CommitInfo(BaseModel)`: `sha: str`, `date: datetime`, `author: str`, `lines_added: int`, `lines_deleted: int`, `files: int`, `message_head: str`
  - `class WeeklyBucket(BaseModel)`: `week_start: date`, `commits: int`, `lines_changed: int`
  - `class ChurnEntry(BaseModel)`: `path: str`, `changes: int`, `lines_changed: int`
  - `class AiFingerprints(BaseModel)`: `files: list[str]`, `coauthor_trailers: dict[str, int]`, `message_patterns: int`
  - `class GitStats(BaseModel)`: `tool: str`, `available: bool`, `reason: str | None`, `commit_count: int`, `first_commit: datetime | None`, `last_commit: datetime | None`, `active_days: int`, `authors: list[AuthorStats]` (sorted by `lines_changed` desc), `bus_factor: int | None`, `top_author_share: float | None`, `large_commits: list[CommitInfo]`, `large_commit_threshold: int`, `weekly_velocity: list[WeeklyBucket]`, `churn_hotspots: list[ChurnEntry]` (top 20), `ai_fingerprints: AiFingerprints`
- Produces (`unvarnish.phases.git`): `class GitPhase` (`name = "git"`), `parse_log(raw: str) -> list[ParsedCommit]`, `AI_FINGERPRINT_FILES: list[str]`, `LOG_FORMAT: str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_git_phase.py
from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase, parse_log
from unvarnish.phases.ingest import ingest_tool
from unvarnish.schemas.git import GitStats


def _run(eng: Engagement, name: str) -> GitStats:
    ctx = build_context(eng, name)
    result = GitPhase().run(ctx)
    assert result.status == PhaseStatus.ok, result.message
    return read_artifact(ctx.paths.git, GitStats).data


def test_git_stats_on_synthetic_repo(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    assert stats.available is True
    assert stats.commit_count == 4
    assert stats.active_days == 4
    assert stats.first_commit is not None and stats.first_commit.year == 2026
    assert [a.name for a in stats.authors] == ["Alice", "Bob"]
    assert stats.authors[0].commits == 3
    assert stats.top_author_share is not None and stats.top_author_share > 0.9
    assert stats.bus_factor == 1


def test_large_commits_and_velocity(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    assert stats.large_commit_threshold == 2000
    assert len(stats.large_commits) == 1
    assert stats.large_commits[0].message_head == "generate processing"
    assert stats.large_commits[0].lines_added > 3000
    assert len(stats.weekly_velocity) >= 2
    assert sum(b.commits for b in stats.weekly_velocity) == 4


def test_churn_and_ai_fingerprints(ingested: tuple[Engagement, str]):
    stats = _run(*ingested)
    churn = {c.path: c for c in stats.churn_hotspots}
    assert churn["app.py"].changes == 2
    assert churn["README.md"].changes == 2
    assert stats.ai_fingerprints.files == ["CLAUDE.md"]
    assert stats.ai_fingerprints.coauthor_trailers == {"Claude": 1}


def test_git_phase_no_repo(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    stats = _run(engagement, "pile")
    assert stats.available is False
    assert stats.reason and ".git" in stats.reason
    assert stats.commit_count == 0


def test_git_phase_empty_repo(engagement: Engagement, tmp_path: Path):
    """A repo with .git but no commits. ingest_tool needs HEAD, so stage it by hand."""
    import shutil
    import subprocess
    from datetime import UTC, datetime

    import yaml

    from unvarnish.schemas.tool import ToolMeta

    repo = tmp_path / "fresh"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    paths = engagement.tool_paths("fresh")
    paths.ensure_dirs()
    shutil.copytree(repo, paths.source, symlinks=True)
    meta = ToolMeta(name="fresh", origin_kind="repo", origin=str(repo), ingested_at=datetime.now(UTC))
    paths.meta_file.write_text(yaml.safe_dump(meta.model_dump(mode="json")))
    engagement.register_tool("fresh")
    stats = _run(engagement, "fresh")
    assert stats.available is False
    assert stats.reason and "no commits" in stats.reason


def test_parse_log_handles_multiline_bodies_and_binary_numstat():
    raw = (
        "\x1e" + "a" * 40 + "\x1fAlice\x1falice@example.com\x1f2026-01-05T10:00:00+00:00\x1f"
        + "subject line\n\nbody with\ttab\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n\x1d\n"
        + "3\t1\tapp.py\n-\t-\timg.png\n"
        + "\x1e" + "b" * 40 + "\x1fBob\x1fbob@example.com\x1f2026-02-01T10:00:00+00:00\x1fsecond\n\x1d\n"
        + "1\t0\tREADME.md\n"
    )
    commits = parse_log(raw)
    assert len(commits) == 2
    assert commits[0].added == 3 and commits[0].deleted == 1
    assert [f for f, _ in commits[0].files] == ["app.py", "img.png"]
    assert "Co-Authored-By" in commits[0].body
    assert commits[1].author == "Bob"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_git_phase.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `schemas/git.py`**

```python
# src/unvarnish/schemas/git.py
from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field


class AuthorStats(BaseModel):
    name: str
    email: str
    commits: int
    lines_changed: int
    share: float


class CommitInfo(BaseModel):
    sha: str
    date: datetime
    author: str
    lines_added: int
    lines_deleted: int
    files: int
    message_head: str


class WeeklyBucket(BaseModel):
    week_start: date
    commits: int
    lines_changed: int


class ChurnEntry(BaseModel):
    path: str
    changes: int
    lines_changed: int


class AiFingerprints(BaseModel):
    files: list[str] = Field(default_factory=list)
    coauthor_trailers: dict[str, int] = Field(default_factory=dict)
    message_patterns: int = 0


class GitStats(BaseModel):
    tool: str
    available: bool
    reason: str | None = None
    commit_count: int = 0
    first_commit: datetime | None = None
    last_commit: datetime | None = None
    active_days: int = 0
    authors: list[AuthorStats] = Field(default_factory=list)
    bus_factor: int | None = None
    top_author_share: float | None = None
    large_commits: list[CommitInfo] = Field(default_factory=list)
    large_commit_threshold: int = 2000
    weekly_velocity: list[WeeklyBucket] = Field(default_factory=list)
    churn_hotspots: list[ChurnEntry] = Field(default_factory=list)
    ai_fingerprints: AiFingerprints = Field(default_factory=AiFingerprints)
```

- [ ] **Step 4: Implement `phases/git.py`**

```python
# src/unvarnish/phases/git.py
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from unvarnish.artifacts import hash_inputs, write_artifact
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.git import (
    AiFingerprints,
    AuthorStats,
    ChurnEntry,
    CommitInfo,
    GitStats,
    WeeklyBucket,
)
from unvarnish.util.gitcmd import GitError, git, is_git_repo

LOG_FORMAT = "%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f%B%x1d"

AI_FINGERPRINT_FILES = [
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".cursor", ".clinerules",
    ".windsurfrules", ".github/copilot-instructions.md", ".aider.conf.yml", ".aiderignore",
]
COAUTHOR_RE = re.compile(r"(?im)^co-authored-by:\s*([^<\n]+?)\s*(?:<[^>]*>)?\s*$")
AI_NAME_RE = re.compile(r"(?i)claude|copilot|cursor|chatgpt|openai|aider|codex|gemini|devin|windsurf|cline")
AI_MESSAGE_RE = re.compile(
    r"(?i)\b(generated (?:by|with) (?:claude|chatgpt|copilot|cursor|ai)|ai[- ]generated|vibe[- ]coded)\b"
)


@dataclass
class ParsedCommit:
    sha: str
    author: str
    email: str
    date: datetime
    body: str
    added: int = 0
    deleted: int = 0
    files: list[tuple[str, int]] = field(default_factory=list)


def parse_log(raw: str) -> list[ParsedCommit]:
    commits: list[ParsedCommit] = []
    for chunk in raw.split("\x1e")[1:]:
        head, _, rest = chunk.partition("\x1d")
        try:
            sha, name, email, date_s, body = head.split("\x1f", 4)
        except ValueError:
            continue
        c = ParsedCommit(sha=sha, author=name, email=email, date=datetime.fromisoformat(date_s), body=body)
        for line in rest.strip("\n").splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            a, d, path = parts
            a_i = int(a) if a.isdigit() else 0
            d_i = int(d) if d.isdigit() else 0
            c.added += a_i
            c.deleted += d_i
            c.files.append((path, a_i + d_i))
        commits.append(c)
    return commits


class GitPhase:
    name = "git"

    def inputs_hash(self, ctx: ToolContext) -> str:
        if not is_git_repo(ctx.source_root):
            return hash_inputs(["no-git"])
        try:
            head = git(["rev-parse", "HEAD"], cwd=ctx.source_root).strip()
            count = git(["rev-list", "--all", "--count"], cwd=ctx.source_root).strip()
        except GitError:
            return hash_inputs(["git-unreadable"])
        threshold = str(ctx.config.scanners.get("generated_bulk", {}).get("commit_lines", 2000))
        return hash_inputs([head, count, threshold])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.git]

    def run(self, ctx: ToolContext) -> PhaseResult:
        threshold = int(ctx.config.scanners.get("generated_bulk", {}).get("commit_lines", 2000))
        stats = self._compute(ctx, threshold)
        write_artifact(ctx.paths.git, stats, produced_by=self.name, inputs_hash=self.inputs_hash(ctx))
        msg = f"{stats.commit_count} commits" if stats.available else f"skipped: {stats.reason}"
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, message=msg)

    def _compute(self, ctx: ToolContext, threshold: int) -> GitStats:
        root = ctx.source_root
        if not is_git_repo(root):
            return GitStats(tool=ctx.tool, available=False, reason="no .git directory",
                            large_commit_threshold=threshold)
        try:
            raw = git(["log", "--all", "--numstat", f"--format={LOG_FORMAT}"], cwd=root)
        except GitError as exc:
            return GitStats(tool=ctx.tool, available=False, reason=f"git log failed: no commits ({exc})",
                            large_commit_threshold=threshold)
        commits = parse_log(raw)
        if not commits:
            return GitStats(tool=ctx.tool, available=False, reason="repository has no commits",
                            large_commit_threshold=threshold)
        commits.sort(key=lambda c: c.date)

        # authors
        by_author: dict[tuple[str, str], AuthorStats] = {}
        total_lines = 0
        for c in commits:
            key = (c.author, c.email)
            a = by_author.setdefault(key, AuthorStats(name=c.author, email=c.email, commits=0, lines_changed=0, share=0.0))
            a.commits += 1
            a.lines_changed += c.added + c.deleted
            total_lines += c.added + c.deleted
        authors = sorted(by_author.values(), key=lambda a: (-a.lines_changed, -a.commits, a.name))
        for a in authors:
            a.share = (a.lines_changed / total_lines) if total_lines else (a.commits / len(commits))
        cumulative, bus_factor = 0.0, 0
        for a in authors:
            cumulative += a.share
            bus_factor += 1
            if cumulative >= 0.8:
                break

        # velocity
        weeks: dict = defaultdict(lambda: [0, 0])
        for c in commits:
            start = (c.date.date() - timedelta(days=c.date.weekday()))
            weeks[start][0] += 1
            weeks[start][1] += c.added + c.deleted
        velocity = [WeeklyBucket(week_start=k, commits=v[0], lines_changed=v[1]) for k, v in sorted(weeks.items())]

        # churn
        churn: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for c in commits:
            for path, lines in c.files:
                churn[path][0] += 1
                churn[path][1] += lines
        hotspots = sorted(
            (ChurnEntry(path=p, changes=v[0], lines_changed=v[1]) for p, v in churn.items()),
            key=lambda e: (-e.changes, -e.lines_changed, e.path),
        )[:20]

        # AI fingerprints
        trailers: dict[str, int] = defaultdict(int)
        patterns = 0
        for c in commits:
            for name in COAUTHOR_RE.findall(c.body):
                if AI_NAME_RE.search(name):
                    trailers[name.strip()] += 1
            if AI_MESSAGE_RE.search(c.body):
                patterns += 1
        fp_files = [f for f in AI_FINGERPRINT_FILES if (root / f).exists()]

        large = [
            CommitInfo(sha=c.sha, date=c.date, author=c.author, lines_added=c.added, lines_deleted=c.deleted,
                       files=len(c.files), message_head=c.body.strip().splitlines()[0] if c.body.strip() else "")
            for c in commits if c.added + c.deleted > threshold
        ]

        return GitStats(
            tool=ctx.tool, available=True, commit_count=len(commits),
            first_commit=commits[0].date, last_commit=commits[-1].date,
            active_days=len({c.date.date() for c in commits}),
            authors=authors, bus_factor=bus_factor, top_author_share=authors[0].share if authors else None,
            large_commits=large, large_commit_threshold=threshold,
            weekly_velocity=velocity, churn_hotspots=hotspots,
            ai_fingerprints=AiFingerprints(files=fp_files, coauthor_trailers=dict(trailers), message_patterns=patterns),
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_git_phase.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/schemas/git.py src/unvarnish/phases/git.py tests/test_git_phase.py
git commit -m "feat: git phase with authorship, bus factor, velocity, churn, and AI fingerprints"
```

---

### Task 11: Scanner framework and scan phase

**Files:**
- Create: `src/unvarnish/scanners/__init__.py`, `src/unvarnish/scanners/base.py`, `src/unvarnish/schemas/scan.py`, `src/unvarnish/phases/scan.py`, `tests/test_scan_phase.py`

**Interfaces:**
- Consumes: `Census, Metrics, Dependencies` (Task 9), `GitStats` (Task 10), `Finding` (Task 3), `ToolContext` (Task 8), `read_artifact, write_artifact, hash_files, hash_inputs`.
- Produces (`unvarnish.scanners.base`):
  - `@dataclass class ScanContext`: `tool: str`, `source_root: Path`, `census: Census`, `metrics: Metrics`, `git: GitStats`, `dependencies: Dependencies`, `options: dict[str, Any]`
  - `class Scanner(Protocol)`: `name: str`, `category: Category`; `run(ctx: ScanContext) -> list[Finding]`
- Produces (`unvarnish.schemas.scan`): `class SkippedScanner(BaseModel)`: `name: str`, `error: str`; `class ScannerFindings(BaseModel)`: `tool: str`, `findings: list[Finding]`, `skipped: list[SkippedScanner]`, `scanners_run: list[str]`
- Produces (`unvarnish.scanners`): `builtin_scanners() -> list[Scanner]` (returns `[]` until Task 14 registers the built-ins), `load_scanners() -> list[Scanner]` (built-ins plus entry points in group `unvarnish.scanners`; an entry point with the same name replaces the built-in), `ENTRY_POINT_GROUP = "unvarnish.scanners"`
- Produces (`unvarnish.phases.scan`): `class ScanPhase` with `__init__(scanners: Sequence[Scanner] | None = None)` (`None` means `load_scanners()`), `name = "scan"`, `sort_findings(findings: list[Finding]) -> list[Finding]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scan_phase.py
from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase, sort_findings
from unvarnish.scanners import load_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.schemas.scan import ScannerFindings


class DummyScanner:
    name = "dummy"
    category = Category.process

    def __init__(self, severity: Severity = Severity.low) -> None:
        self.severity = severity
        self.seen_options: dict | None = None

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.seen_options = ctx.options
        return [
            Finding(
                tool=ctx.tool, category=self.category, severity=self.severity,
                title="Dummy finding", summary="s", impact="i", remediation="r",
                evidence=[Evidence(path="app.py", line_start=1)], source=Source.scanner, scanner=self.name,
            )
        ]


class BrokenScanner:
    name = "broken"
    category = Category.process

    def run(self, ctx: ScanContext) -> list[Finding]:
        raise ValueError("kaboom")


def _prepare(ingested: tuple[Engagement, str]):
    eng, name = ingested
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    return ctx


def test_scan_phase_collects_and_records_skips(ingested):
    ctx = _prepare(ingested)
    eng = ctx.engagement
    eng.config.scanners["dummy"] = {"threshold": 3}
    dummy = DummyScanner()
    phase = ScanPhase(scanners=[dummy, BrokenScanner()])
    result = phase.run(ctx)
    assert result.status == PhaseStatus.ok
    assert result.failures == ["broken: ValueError('kaboom')"]
    out = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert [f.title for f in out.findings] == ["Dummy finding"]
    assert out.findings[0].verification == "not_required"
    assert out.skipped[0].name == "broken" and "kaboom" in out.skipped[0].error
    assert out.scanners_run == ["dummy", "broken"]
    assert dummy.seen_options == {"threshold": 3}


def test_scan_phase_freshness_tracks_options(ingested):
    ctx = _prepare(ingested)
    phase = ScanPhase(scanners=[DummyScanner()])
    h1 = phase.inputs_hash(ctx)
    ctx.engagement.config.scanners["dummy"] = {"threshold": 9}
    assert phase.inputs_hash(ctx) != h1


def test_sort_findings_by_severity_then_path():
    def f(sev, path, title="t"):
        return Finding(tool="x", category=Category.security, severity=sev, title=title, summary="s",
                       impact="i", remediation="r", evidence=[Evidence(path=path)], source=Source.scanner)

    out = sort_findings([f(Severity.low, "b.py"), f(Severity.critical, "z.py"), f(Severity.low, "a.py")])
    assert [(x.severity, x.evidence[0].path) for x in out] == [
        (Severity.critical, "z.py"), (Severity.low, "a.py"), (Severity.low, "b.py"),
    ]


def test_load_scanners_includes_entry_points(monkeypatch):
    import importlib.metadata as md

    class FakeEP:
        name = "dummy"
        group = "unvarnish.scanners"

        def load(self):
            return DummyScanner

    class FakeEPs(list):
        def select(self, group):
            return self if group == "unvarnish.scanners" else []

    monkeypatch.setattr(md, "entry_points", lambda: FakeEPs([FakeEP()]))
    names = [s.name for s in load_scanners()]
    assert names.count("dummy") == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scan_phase.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `schemas/scan.py` and `scanners/base.py`**

```python
# src/unvarnish/schemas/scan.py
from __future__ import annotations

from pydantic import BaseModel, Field

from unvarnish.schemas.finding import Finding


class SkippedScanner(BaseModel):
    name: str
    error: str


class ScannerFindings(BaseModel):
    tool: str
    findings: list[Finding] = Field(default_factory=list)
    skipped: list[SkippedScanner] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
```

```python
# src/unvarnish/scanners/base.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from unvarnish.schemas.finding import Category, Finding
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics


@dataclass
class ScanContext:
    tool: str
    source_root: Path
    census: Census
    metrics: Metrics
    git: GitStats
    dependencies: Dependencies
    options: dict[str, Any] = field(default_factory=dict)


class Scanner(Protocol):
    name: str
    category: Category

    def run(self, ctx: ScanContext) -> list[Finding]: ...
```

- [ ] **Step 4: Implement `scanners/__init__.py`**

```python
# src/unvarnish/scanners/__init__.py
from __future__ import annotations

import importlib.metadata as md

from unvarnish.scanners.base import ScanContext, Scanner

ENTRY_POINT_GROUP = "unvarnish.scanners"

__all__ = ["ENTRY_POINT_GROUP", "ScanContext", "Scanner", "builtin_scanners", "load_scanners"]


def builtin_scanners() -> list[Scanner]:
    """Built-in scanners. Populated in Task 14; empty until then."""
    return []


def load_scanners() -> list[Scanner]:
    scanners: dict[str, Scanner] = {s.name: s for s in builtin_scanners()}
    for ep in md.entry_points().select(group=ENTRY_POINT_GROUP):
        cls = ep.load()
        instance = cls() if isinstance(cls, type) else cls
        scanners[instance.name] = instance  # entry point overrides a built-in of the same name
    return list(scanners.values())
```

- [ ] **Step 5: Implement `phases/scan.py`**

```python
# src/unvarnish/phases/scan.py
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.scanners import load_scanners
from unvarnish.scanners.base import ScanContext, Scanner
from unvarnish.schemas.finding import SEVERITY_ORDER, Finding
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings, SkippedScanner


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path, f.evidence[0].line_start or 0, f.title),
    )


class ScanPhase:
    name = "scan"

    def __init__(self, scanners: Sequence[Scanner] | None = None) -> None:
        self._scanners = list(scanners) if scanners is not None else None

    def scanners(self) -> list[Scanner]:
        return self._scanners if self._scanners is not None else load_scanners()

    def _artifacts(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.census, ctx.paths.metrics, ctx.paths.git, ctx.paths.dependencies]

    def inputs_hash(self, ctx: ToolContext) -> str:
        names = [s.name for s in self.scanners()]
        options = json.dumps({n: ctx.config.scanners.get(n, {}) for n in names}, sort_keys=True)
        return hash_inputs([hash_files(self._artifacts(ctx)), ",".join(names), options])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.scanner_findings]

    def run(self, ctx: ToolContext) -> PhaseResult:
        census = read_artifact(ctx.paths.census, Census).data
        metrics = read_artifact(ctx.paths.metrics, Metrics).data
        git = read_artifact(ctx.paths.git, GitStats).data
        deps = read_artifact(ctx.paths.dependencies, Dependencies).data

        findings: list[Finding] = []
        skipped: list[SkippedScanner] = []
        run_names: list[str] = []
        for scanner in self.scanners():
            run_names.append(scanner.name)
            sctx = ScanContext(
                tool=ctx.tool, source_root=ctx.source_root, census=census, metrics=metrics,
                git=git, dependencies=deps, options=dict(ctx.config.scanners.get(scanner.name, {})),
            )
            try:
                findings.extend(scanner.run(sctx))
            except Exception as exc:  # a broken scanner is recorded, never fatal
                skipped.append(SkippedScanner(name=scanner.name, error=repr(exc)))

        out = ScannerFindings(tool=ctx.tool, findings=sort_findings(findings), skipped=skipped, scanners_run=run_names)
        write_artifact(ctx.paths.scanner_findings, out, produced_by=self.name, inputs_hash=self.inputs_hash(ctx))
        return PhaseResult(
            phase=self.name, status=PhaseStatus.ok,
            message=f"{len(findings)} findings from {len(run_names) - len(skipped)} scanners",
            failures=[f"{s.name}: {s.error}" for s in skipped],
        )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_scan_phase.py -v`
Expected: PASS (4 tests)

- [ ] **Step 7: Commit**

```bash
git add src/unvarnish/scanners src/unvarnish/schemas/scan.py src/unvarnish/phases/scan.py tests/test_scan_phase.py
git commit -m "feat: scanner protocol, registry with entry points, and scan phase"
```

---

### Task 12: Secrets scanner

**Files:**
- Create: `src/unvarnish/scanners/secrets.py`, `tests/test_scanner_secrets.py`

**Interfaces:**
- Consumes: `ScanContext, Scanner` (Task 11), `Finding, Evidence, Category, Severity, Source` (Task 3), `git_lines, is_git_repo` (Task 5), `Classification` (Task 6).
- Produces (`unvarnish.scanners.secrets`):
  - `@dataclass class SecretRule`: `name: str`, `pattern: re.Pattern`, `severity: Severity`, `title: str`, `value_group: int` (0 = whole match)
  - `RULES: list[SecretRule]`
  - `@dataclass class SecretMatch`: `rule: str`, `path: str`, `line: int | None`, `raw: str`, `line_text: str`, `commit: str | None`
  - `fingerprint(raw: str) -> str` (12 hex chars)
  - `redact(line_text: str, raw: str) -> str`
  - `is_placeholder(value: str) -> bool`
  - `scan_text(path: str, text: str, commit: str | None = None) -> list[SecretMatch]`
  - `scan_history_lines(lines: Iterable[str]) -> list[SecretMatch]` (consumes a `git log -p` line stream)
  - `class SecretsScanner` (`name = "secrets"`, `category = Category.security`), `MAX_SCAN_BYTES = 5_000_000`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scanner_secrets.py
from pathlib import Path

import pytest

from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.artifacts import read_artifact
from unvarnish.scanners import secrets as secrets_mod
from unvarnish.scanners.secrets import (
    SecretsScanner,
    fingerprint,
    is_placeholder,
    redact,
    scan_history_lines,
    scan_text,
)
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.scan import ScannerFindings
from tests.conftest import LEAKED_DB_URL, LEAKED_KEY


def _scan(eng: Engagement, name: str) -> ScannerFindings:
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert ScanPhase(scanners=[SecretsScanner()]).run(ctx).status == PhaseStatus.ok
    return read_artifact(ctx.paths.scanner_findings, ScannerFindings).data


def test_history_only_secrets_are_high_and_redacted(ingested):
    out = _scan(*ingested)
    assert len(out.findings) == 2
    titles = sorted(f.title for f in out.findings)
    assert titles == ["AWS access key ID in git history", "Database connection string with embedded password in git history"]
    for f in out.findings:
        assert f.severity == Severity.high
        ev = f.evidence[0]
        assert ev.path == "app.py"
        assert ev.fingerprint and len(ev.fingerprint) == 12
        assert LEAKED_KEY not in (ev.excerpt or "")
        assert "hunter2" not in (ev.excerpt or "")
        assert ev.note and "commit" in ev.note
        assert f.scanner == "secrets"


def test_current_secrets_are_critical(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "settings.py").write_text(
        'API_KEY = "sk-ant-' + 'api03-abcdefghijklmnopqrstuvwxyz0123456789"\n'
        'PASSWORD = "changeme"\n'
        'db = "mysql://root:S3cret!@10.0.0.5/app"\n'
    )
    (pile / "id_rsa").write_text("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
    (pile / "safe.py").write_text('token = os.environ["TOKEN"]\nplaceholder = "<your-api-key>"\n')
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    by_title = {f.title: f for f in out.findings}
    assert "Anthropic API key" in by_title
    assert "Database connection string with embedded password" in by_title
    assert "Private key material" in by_title
    assert all(f.severity == Severity.critical for f in out.findings)
    assert not any("changeme" in (f.evidence[0].excerpt or "") for f in out.findings)
    assert not any(f.evidence[0].path == "safe.py" for f in out.findings)
    key_finding = by_title["Anthropic API key"]
    assert key_finding.evidence[0].line_start == 1
    assert "sk-a" in key_finding.evidence[0].excerpt and "abcdefghijklmnop" not in key_finding.evidence[0].excerpt


def test_scan_text_rules_and_redaction():
    text = f'x = "{LEAKED_KEY}"\ny = "{LEAKED_DB_URL}"\nz = "ghp_" + "a" * 36\n'
    matches = scan_text("f.py", text)
    rules = {m.rule for m in matches}
    assert {"aws_access_key", "connection_string"} <= rules
    m = next(m for m in matches if m.rule == "aws_access_key")
    assert m.line == 1 and m.raw == LEAKED_KEY
    red = redact(m.line_text, m.raw)
    assert LEAKED_KEY not in red and "AKIA" in red and "redacted" in red
    assert fingerprint(LEAKED_KEY) == fingerprint(LEAKED_KEY) and len(fingerprint(LEAKED_KEY)) == 12


def test_placeholders_ignored():
    assert is_placeholder("changeme")
    assert is_placeholder("<your-api-key>")
    assert is_placeholder("${SECRET}")
    assert is_placeholder("xxxxxxxxxxxx")
    assert not is_placeholder("S3cret!Value99")
    assert scan_text("f.py", 'password = "changeme"\n') == []


def test_scan_history_lines_tracks_commit_and_path():
    lines = iter([
        "\x1e" + "c" * 40,
        "diff --git a/app.py b/app.py",
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -0,0 +1 @@",
        f'+KEY = "{LEAKED_KEY}"',
        "\x1e" + "d" * 40,
        "diff --git a/other.py b/other.py",
        "+++ b/other.py",
        "-removed line with nothing",
        "+clean = 1",
    ])
    matches = scan_history_lines(lines)
    assert len(matches) == 1
    assert matches[0].commit == "c" * 40
    assert matches[0].path == "app.py"
    assert matches[0].raw == LEAKED_KEY


def test_history_scan_uses_streaming(ingested, monkeypatch):
    eng, name = ingested
    calls: list[list[str]] = []
    real = secrets_mod.git_lines

    def spy(args, cwd):
        calls.append(list(args))
        return real(args, cwd)

    monkeypatch.setattr(secrets_mod, "git_lines", spy)
    _scan(eng, name)
    assert calls and calls[0][:2] == ["log", "-p"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scanner_secrets.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `scanners/secrets.py`**

```python
# src/unvarnish/scanners/secrets.py
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.gitcmd import GitError, git_lines, is_git_repo

MAX_SCAN_BYTES = 5_000_000


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    title: str
    value_group: int = 0


RULES: list[SecretRule] = [
    SecretRule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), Severity.critical, "Anthropic API key"),
    SecretRule("openai_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b"), Severity.critical, "OpenAI API key"),
    SecretRule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.critical, "AWS access key ID"),
    SecretRule("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), Severity.critical, "GitHub token"),
    SecretRule("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), Severity.critical, "Slack token"),
    SecretRule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.critical, "Private key material",
    ),
    SecretRule(
        "connection_string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)://[^\s:/@]+:([^\s@]+)@[^\s'\"]+"),
        Severity.critical, "Database connection string with embedded password", value_group=1,
    ),
    SecretRule(
        "generic_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|auth[_-]?token|access[_-]?token|token)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        Severity.critical, "Hardcoded credential assignment", value_group=1,
    ),
]

PLACEHOLDER_WORDS = {"changeme", "change_me", "password", "secret", "example", "placeholder",
                     "your_api_key", "your-api-key", "dummy", "test", "todo", "replace_me", "xxx"}


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if v in PLACEHOLDER_WORDS:
        return True
    if v.startswith(("<", "${", "{{", "%(", "$")) or v.endswith(">"):
        return True
    if len(set(v)) <= 2:  # "xxxxxxxx", "********"
        return True
    return any(word in v for word in ("your_", "your-", "example", "changeme", "placeholder"))


def fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def redact(line_text: str, raw: str) -> str:
    keep = raw[:4] if len(raw) > 8 else ""
    return line_text.replace(raw, f"{keep}…[redacted {len(raw)} chars]").strip()[:200]


@dataclass
class SecretMatch:
    rule: str
    path: str
    line: int | None
    raw: str
    line_text: str
    commit: str | None = None


def _match_line(rule: SecretRule, path: str, lineno: int | None, text: str, commit: str | None) -> list[SecretMatch]:
    out = []
    for m in rule.pattern.finditer(text):
        raw = m.group(rule.value_group) if rule.value_group else m.group(0)
        if rule.value_group and is_placeholder(raw):
            continue
        out.append(SecretMatch(rule=rule.name, path=path, line=lineno, raw=raw, line_text=text, commit=commit))
    return out


def scan_text(path: str, text: str, commit: str | None = None) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            matches.extend(_match_line(rule, path, lineno, line, commit))
    return matches


def scan_history_lines(lines: Iterable[str]) -> list[SecretMatch]:
    """Consume a `git log -p --format=%x1e%H` stream; return matches on added lines."""
    matches: list[SecretMatch] = []
    commit: str | None = None
    path: str | None = None
    for line in lines:
        if line.startswith("\x1e"):
            commit = line[1:].strip() or None
            path = None
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and path is not None:
            content = line[1:]
            for rule in RULES:
                matches.extend(_match_line(rule, path, None, content, commit))
    return matches


def _rule(name: str) -> SecretRule:
    return next(r for r in RULES if r.name == name)


class SecretsScanner:
    name = "secrets"
    category = Category.security

    def run(self, ctx: ScanContext) -> list[Finding]:
        current: dict[str, list[SecretMatch]] = {}
        for rec in ctx.census.files:
            if rec.classification == Classification.binary or rec.bytes > MAX_SCAN_BYTES:
                continue
            if rec.exclusion_reason and (rec.exclusion_reason.startswith("vendored") or rec.exclusion_reason == "lockfile"):
                continue
            text = (ctx.source_root / rec.path).read_text(errors="replace")
            for m in scan_text(rec.path, text):
                current.setdefault(fingerprint(m.raw), []).append(m)

        history: dict[str, SecretMatch] = {}
        history_counts: dict[str, int] = {}
        if is_git_repo(ctx.source_root):
            try:
                stream = git_lines(["log", "-p", "--all", "--no-color", "--unified=0", "--format=%x1e%H"], ctx.source_root)
                for m in scan_history_lines(stream):
                    fp = fingerprint(m.raw)
                    history.setdefault(fp, m)
                    history_counts[fp] = history_counts.get(fp, 0) + 1
            except GitError:
                pass  # history unavailable; working-tree findings still stand

        findings: list[Finding] = []
        for fp, ms in current.items():
            m = ms[0]
            rule = _rule(m.rule)
            note = f"fingerprint {fp}"
            if fp in history_counts:
                note += f"; also appears in {history_counts[fp]} commit(s) in git history"
            findings.append(self._finding(ctx.tool, rule, m, fp, rule.severity, rule.title, note, extra=len(ms) - 1))

        for fp, m in history.items():
            if fp in current:
                continue
            rule = _rule(m.rule)
            sha = (m.commit or "unknown")[:12]
            note = (f"fingerprint {fp}; added in commit {sha}; removed from the working tree "
                    f"but recoverable by anyone with repository access")
            findings.append(self._finding(ctx.tool, rule, m, fp, Severity.high, f"{rule.title} in git history", note))
        return findings

    def _finding(self, tool: str, rule: SecretRule, m: SecretMatch, fp: str, severity: Severity,
                 title: str, note: str, extra: int = 0) -> Finding:
        more = f" ({extra} more occurrence(s) with the same value)" if extra else ""
        return Finding(
            tool=tool, category=self.category, severity=severity, title=title,
            summary=f"{rule.title} found in {m.path}{more}. The value is redacted here and identified by fingerprint.",
            impact=("Anyone who can read this code or its history holds a working credential. "
                    "Rotation is required regardless of whether the file is still present."),
            remediation=("Rotate the credential now. Move it to a secret manager or environment variable. "
                         "Purge it from git history (git filter-repo) before the repository moves anywhere."),
            evidence=[Evidence(path=m.path, line_start=m.line, line_end=m.line,
                               excerpt=redact(m.line_text, m.raw), fingerprint=fp, note=note)],
            source=Source.scanner, scanner=self.name, tags=[rule.name],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_scanner_secrets.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/unvarnish/scanners/secrets.py tests/test_scanner_secrets.py
git commit -m "feat: secrets scanner over working tree and full git history with redaction"
```

---

### Task 13: Oversized-files and hygiene scanners

**Files:**
- Create: `src/unvarnish/scanners/oversized_files.py`, `src/unvarnish/scanners/hygiene.py`, `tests/test_scanner_oversized.py`, `tests/test_scanner_hygiene.py`

**Interfaces:**
- Consumes: `ScanContext` (Task 11), `FileMetrics` (Task 7), `Census, FileRecord` (Task 9), `Classification` (Task 6), `Finding` (Task 3).
- Produces: `class OversizedFilesScanner` (`name = "oversized_files"`, `category = Category.maintainability`; options `file_lines`, `function_lines`, `html_script_lines`); `class HygieneScanner` (`name = "hygiene"`, `category = Category.process`; constants `CI_PATHS`, `LINTER_CONFIGS`, `TODO_RE`, `TODO_PER_KLOC_THRESHOLD = 5`, `EMPTY_HANDLER_PATTERNS: dict[str, re.Pattern]`).

- [ ] **Step 1: Write the failing oversized tests**

```python
# tests/test_scanner_oversized.py
from pathlib import Path

from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.oversized_files import OversizedFilesScanner
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    FileMetrics,
    HtmlBreakdown,
    Metrics,
)


def _ctx(files: list[FileMetrics], options: dict | None = None) -> ScanContext:
    return ScanContext(
        tool="t", source_root=Path("."),
        census=Census(tool="t", files=[], totals=CensusTotals()),
        metrics=Metrics(tool="t", files=files),
        git=GitStats(tool="t", available=False),
        dependencies=Dependencies(tool="t", dependencies=[]),
        options=options or {"file_lines": 1500, "function_lines": 150, "html_script_lines": 500},
    )


def test_flags_oversized_file_and_function():
    fm = FileMetrics(path="app.py", lines=3010, bytes=1, functions=2, max_function_lines=3002,
                     max_function_name="process_everything", metrics_method="treesitter")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    titles = {f.title: f for f in findings}
    assert titles["Oversized file"].severity == Severity.high
    assert titles["Oversized file"].evidence[0].path == "app.py"
    assert "3,010" in titles["Oversized file"].summary
    assert titles["Oversized function"].severity == Severity.high  # > 5x threshold
    assert "process_everything" in titles["Oversized function"].summary


def test_function_just_over_threshold_is_medium():
    fm = FileMetrics(path="a.py", lines=200, bytes=1, functions=1, max_function_lines=160,
                     max_function_name="f", metrics_method="treesitter")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    assert [f.severity for f in findings] == [Severity.medium]


def test_html_inline_script_threshold():
    bd = HtmlBreakdown(markup_lines=100, script_lines=900, style_lines=50, markup_bytes=1,
                       script_bytes=1, style_bytes=1, script_blocks=3, style_blocks=1)
    fm = FileMetrics(path="index.html", lines=1050, bytes=1, html=bd, metrics_method="lines")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    assert [f.title for f in findings] == ["Inline script in HTML exceeds threshold"]
    assert "900" in findings[0].summary and "3 script" in findings[0].summary


def test_nothing_flagged_under_thresholds():
    fm = FileMetrics(path="ok.py", lines=10, bytes=1, functions=1, max_function_lines=5,
                     max_function_name="f", metrics_method="treesitter")
    assert OversizedFilesScanner().run(_ctx([fm])) == []
```

- [ ] **Step 2: Write the failing hygiene tests**

```python
# tests/test_scanner_hygiene.py
from pathlib import Path

from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.artifacts import read_artifact
from unvarnish.scanners.hygiene import HygieneScanner
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.scan import ScannerFindings


def _scan(eng: Engagement, name: str) -> ScannerFindings:
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert ScanPhase(scanners=[HygieneScanner()]).run(ctx).status == PhaseStatus.ok
    return read_artifact(ctx.paths.scanner_findings, ScannerFindings).data


def test_synthetic_repo_hygiene(ingested):
    out = _scan(*ingested)
    titles = {f.title for f in out.findings}
    assert "No automated tests" in titles
    assert "No continuous integration configuration" in titles
    assert "No license file" in titles
    assert "No linter or formatter configuration" in titles
    assert "No README" not in titles
    tests_f = next(f for f in out.findings if f.title == "No automated tests")
    assert tests_f.severity == Severity.medium and tests_f.category == Category.process
    assert tests_f.evidence[0].path == "."


def test_well_kept_tool_has_no_hygiene_findings(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "tests").mkdir(parents=True)
    (pile / ".github" / "workflows").mkdir(parents=True)
    (pile / "src").mkdir()
    (pile / "README.md").write_text("# ok\n")
    (pile / "LICENSE").write_text("MIT\n")
    (pile / "ruff.toml").write_text("line-length = 100\n")
    (pile / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    (pile / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")
    (pile / "src" / "x.py").write_text("def x():\n    return 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    assert out.findings == []


def test_todo_density_and_empty_handlers(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text(
        "# TODO one\n# FIXME two\n# HACK three\n"
        "try:\n    x = 1\nexcept:\n    pass\n"
        "try:\n    y = 2\nexcept Exception:\n    pass\n"
    )
    (pile / "b.js").write_text("try { f(); } catch (e) {}\ntry { g(); } catch (err) { }\n")
    (pile / "c.go").write_text("x, err := f()\nif err != nil {\n}\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    by_title = {f.title: f for f in out.findings}
    todo = by_title["High density of TODO/FIXME/HACK markers"]
    assert todo.severity == Severity.low
    assert len(todo.evidence) == 3
    empty = by_title["Swallowed errors"]
    assert empty.severity == Severity.medium and empty.category == Category.reliability
    paths = sorted({e.path for e in empty.evidence})
    assert paths == ["a.py", "b.js", "c.go"]
    assert len(empty.evidence) == 5
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_scanner_oversized.py tests/test_scanner_hygiene.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Implement `scanners/oversized_files.py`**

```python
# src/unvarnish/scanners/oversized_files.py
from __future__ import annotations

from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source


class OversizedFilesScanner:
    name = "oversized_files"
    category = Category.maintainability

    def run(self, ctx: ScanContext) -> list[Finding]:
        file_lines = int(ctx.options.get("file_lines", 1500))
        function_lines = int(ctx.options.get("function_lines", 150))
        script_lines = int(ctx.options.get("html_script_lines", 500))
        findings: list[Finding] = []

        for fm in ctx.metrics.files:
            if fm.html is not None:
                if fm.html.script_lines > script_lines:
                    findings.append(Finding(
                        tool=ctx.tool, category=self.category, severity=Severity.high,
                        title="Inline script in HTML exceeds threshold",
                        summary=(f"{fm.path} embeds {fm.html.script_lines:,} lines of JavaScript across "
                                 f"{fm.html.script_blocks} script block(s) and {fm.html.style_lines:,} lines of CSS, "
                                 f"in a file of {fm.lines:,} lines (threshold {script_lines:,})."),
                        impact=("Application logic inside an HTML file cannot be linted, tested, or reviewed with "
                                "standard tooling, and every change risks the whole page."),
                        remediation="Move scripts and styles into separate files under a build step; split by feature.",
                        evidence=[Evidence(path=fm.path, line_start=1, line_end=fm.lines)],
                        source=Source.scanner, scanner=self.name,
                    ))
                continue

            if fm.lines > file_lines:
                findings.append(Finding(
                    tool=ctx.tool, category=self.category, severity=Severity.high,
                    title="Oversized file",
                    summary=f"{fm.path} is {fm.lines:,} lines (threshold {file_lines:,}).",
                    impact=("Files this large are not readable in one sitting, hide duplicated logic, and make "
                            "ownership and review impractical."),
                    remediation="Split by responsibility into modules of a few hundred lines each.",
                    evidence=[Evidence(path=fm.path, line_start=1, line_end=fm.lines)],
                    source=Source.scanner, scanner=self.name,
                ))

            if fm.max_function_lines and fm.max_function_lines > function_lines:
                severity = Severity.high if fm.max_function_lines > 5 * function_lines else Severity.medium
                findings.append(Finding(
                    tool=ctx.tool, category=self.category, severity=severity,
                    title="Oversized function",
                    summary=(f"{fm.max_function_name or 'a function'} in {fm.path} is "
                             f"{fm.max_function_lines:,} lines (threshold {function_lines:,})."),
                    impact="A function this long cannot be unit tested or reasoned about; defects hide in it.",
                    remediation="Extract cohesive steps into named functions with their own tests.",
                    evidence=[Evidence(path=fm.path, note=f"longest function: {fm.max_function_name}")],
                    source=Source.scanner, scanner=self.name,
                ))
        return findings
```

- [ ] **Step 5: Implement `scanners/hygiene.py`**

```python
# src/unvarnish/scanners/hygiene.py
from __future__ import annotations

import re

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source

CI_PATHS = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
            ".circleci", "bitbucket-pipelines.yml", ".travis.yml", "cloudbuild.yaml"]
LINTER_CONFIGS = ["ruff.toml", ".ruff.toml", ".flake8", "setup.cfg", "tox.ini", ".pylintrc",
                  ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs", "eslint.config.js",
                  "eslint.config.mjs", "biome.json", ".prettierrc", ".golangci.yml", ".golangci.yaml",
                  "rustfmt.toml", ".rustfmt.toml", "clippy.toml", "checkstyle.xml", ".editorconfig",
                  ".stylelintrc", "phpcs.xml", ".rubocop.yml"]
README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}
LICENSE_NAMES = {"license", "license.md", "license.txt", "licence", "licence.md", "copying"}
TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
TODO_PER_KLOC_THRESHOLD = 5
MAX_EVIDENCE = 20

EMPTY_HANDLER_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"^\s*except(?:\s+[\w.(), ]+)?\s*:\s*\n\s*pass\b", re.MULTILINE),
    "javascript": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "typescript": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "tsx": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "java": re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"),
    "c_sharp": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "go": re.compile(r"if\s+err\s*!=\s*nil\s*\{\s*\}"),
}


def _pyproject_has_linter(ctx: ScanContext) -> bool:
    p = ctx.source_root / "pyproject.toml"
    if not p.exists():
        return False
    text = p.read_text(errors="replace")
    return any(k in text for k in ("[tool.ruff", "[tool.black", "[tool.flake8", "[tool.pylint", "[tool.mypy"))


class HygieneScanner:
    name = "hygiene"
    category = Category.process

    def _presence(self, ctx: ScanContext, title: str, severity: Severity, category: Category,
                  summary: str, impact: str, remediation: str) -> Finding:
        return Finding(tool=ctx.tool, category=category, severity=severity, title=title, summary=summary,
                       impact=impact, remediation=remediation, evidence=[Evidence(path=".", note="repository root")],
                       source=Source.scanner, scanner=self.name)

    def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.source_root
        files = [f for f in ctx.census.files if not f.excluded]
        names_lower = {f.path.lower() for f in files}
        findings: list[Finding] = []

        if not any(f.classification == Classification.test for f in files):
            findings.append(self._presence(
                ctx, "No automated tests", Severity.medium, Category.process,
                "The tool has no test files of any kind.",
                "Every change is verified by hand or not at all; regressions reach users.",
                "Add a test runner and cover the main paths before any further change.",
            ))
        if not any((root / p).exists() for p in CI_PATHS):
            findings.append(self._presence(
                ctx, "No continuous integration configuration", Severity.medium, Category.process,
                "No CI pipeline definition was found.",
                "Nothing runs tests, linting, or builds automatically; quality depends on individual discipline.",
                "Add a pipeline that runs tests and linting on every push.",
            ))
        if not any(n in names_lower for n in README_NAMES):
            findings.append(self._presence(
                ctx, "No README", Severity.low, Category.process,
                "No README describes what the tool is or how to run it.",
                "Knowledge lives only in the author's head.",
                "Write a README covering purpose, setup, and operation.",
            ))
        if not any(n in names_lower for n in LICENSE_NAMES):
            findings.append(self._presence(
                ctx, "No license file", Severity.low, Category.compliance,
                "No license or ownership statement is present.",
                "Ownership and permitted use of the code are undefined, which matters once it is shared or handed over.",
                "Add an internal-use license or ownership notice agreed with legal.",
            ))
        if not any((root / c).exists() for c in LINTER_CONFIGS) and not _pyproject_has_linter(ctx):
            findings.append(self._presence(
                ctx, "No linter or formatter configuration", Severity.low, Category.maintainability,
                "No linting or formatting configuration was found.",
                "Style and common defects are not checked automatically.",
                "Adopt the standard linter for the language and run it in CI.",
            ))

        # TODO density and swallowed errors over source files
        source_files = [f for f in files if f.classification in (Classification.source, Classification.test)
                        and f.language]
        total_lines = sum(f.lines for f in source_files) or 1
        todo_evidence: list[Evidence] = []
        handler_evidence: list[Evidence] = []
        todo_count = 0
        for f in source_files:
            text = (root / f.path).read_text(errors="replace")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if TODO_RE.search(line):
                    todo_count += 1
                    if len(todo_evidence) < MAX_EVIDENCE:
                        todo_evidence.append(Evidence(path=f.path, line_start=lineno, excerpt=line.strip()[:120]))
            pattern = EMPTY_HANDLER_PATTERNS.get(f.language or "")
            if pattern:
                for m in pattern.finditer(text):
                    if len(handler_evidence) >= MAX_EVIDENCE:
                        break
                    lineno = text.count("\n", 0, m.start()) + 1
                    handler_evidence.append(Evidence(path=f.path, line_start=lineno, excerpt=m.group(0).strip()[:120]))

        if todo_evidence and (todo_count * 1000 / total_lines) > TODO_PER_KLOC_THRESHOLD:
            findings.append(Finding(
                tool=ctx.tool, category=Category.maintainability, severity=Severity.low,
                title="High density of TODO/FIXME/HACK markers",
                summary=f"{todo_count} unresolved markers across {total_lines:,} source lines.",
                impact="Known gaps are documented only as comments and will be forgotten.",
                remediation="Convert markers into tracked issues or resolve them.",
                evidence=todo_evidence, source=Source.scanner, scanner=self.name,
            ))
        if handler_evidence:
            findings.append(Finding(
                tool=ctx.tool, category=Category.reliability, severity=Severity.medium,
                title="Swallowed errors",
                summary=f"{len(handler_evidence)} empty exception or error handlers discard failures silently.",
                impact="Failures go unnoticed; data may be lost or corrupted without any signal.",
                remediation="Log and surface errors, or handle them explicitly with a documented reason.",
                evidence=handler_evidence, source=Source.scanner, scanner=self.name,
            ))
        return findings
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_scanner_oversized.py tests/test_scanner_hygiene.py -v`
Expected: PASS (7 tests)

- [ ] **Step 7: Commit**

```bash
git add src/unvarnish/scanners/oversized_files.py src/unvarnish/scanners/hygiene.py tests/test_scanner_oversized.py tests/test_scanner_hygiene.py
git commit -m "feat: oversized-files and hygiene scanners"
```

---

### Task 14: Bus-factor scanner and built-in registry

**Files:**
- Create: `src/unvarnish/scanners/bus_factor.py`, `tests/test_scanner_bus_factor.py`
- Modify: `src/unvarnish/scanners/__init__.py` (`builtin_scanners`)

**Interfaces:**
- Consumes: `GitStats, AuthorStats` (Task 10), `ScanContext` (Task 11).
- Produces: `class BusFactorScanner` (`name = "bus_factor"`, `category = Category.process`; option `single_author_share`). `builtin_scanners()` now returns `[SecretsScanner(), OversizedFilesScanner(), HygieneScanner(), BusFactorScanner()]` in that order.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scanner_bus_factor.py
from pathlib import Path

from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.bus_factor import BusFactorScanner
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import AuthorStats, GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics


def _ctx(git: GitStats, share: float = 0.9) -> ScanContext:
    return ScanContext(
        tool="t", source_root=Path("."), census=Census(tool="t", files=[], totals=CensusTotals()),
        metrics=Metrics(tool="t", files=[]), git=git, dependencies=Dependencies(tool="t", dependencies=[]),
        options={"single_author_share": share},
    )


def _git(shares: list[float], commits: int = 10) -> GitStats:
    authors = [AuthorStats(name=f"A{i}", email=f"a{i}@x", commits=max(commits // len(shares), 1),
                           lines_changed=int(s * 1000), share=s) for i, s in enumerate(shares)]
    cumulative, bus = 0.0, 0
    for a in authors:
        cumulative += a.share
        bus += 1
        if cumulative >= 0.8:
            break
    return GitStats(tool="t", available=True, commit_count=commits, authors=authors, bus_factor=bus,
                    top_author_share=shares[0])


def test_single_author_concentration_is_high():
    findings = BusFactorScanner().run(_ctx(_git([0.97, 0.03])))
    assert [f.title for f in findings] == ["Single-author concentration"]
    assert findings[0].severity == Severity.high
    assert "97%" in findings[0].summary
    assert findings[0].evidence[0].path == "."


def test_low_bus_factor_is_medium():
    findings = BusFactorScanner().run(_ctx(_git([0.85, 0.10, 0.05])))
    assert [f.title for f in findings] == ["Low bus factor"]
    assert findings[0].severity == Severity.medium


def test_balanced_team_has_no_finding():
    assert BusFactorScanner().run(_ctx(_git([0.4, 0.35, 0.25]))) == []


def test_skips_without_history():
    assert BusFactorScanner().run(_ctx(GitStats(tool="t", available=False))) == []
    assert BusFactorScanner().run(_ctx(_git([1.0], commits=1))) == []


def test_builtin_registry_order():
    assert [s.name for s in builtin_scanners()] == ["secrets", "oversized_files", "hygiene", "bus_factor"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scanner_bus_factor.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `scanners/bus_factor.py`**

```python
# src/unvarnish/scanners/bus_factor.py
from __future__ import annotations

from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source


class BusFactorScanner:
    name = "bus_factor"
    category = Category.process

    def run(self, ctx: ScanContext) -> list[Finding]:
        g = ctx.git
        if not g.available or g.commit_count < 2 or not g.authors:
            return []
        threshold = float(ctx.options.get("single_author_share", 0.9))
        top = g.authors[0]
        shares = ", ".join(f"{a.name} {a.share:.0%}" for a in g.authors[:5])
        evidence = [Evidence(path=".", note=f"{g.commit_count} commits; shares by changed lines: {shares}")]

        if top.share > threshold:
            return [Finding(
                tool=ctx.tool, category=self.category, severity=Severity.high,
                title="Single-author concentration",
                summary=(f"{top.name} authored {top.share:.0%} of all changed lines across {g.commit_count} "
                         f"commits; {len(g.authors)} author(s) in total (threshold {threshold:.0%})."),
                impact=("Knowledge of how this tool works lives with one person. If they leave or are "
                        "unavailable, nobody can safely change or operate it."),
                remediation="Pair a second maintainer with the author now and document the design before handover.",
                evidence=evidence, source=Source.scanner, scanner=self.name,
            )]
        if g.bus_factor == 1 and len(g.authors) > 1:
            return [Finding(
                tool=ctx.tool, category=self.category, severity=Severity.medium,
                title="Low bus factor",
                summary=(f"One author ({top.name}, {top.share:.0%}) accounts for at least 80% of changes; "
                         f"{len(g.authors)} author(s) in total."),
                impact="Most knowledge of the tool sits with one person.",
                remediation="Spread ownership through reviews and shared on-call before relying on this tool.",
                evidence=evidence, source=Source.scanner, scanner=self.name,
            )]
        return []
```

- [ ] **Step 4: Register the built-ins**

Replace `builtin_scanners` in `src/unvarnish/scanners/__init__.py`:

```python
def builtin_scanners() -> list[Scanner]:
    from unvarnish.scanners.bus_factor import BusFactorScanner
    from unvarnish.scanners.hygiene import HygieneScanner
    from unvarnish.scanners.oversized_files import OversizedFilesScanner
    from unvarnish.scanners.secrets import SecretsScanner

    return [SecretsScanner(), OversizedFilesScanner(), HygieneScanner(), BusFactorScanner()]
```

(Imports are inside the function to avoid import cycles between `scanners.base` and the scanner modules.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_scanner_bus_factor.py tests/test_scan_phase.py -v`
Expected: PASS (9 tests)

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/scanners/bus_factor.py src/unvarnish/scanners/__init__.py tests/test_scanner_bus_factor.py
git commit -m "feat: bus-factor scanner and built-in scanner registry"
```

---

### Task 15: Render phase and findings template

**Files:**
- Create: `src/unvarnish/render/__init__.py`, `src/unvarnish/render/markdown.py`, `src/unvarnish/render/findings.py`, `src/unvarnish/render/templates/findings.md.j2`, `src/unvarnish/schemas/render.py`, `src/unvarnish/phases/render.py`, `tests/test_render.py`

**Interfaces:**
- Consumes: all inventory/git/scan artifacts; `user_config_path` (Task 4); `SEVERITY_ORDER` (Task 3).
- Produces (`unvarnish.render.markdown`):
  - `make_env(override_dirs: Sequence[Path] = ()) -> jinja2.Environment` (ChoiceLoader: overrides first, then the package `templates/`; `StrictUndefined`; filters `fmt_int`, `pct`)
  - `render_document(env, template_name: str, context: dict) -> str`
  - `template_source_hash(env, template_name: str) -> str`
  - `fmt_int(v: int | None) -> str` (`"3,010"`, `"—"` for `None`), `pct(v: float | None) -> str` (`"97%"`)
- Produces (`unvarnish.render.findings`): `build_findings_context(ctx: ToolContext, census: Census, metrics: Metrics, git: GitStats, deps: Dependencies, scan: ScannerFindings) -> dict`
- Produces (`unvarnish.schemas.render`): `class RenderState(BaseModel)`: `tool: str`, `documents: dict[str, str]` (filename → sha256 of content)
- Produces (`unvarnish.phases.render`): `class RenderPhase` (`name = "render"`, `TEMPLATE = "findings.md.j2"`), `template_override_dirs(ctx) -> list[Path]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_render.py
from pathlib import Path

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.render import RenderPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.render.markdown import fmt_int, make_env, pct
from unvarnish.schemas.render import RenderState
from tests.conftest import LEAKED_DB_URL, LEAKED_KEY


def _render(eng: Engagement, name: str) -> tuple[str, object]:
    ctx = build_context(eng, name)
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    return ctx.paths.findings_doc.read_text(), ctx


def test_filters():
    assert fmt_int(3010) == "3,010"
    assert fmt_int(None) == "—"
    assert pct(0.966) == "97%"
    assert pct(None) == "—"


def test_findings_document_content(ingested):
    doc, ctx = _render(*ingested)
    assert doc.startswith("# expense-bot: Findings")
    assert "Acme" in doc and "Bonham Technologies" in doc
    assert "## By the numbers" in doc
    assert "## Findings" in doc
    for title in ("AWS access key ID in git history", "Oversized file", "Oversized function",
                  "Single-author concentration", "No automated tests"):
        assert title in doc, title
    assert "### Critical" not in doc  # synthetic repo has history-only secrets, which are high
    assert "### High" in doc
    assert "## Not analysed" in doc
    assert "vendored:node_modules" in doc and "node_modules/leftpad/index.js" in doc
    assert "CLAUDE.md" in doc  # AI tooling indicator row
    assert LEAKED_KEY not in doc and "hunter2" not in doc and LEAKED_DB_URL not in doc
    assert "Dependency vulnerabilities | not checked" in doc


def test_render_state_and_freshness(ingested):
    doc, ctx = _render(*ingested)
    state = read_artifact(ctx.paths.render_state, RenderState).data
    assert "findings.md" in state.documents
    assert is_fresh(RenderPhase(), ctx)
    results = PhaseRunner([RenderPhase()]).run(ctx)
    assert results[0].status == PhaseStatus.skipped


def test_template_override(ingested):
    eng, name = ingested
    tdir = eng.root / "templates"
    tdir.mkdir()
    (tdir / "findings.md.j2").write_text("CUSTOM {{ tool.name }} {{ numbers.total_findings }}\n")
    doc, ctx = _render(eng, name)
    assert doc.startswith("CUSTOM expense-bot ")
    # changing the template invalidates freshness
    (tdir / "findings.md.j2").write_text("OTHER {{ tool.name }}\n")
    assert not is_fresh(RenderPhase(), ctx)


def test_make_env_strict_undefined():
    import pytest
    from jinja2 import StrictUndefined, UndefinedError

    env = make_env()
    assert env.undefined is StrictUndefined
    with pytest.raises(UndefinedError):
        env.from_string("{{ nope }}").render()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_render.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `schemas/render.py` and `render/markdown.py`**

```python
# src/unvarnish/schemas/render.py
from __future__ import annotations

from pydantic import BaseModel, Field


class RenderState(BaseModel):
    tool: str
    documents: dict[str, str] = Field(default_factory=dict)
```

```python
# src/unvarnish/render/__init__.py
```
(empty file)

```python
# src/unvarnish/render/markdown.py
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader, StrictUndefined

from unvarnish.artifacts import hash_inputs


def fmt_int(v: int | None) -> str:
    return "—" if v is None else f"{v:,}"


def pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


def make_env(override_dirs: Sequence[Path] = ()) -> Environment:
    loaders = [FileSystemLoader(str(d)) for d in override_dirs if d.is_dir()]
    loaders.append(PackageLoader("unvarnish.render", "templates"))
    env = Environment(
        loader=ChoiceLoader(loaders),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
    )
    env.filters["fmt_int"] = fmt_int
    env.filters["pct"] = pct
    return env


def render_document(env: Environment, template_name: str, context: dict) -> str:
    return env.get_template(template_name).render(**context)


def template_source_hash(env: Environment, template_name: str) -> str:
    assert env.loader is not None
    source, _, _ = env.loader.get_source(env, template_name)
    return hash_inputs([template_name, source])
```

- [ ] **Step 4: Implement `render/findings.py`**

```python
# src/unvarnish/render/findings.py
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from unvarnish.analysis.languages import Classification
from unvarnish.phases.base import ToolContext
from unvarnish.schemas.finding import SEVERITY_ORDER, Finding, Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings

EXAMPLES_PER_REASON = 5


def _severity_groups(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    groups: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.severity].append(f)
    return [(sev.value, groups[sev]) for sev in sorted(groups, key=SEVERITY_ORDER.__getitem__)]


def build_findings_context(ctx: ToolContext, census: Census, metrics: Metrics, git: GitStats,
                           deps: Dependencies, scan: ScannerFindings) -> dict:
    live = [f for f in census.files if not f.excluded]
    analysed = [f for f in live if f.classification != Classification.binary]
    source_lines = sum(f.lines for f in live if f.classification == Classification.source)
    largest = sorted(metrics.files, key=lambda m: -m.lines)[:5]
    longest = max((m for m in metrics.files if m.max_function_lines), key=lambda m: m.max_function_lines or 0, default=None)
    languages = sorted(census.languages.items(), key=lambda kv: -kv[1])[:5]

    secrets = [f for f in scan.findings if f.scanner == "secrets"]
    secrets_history = [f for f in secrets if f.title.endswith("in git history")]
    by_sev = [(sev.value, n) for sev in Severity if (n := sum(1 for f in scan.findings if f.severity == sev))]

    excluded: dict[str, list[str]] = defaultdict(list)
    for f in census.files:
        if f.excluded and f.exclusion_reason:
            excluded[f.exclusion_reason].append(f.path)
    not_analysed = [
        {"reason": reason, "count": len(paths), "examples": paths[:EXAMPLES_PER_REASON]}
        for reason, paths in sorted(excluded.items())
    ]
    binaries = [f.path for f in live if f.classification == Classification.binary]

    ai = git.ai_fingerprints
    ai_indicators = list(ai.files) + [f"Co-Authored-By {name} ×{n}" for name, n in ai.coauthor_trailers.items()]
    if ai.message_patterns:
        ai_indicators.append(f"{ai.message_patterns} commit message(s) mention AI generation")

    return {
        "tool": ctx.meta,
        "client": ctx.config.client,
        "consultant": ctx.config.consultant,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "census": census,
        "metrics": metrics,
        "git": git,
        "deps": deps,
        "scan": scan,
        "severity_groups": _severity_groups(scan.findings),
        "numbers": {
            "total_findings": len(scan.findings),
            "by_severity": by_sev,
            "critical_or_high": sum(1 for f in scan.findings if f.severity in (Severity.critical, Severity.high)),
            "analysed_files": len(analysed),
            "source_lines": source_lines,
            "largest_files": largest,
            "largest_file": largest[0] if largest else None,
            "longest_function": longest,
            "languages": languages,
            "tests_present": any(f.classification == Classification.test for f in live),
            "secrets_current": len(secrets) - len(secrets_history),
            "secrets_history": len(secrets_history),
            "ai_indicators": ai_indicators,
        },
        "not_analysed": not_analysed,
        "binaries": binaries,
    }
```

- [ ] **Step 5: Write the template**

```jinja
{# src/unvarnish/render/templates/findings.md.j2 #}
# {{ tool.name }}: Findings

**Client:** {{ client or "—" }} · **Prepared by:** {{ consultant or "—" }} · **Generated:** {{ generated_at }}
**Source:** {{ tool.origin_kind }} `{{ tool.origin }}`{% if tool.commit %} at `{{ tool.commit[:12] }}`{% endif %}

> Produced by Unvarnish's deterministic scanners. Every finding below is reproducible and traceable to a
> file and line. Model-assisted analysis was not run for this document.

## Summary

{{ numbers.total_findings }} finding(s){% if numbers.by_severity %}: {% for sev, n in numbers.by_severity %}{{ n }} {{ sev }}{{ ", " if not loop.last }}{% endfor %}{% endif %}.
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
No findings from the deterministic scanners.
{% endif %}
{% for sev, group in severity_groups %}
### {{ sev | capitalize }} ({{ group | length }})

{% for f in group %}
#### {{ f.title }}

`{{ f.category }}` · source: {{ f.source }}{% if f.scanner %} ({{ f.scanner }}){% endif %} · id `{{ f.id }}`

{{ f.summary }}

**Impact.** {{ f.impact }}

**Remediation.** {{ f.remediation }}

**Evidence.**
{% for e in f.evidence %}
- `{{ e.path }}{% if e.line_start %}:{{ e.line_start }}{% if e.line_end and e.line_end != e.line_start %}-{{ e.line_end }}{% endif %}{% endif %}`{% if e.excerpt %} — `{{ e.excerpt }}`{% endif %}{% if e.note %} ({{ e.note }}){% endif %}
{% endfor %}

{% endfor %}
{% endfor %}
## Not analysed

{% if not_analysed %}
Excluded from analysis but counted in totals:

{% for group in not_analysed %}
- **{{ group.reason }}**: {{ group.count }} file(s){% if group.examples %} — e.g. {% for p in group.examples %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}{% endif %}
{% endfor %}
{% endif %}
{% if binaries %}
Binary files ({{ binaries | length }}): {% for p in binaries[:10] %}`{{ p }}`{{ ", " if not loop.last }}{% endfor %}{% if binaries | length > 10 %}, …{% endif %}
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
{% if not git.available %}
Git history was not analysed: {{ git.reason }}.
{% endif %}
{% if not not_analysed and not binaries and not census.failures and not scan.skipped and git.available %}
Everything in the source tree was analysed.
{% endif %}
```

- [ ] **Step 6: Implement `phases/render.py`**

```python
# src/unvarnish/phases/render.py
from __future__ import annotations

import hashlib
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import user_config_path
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.render.findings import build_findings_context
from unvarnish.render.markdown import make_env, render_document, template_source_hash
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.render import RenderState
from unvarnish.schemas.scan import ScannerFindings


def template_override_dirs(ctx: ToolContext) -> list[Path]:
    dirs = [ctx.engagement.root / "templates"]
    if ctx.config.report.templates_dir:
        dirs.append(Path(ctx.config.report.templates_dir))
    dirs.append(user_config_path().parent / "templates")
    return dirs


class RenderPhase:
    name = "render"
    TEMPLATE = "findings.md.j2"

    def _env(self, ctx: ToolContext):
        return make_env(template_override_dirs(ctx))

    def _inputs(self, ctx: ToolContext) -> list[Path]:
        p = ctx.paths
        return [p.census, p.metrics, p.git, p.dependencies, p.scanner_findings]

    def inputs_hash(self, ctx: ToolContext) -> str:
        return hash_inputs([
            hash_files(self._inputs(ctx)),
            template_source_hash(self._env(ctx), self.TEMPLATE),
            ctx.config.client or "", ctx.config.consultant or "", ctx.config.report.tone,
        ])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.render_state, ctx.paths.findings_doc]

    def run(self, ctx: ToolContext) -> PhaseResult:
        p = ctx.paths
        census = read_artifact(p.census, Census).data
        metrics = read_artifact(p.metrics, Metrics).data
        git = read_artifact(p.git, GitStats).data
        deps = read_artifact(p.dependencies, Dependencies).data
        scan = read_artifact(p.scanner_findings, ScannerFindings).data

        context = build_findings_context(ctx, census, metrics, git, deps, scan)
        doc = render_document(self._env(ctx), self.TEMPLATE, context)
        p.docs.mkdir(parents=True, exist_ok=True)
        p.findings_doc.write_text(doc)
        state = RenderState(tool=ctx.tool, documents={
            p.findings_doc.name: hashlib.sha256(doc.encode("utf-8")).hexdigest(),
        })
        write_artifact(p.render_state, state, produced_by=self.name, inputs_hash=self.inputs_hash(ctx))
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, message=f"wrote {p.findings_doc.name}")
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_render.py -v`
Expected: PASS (5 tests). If `test_findings_document_content` fails on a title, print the document (`print(doc)`) and check whether the scanner or the template is at fault before editing either.

- [ ] **Step 8: Commit**

```bash
git add src/unvarnish/render src/unvarnish/schemas/render.py src/unvarnish/phases/render.py tests/test_render.py
git commit -m "feat: render phase producing scanner-only findings.md from JSON artifacts"
```

---

### Task 16: `run`, `status`, `scanners list` commands and end-to-end test

**Files:**
- Modify: `src/unvarnish/phases/__init__.py`, `src/unvarnish/cli.py`
- Create: `tests/test_cli_run.py`

**Interfaces:**
- Produces (`unvarnish.phases`): `default_phases() -> list[Phase]` returning `[InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]`.
- CLI: `unvarnish run [TOOL ...] [--phase P] [--force] [--dry-run] [-e DIR]`, `unvarnish status [-e DIR]`, `unvarnish scanners list [-e DIR]`. Exit codes per Global Constraints.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli_run.py
from pathlib import Path

from typer.testing import CliRunner

from unvarnish.cli import app

runner = CliRunner()


def _setup(tmp_path: Path, synthetic_repo: Path) -> Path:
    eng = tmp_path / "acme"
    assert runner.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = runner.invoke(app, ["add", "expense-bot", "--repo", str(synthetic_repo), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    return eng


def test_end_to_end_run(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    for phase in ("inventory", "git", "scan", "render"):
        assert phase in r.output
    doc = (eng / "tools" / "expense-bot" / "docs" / "findings.md").read_text()
    assert "Single-author concentration" in doc

    again = runner.invoke(app, ["run", "-e", str(eng)])
    assert again.exit_code == 0
    assert again.output.count("fresh") == 4

    forced = runner.invoke(app, ["run", "expense-bot", "--phase", "scan", "--force", "-e", str(eng)])
    assert forced.exit_code == 0, forced.output
    assert "scan" in forced.output and "inventory" not in forced.output


def test_dry_run_and_unknown_phase(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    dry = runner.invoke(app, ["run", "--dry-run", "-e", str(eng)])
    assert dry.exit_code == 0, dry.output
    assert "inventory" in dry.output
    assert not (eng / "tools" / "expense-bot" / "inventory" / "census.json").exists()
    bad = runner.invoke(app, ["run", "--phase", "nope", "-e", str(eng)])
    assert bad.exit_code == 2
    assert "unknown phase" in bad.output


def test_run_unknown_tool_and_empty_engagement(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    r = runner.invoke(app, ["run", "ghost", "-e", str(eng)])
    assert r.exit_code == 2 and "ghost" in r.output
    empty = tmp_path / "empty"
    assert runner.invoke(app, ["init", str(empty)]).exit_code == 0
    r2 = runner.invoke(app, ["run", "-e", str(empty)])
    assert r2.exit_code == 2 and "no tools" in r2.output


def test_status(tmp_path: Path, synthetic_repo: Path):
    eng = _setup(tmp_path, synthetic_repo)
    before = runner.invoke(app, ["status", "-e", str(eng)])
    assert before.exit_code == 0 and "missing" in before.output
    assert runner.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    after = runner.invoke(app, ["status", "-e", str(eng)])
    assert after.exit_code == 0
    assert "missing" not in after.output and after.output.count("fresh") == 4


def test_scanners_list(tmp_path: Path):
    r = runner.invoke(app, ["scanners", "list"])
    assert r.exit_code == 0
    for name in ("secrets", "oversized_files", "hygiene", "bus_factor"):
        assert name in r.output
    assert "file_lines" in r.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli_run.py -v`
Expected: FAIL (`run` is not a registered command; `No such command`)

- [ ] **Step 3: Implement `default_phases`**

```python
# src/unvarnish/phases/__init__.py
from __future__ import annotations

from unvarnish.phases.base import Phase


def default_phases() -> list[Phase]:
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    return [InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]
```

- [ ] **Step 4: Add `run`, `status`, and `scanners list` to the CLI**

Append to `src/unvarnish/cli.py` (and hoist imports to the top):

```python
from rich.table import Table

from unvarnish.config import EngagementConfig
from unvarnish.phases import default_phases
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.scanners import load_scanners


def _select_tools(eng: Engagement, tools: list[str] | None) -> list[str]:
    known = eng.tool_names()
    if not known:
        err_console.print("[red]error:[/red] no tools in this engagement; use [cyan]unvarnish add[/cyan] first")
        raise typer.Exit(code=2)
    if not tools:
        return known
    unknown = [t for t in tools if t not in known]
    if unknown:
        err_console.print(f"[red]error:[/red] unknown tool(s): {', '.join(unknown)}; known: {', '.join(known)}")
        raise typer.Exit(code=2)
    return list(tools)


@app.command()
def run(
    tools: list[str] | None = typer.Argument(None, help="Tools to run (default: all)."),
    phase: str | None = typer.Option(None, "--phase", help="Run only this phase."),
    force: bool = typer.Option(False, "--force", help="Rerun phases even if fresh."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would run; change nothing."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Run outstanding phases for one or more tools."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, tools)
    runner = PhaseRunner(default_phases())
    table = Table("tool", "phase", "status", "detail", title="run" if not dry_run else "dry run")
    any_failed = False
    for name in names:
        ctx = build_context(eng, name)
        try:
            if dry_run:
                for p in runner.plan(ctx, force=force, only=phase):
                    table.add_row(name, p.name, "would run", "")
                continue
            results = runner.run(ctx, force=force, only=phase)
        except ValueError as exc:  # unknown phase
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        for r in results:
            colour = {"ok": "green", "skipped": "dim", "failed": "red"}[r.status]
            detail = r.message or ""
            if r.failures:
                detail += f" [yellow]({len(r.failures)} recorded failure(s))[/yellow]"
                any_failed = True
            if r.status == PhaseStatus.failed:
                any_failed = True
            table.add_row(name, r.phase, f"[{colour}]{r.status}[/{colour}]", detail)
    console.print(table)
    if any_failed:
        err_console.print("Run completed with recorded failures; see [cyan]unvarnish status[/cyan].")
        raise typer.Exit(code=1)


@app.command()
def status(engagement: Path | None = EngagementOption) -> None:
    """Show phase freshness for every tool."""
    eng = _load_engagement(engagement)
    phases = default_phases()
    table = Table("tool", *[p.name for p in phases], title=f"status: {eng.config.client or eng.root.name}")
    for name in eng.tool_names():
        ctx = build_context(eng, name)
        cells = []
        for p in phases:
            outputs = p.outputs(ctx)
            if not all(o.exists() for o in outputs):
                cells.append("[red]missing[/red]")
            elif is_fresh(p, ctx):
                cells.append("[green]fresh[/green]")
            else:
                cells.append("[yellow]stale[/yellow]")
        table.add_row(name, *cells)
    console.print(table)


scanners_app = typer.Typer(help="Inspect scanners.", no_args_is_help=True)
app.add_typer(scanners_app, name="scanners")


@scanners_app.command("list")
def scanners_list(engagement: Path | None = EngagementOption) -> None:
    """List registered scanners and their effective options."""
    try:
        cfg = Engagement.find(engagement or Path.cwd()).config
    except NotAnEngagement:
        cfg = EngagementConfig()
    table = Table("scanner", "category", "options")
    for s in load_scanners():
        opts = cfg.scanners.get(s.name, {})
        table.add_row(s.name, str(s.category), ", ".join(f"{k}={v}" for k, v in opts.items()) or "—")
    console.print(table)
```

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -v`
Expected: PASS, all tests. Then `uv run ruff check .` and fix any lint findings (unused imports from hoisting are the usual culprits).

- [ ] **Step 6: Commit**

```bash
git add src/unvarnish/phases/__init__.py src/unvarnish/cli.py tests/test_cli_run.py
git commit -m "feat: run, status, and scanners list commands with end-to-end test"
```

---

### Task 17: README and CI

**Files:**
- Modify: `README.md`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the README**

```markdown
# Unvarnish

The unvarnished truth about internally built software.

Unvarnish is a portable command-line tool for vetting internally built, often AI-generated
tools. Point it at a repository or a pile of files in any language and it produces an
evidence-backed findings document: embedded secrets, oversized files and functions, missing
tests and CI, single-author risk, and how the tool was built. Every finding is traceable to a
file and line.

This is slice 1: the deterministic core. No model is required. Later slices add model-assisted
architecture and requirements documents, cross-tool comparison, question answering, and export.

## Install

Requires Python 3.12+ and git.

    uv tool install unvarnish        # or: uv sync && uv run unvarnish ...

## Use

    unvarnish init acme-2026-10 --client "Acme Corp" --consultant "Your Firm"
    cd acme-2026-10
    unvarnish add expense-bot --repo https://github.com/acme/expense-bot.git
    unvarnish add receipt-ocr --files ~/Downloads/receipt-ocr
    unvarnish run
    open tools/expense-bot/docs/findings.md

`unvarnish status` shows which phases are fresh. `unvarnish run --phase scan --force` reruns one
phase. `unvarnish scanners list` shows scanners and their thresholds, which you can change under
`scanners:` in `engagement.yaml`.

## Layout of an engagement

    engagement.yaml            client, tools, scanner thresholds, model config (later slices)
    tools/<name>/source/       the ingested code
    tools/<name>/inventory/    census, metrics, dependencies, git stats, scanner findings (JSON)
    tools/<name>/docs/         rendered Markdown documents
    templates/                 optional overrides for the bundled Jinja templates

JSON is the source of truth; Markdown is rendered from it.

## Develop

    uv sync
    uv run pytest
    uv run ruff check .

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/` for implementation plans.
```

- [ ] **Step 2: Add CI**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - run: uv python install 3.12
      - run: uv sync --all-groups
      - run: uv run ruff check .
      - run: uv run pytest -q
```

- [ ] **Step 3: Verify locally**

Run: `uv run pytest -q && uv run ruff check .`
Expected: all tests pass, ruff clean.

- [ ] **Step 4: Commit**

```bash
git add README.md .github/workflows/ci.yml
git commit -m "docs: README and CI workflow for slice 1"
```

---

## Self-review notes

- **Spec coverage (slice 1 scope, spec §16 item 1):** CLI (§3) `init`, `add`, `run`, `status`, `scanners list` → Tasks 4, 5, 16. Workspace (§4) → Task 4. Finding schema (§5.1) → Task 3. `ingest` (§6.1) → Task 5. `inventory` (§6.2) → Tasks 6, 7, 9. `git` (§6.3) → Task 10. `scan` with `secrets`, `oversized_files`, `hygiene`, `bus_factor` (§6.4) → Tasks 11–14. `render` of findings.md (§6.9, §8.4) → Task 15. Error handling principle (§13) → Tasks 8, 9, 11. Config (§10) → Task 4. Not in this slice by design: `compare`, `ask`, `export`, `cost`, `config check`, `cache clear`, OSV advisories, gitleaks augmentation, `hardcoded_infra`, `vendored_bulk`, `generated_bulk`, `dependencies` scanners, prose blocks, diagrams, Docker image, PyPI publishing. These belong to slices 2–7.
- **Deviation from spec noted:** spec §6.1 describes `git clone --no-checkout` then checkout; the plan uses a plain `git clone [--branch]`, which yields the same full-history result with less code. Spec §6.4 lists `gitleaks` augmentation for secrets; slice 1 ships the built-in rule set only, with `gitleaks` deferred to slice 7 hardening.
- **Type consistency checked:** `ToolPaths` attribute names, `PhaseResult` fields, `ScanContext` fields, `Finding`/`Evidence` fields, and `GitStats` fields are used identically across Tasks 8–16.
