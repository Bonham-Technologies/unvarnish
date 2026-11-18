# Unvarnish Slice 5: Ask Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `unvarnish ask`, a bounded question-answering loop over the engagement's analysis JSON and source, with a BM25 index, five read-only tools, cited answers, and saved sessions.

**Architecture:** A pure-Python BM25 index (`ask/index.py`) is built lazily from every tool's artifacts and cached under `cache/index/`. Five tools (`ask/tools.py`) read artifacts and grep source with exclusions and secret redaction. The loop (`ask/loop.py`) drives the model with the spec's structured action schema (`call` or `answer`) on every backend, so it works offline with `StubBackend`, on Anthropic, and on any OpenAI-compatible endpoint without native tool calling. Answers are checked for citations; sessions are appended to `ask-sessions/<timestamp>.md`. The CLI runs one question or an interactive session.

**Tech Stack:** Python 3.12+, Pydantic v2, Typer/Rich, pytest, ruff. No new dependencies: BM25 is about forty lines in-house (spec 9 allows "rank-bm25 or an in-house implementation").

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` sections 3 (`ask`), 4 (`cache/index/`, `ask-sessions/`), 9, 10 (`ask.max_tool_calls`), 13.

## Global Constraints

- Python 3.12+, Pydantic v2, ruff `line-length = 100`, select `E,F,I,UP,B`; PEP 695 generics.
- Spec 9: tools are exactly `search_index(query, tool?)`, `get_unit(id)`, `get_module(id)`, `get_tool(name)`, `get_findings(tool?, category?, severity?)`, `grep_source(pattern, tool, max_results)`; grep "respecting exclusions".
- Spec 9: "repeat until a final answer or `ask.max_tool_calls` (default 12). The final answer must cite artifact ids or paths. If the answer contains no citations, the transcript marks it 'unverified' and the console prints a warning; no automatic rewriting."
- Spec 9: index "Built lazily on first `ask` from analysis JSON; rebuilt when any `tool.json` is newer than the index." Sessions "saved to `ask-sessions/<timestamp>.md` with questions, answers, and citations."
- Spec 3: `unvarnish ask ["QUESTION"] [--tool NAME]`: "With no question, opens an interactive session." Exit codes 0/1/2/3 as elsewhere.
- Secrets never reach the transcript, the session file, or the console unredacted: every tool result passes through `redact_text`.
- Model calls go through `CachingBackend` and `complete_structured`; the shared `BudgetTracker` caps a session.
- Model tests run offline. Commit messages end with the session's attribution lines. Lint touched files per task, the whole tree at the end.

## Review Focus

1. **No model configured.** `ask` needs a model; it must exit 2 with a one-line message, not a traceback. (Task 4: `test_ask_without_model_exits_2`.)
2. **An answer with no citations.** The console prints a warning, the session file marks it "unverified", the exit code stays 0 (the answer may still be right). (Task 3: `test_uncited_answer_is_marked_unverified`; Task 4 CLI test.)
3. **A model that never answers.** After `max_tool_calls` the loop makes one final answer-only call; if that still is not an answer, the result says so, the session records it, and `ask` exits 1. (Task 3: `test_loop_stops_at_max_tool_calls`.)
4. **`grep_source` on a large or linked tree.** Excluded files (vendored, build output, binaries) are never read; results are capped; an invalid regex comes back to the model as a tool error, not a crash; output lines are redacted. (Task 2: `test_grep_source_respects_exclusions_and_caps`, `test_grep_source_invalid_regex_is_a_tool_error`, `test_tool_results_are_redacted`.)
5. **A stale index.** After a tool is re-analysed, the next `ask` rebuilds; an index built from an older artifact set is never served. (Task 1: `test_index_rebuilds_when_artifacts_change`.)
6. **A tool argument the model gets wrong** (unknown tool name, missing id, unknown unit id). The loop returns a tool error message and continues; it never raises. (Task 2: `test_dispatch_errors_are_returned_not_raised`.)

## File Structure

Created:

- `src/unvarnish/ask/__init__.py` (empty), `src/unvarnish/ask/bm25.py` (tokeniser + BM25), `src/unvarnish/ask/index.py` (`IndexDoc`, `Hit`, `AskIndex`, `build_index`, `load_or_build_index`), `src/unvarnish/ask/tools.py` (`AskTools`, `TOOL_SPECS`), `src/unvarnish/ask/loop.py` (`AskStep`, `StepRecord`, `AskResult`, `run_question`, `find_citations`, `write_session`), `src/unvarnish/model/prompts/ask_system.md`, `src/unvarnish/model/prompts/ask.py`.
- `tests/test_ask_index.py`, `tests/test_ask_tools.py`, `tests/test_ask_loop.py`, `tests/test_cli_ask.py`.

Modified:

- `src/unvarnish/engagement.py` — `index_dir`, `index_file`, `ask_sessions_dir` properties (and `create` makes `ask-sessions/`).
- `src/unvarnish/cli.py` — `ask` command.
- `README.md`, `scripts/smoke.sh` (one `ask` question at the end).

---

### Task 1: BM25 index over the analysis artifacts

**Files:**
- Create: `src/unvarnish/ask/__init__.py`, `src/unvarnish/ask/bm25.py`, `src/unvarnish/ask/index.py`
- Modify: `src/unvarnish/engagement.py`
- Test: `tests/test_ask_index.py`

**Interfaces:**
- Consumes: `Engagement`, `ToolPaths`, `read_artifact`, `hash_files`, `UnitResult`, `Module`, `ToolModel`, `RequirementsInventory`, `ModelFindings`, `ScannerFindings`, `Verification`.
- Produces:
  - `unvarnish.ask.bm25`: `tokenize(text) -> list[str]`, `class BM25(docs: Sequence[Sequence[str]], k1=1.5, b=0.75)` with `score(query_tokens) -> list[float]`.
  - `unvarnish.ask.index`: `IndexDoc(id, kind: Literal["unit","module","tool","finding","capability"], tool, path: str | None, text, snippet)`, `Hit(id, kind, tool, path, score, snippet)`, `AskIndex(docs, inputs_hash)` pydantic model with `search(query, tool=None, k=8) -> list[Hit]`, `index_inputs(eng) -> list[Path]`, `build_index(eng) -> AskIndex`, `load_or_build_index(eng) -> tuple[AskIndex, bool]` (index, rebuilt).
  - `Engagement.index_dir` (`cache/index`), `Engagement.index_file` (`cache/index/index.json`), `Engagement.ask_sessions_dir` (`ask-sessions`).

- [ ] **Step 1: Write the failing tests**

`tests/test_ask_index.py`:

```python
import json

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.bm25 import BM25, tokenize
from unvarnish.ask.index import AskIndex, build_index, load_or_build_index
from unvarnish.engagement import Engagement


def test_tokenize_and_bm25_rank():
    assert tokenize("Reads the Expenses-DB table; writes_nothing!") == [
        "reads", "the", "expenses", "db", "table", "writes_nothing"]
    docs = [tokenize(t) for t in ("the cat sat", "the dog sat on the log", "expenses report")]
    scores = BM25(docs).score(tokenize("expenses"))
    assert scores[2] > 0 and scores[0] == 0 == scores[1]
    scores = BM25(docs).score(tokenize("the sat"))
    assert scores[0] > scores[1] > 0  # shorter doc with the same terms ranks higher


def test_paths_exist(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    assert eng.index_file == eng.root / "cache" / "index" / "index.json"
    assert eng.ask_sessions_dir == eng.root / "ask-sessions" and eng.ask_sessions_dir.is_dir()


def test_build_index_covers_every_artifact_kind(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    index = build_index(engagement)
    kinds = {d.kind for d in index.docs}
    assert kinds == {"unit", "module", "tool", "finding", "capability"}
    assert {d.tool for d in index.docs} == {"alpha", "beta"}
    finding_docs = [d for d in index.docs if d.kind == "finding"]
    assert any("AWS access key" in d.text for d in finding_docs)  # scanner findings too
    assert any(d.text.startswith("Hardcoded credential") for d in finding_docs)
    # the README.md credential finding is rejected by the stub verifier: not indexed
    assert not any(d.path == "README.md" and d.text.startswith("Hardcoded credential")
                   for d in finding_docs)
    hits = index.search("export report", k=3)
    assert hits and hits[0].kind == "capability" and hits[0].tool in ("alpha", "beta")
    only_beta = index.search("export report", tool="beta")
    assert only_beta and all(h.tool == "beta" for h in only_beta)
    assert all(len(h.snippet) <= 240 for h in hits)


def test_index_rebuilds_when_artifacts_change(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    index, rebuilt = load_or_build_index(engagement)
    assert rebuilt and engagement.index_file.exists()
    again, rebuilt = load_or_build_index(engagement)
    assert not rebuilt and again.inputs_hash == index.inputs_hash
    tool_json = engagement.tool_paths("alpha").tool_model
    data = json.loads(tool_json.read_text())
    data["data"]["purpose"] = "Something entirely new"
    tool_json.write_text(json.dumps(data))
    fresh, rebuilt = load_or_build_index(engagement)
    assert rebuilt and fresh.inputs_hash != index.inputs_hash
    assert any("entirely new" in d.text for d in fresh.docs if d.kind == "tool")


def test_index_handles_scanner_only_tool(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub, model_for=("alpha",))
    index = build_index(engagement)
    beta = [d for d in index.docs if d.tool == "beta"]
    assert beta and {d.kind for d in beta} == {"finding"}
    assert AskIndex.model_validate(index.model_dump()).search("secret")  # round-trips
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_ask_index.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.ask'`.

- [ ] **Step 3: Write BM25, the index, and the paths**

`src/unvarnish/ask/__init__.py`: empty.

`src/unvarnish/ask/bm25.py`:

```python
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

TOKEN_RE = re.compile(r"[a-z0-9_]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class BM25:
    """Okapi BM25 over pre-tokenised documents; small, pure Python, no dependency."""

    def __init__(self, docs: Sequence[Sequence[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.doc_len = [len(d) for d in docs]
        self.avg_len = (sum(self.doc_len) / len(docs)) if docs else 0.0
        self.tf = [Counter(d) for d in docs]
        df: Counter[str] = Counter()
        for counts in self.tf:
            df.update(counts.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def score(self, query_tokens: Sequence[str]) -> list[float]:
        scores = [0.0] * len(self.tf)
        for term in query_tokens:
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i, counts in enumerate(self.tf):
                tf = counts.get(term)
                if not tf:
                    continue
                norm = 1 - self.b + self.b * (self.doc_len[i] / self.avg_len if self.avg_len else 0)
                scores[i] += idf * tf * (self.k1 + 1) / (tf + self.k1 * norm)
        return scores
```

`src/unvarnish/ask/index.py`:

```python
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.artifacts import hash_files, read_artifact, write_artifact
from unvarnish.ask.bm25 import BM25, tokenize
from unvarnish.engagement import Engagement
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import Finding, Verification
from unvarnish.schemas.rollup import Module
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import RequirementsInventory, ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.ask")
SNIPPET_CHARS = 240
Kind = Literal["unit", "module", "tool", "finding", "capability"]


class IndexDoc(BaseModel):
    id: str
    kind: Kind
    tool: str
    path: str | None = None
    text: str
    snippet: str


class Hit(BaseModel):
    id: str
    kind: Kind
    tool: str
    path: str | None
    score: float
    snippet: str


def _snip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= SNIPPET_CHARS else text[:SNIPPET_CHARS - 1] + "…"


class AskIndex(BaseModel):
    docs: list[IndexDoc] = Field(default_factory=list)
    inputs_hash: str = ""

    def search(self, query: str, tool: str | None = None, k: int = 8) -> list[Hit]:
        docs = [d for d in self.docs if tool is None or d.tool == tool]
        if not docs:
            return []
        scores = BM25([tokenize(d.text) for d in docs]).score(tokenize(query))
        ranked = sorted(zip(scores, docs, strict=True), key=lambda p: -p[0])
        return [Hit(id=d.id, kind=d.kind, tool=d.tool, path=d.path, score=round(s, 3),
                    snippet=d.snippet) for s, d in ranked[:k] if s > 0]


def _finding_doc(tool: str, f: Finding) -> IndexDoc:
    text = f"{f.title}. {f.summary} {f.impact}"
    return IndexDoc(id=f.id, kind="finding", tool=tool, path=f.evidence[0].path, text=text,
                    snippet=_snip(f"{f.title} [{f.severity}, {f.source}]: {f.summary}"))


def _tool_docs(eng: Engagement, tool: str) -> list[IndexDoc]:
    p = eng.tool_paths(tool)
    docs: list[IndexDoc] = []
    for path in sorted(p.unit_dir.glob("*.json")) if p.unit_dir.exists() else []:
        try:
            r = read_artifact(path, UnitResult).data
        except Exception:
            continue
        label = f"{r.unit.path}:{r.unit.line_start}-{r.unit.line_end}"
        text = f"{label} {r.unit.name or ''} {r.extraction.purpose} " + " ".join(
            r.extraction.interface + r.extraction.risks)
        docs.append(IndexDoc(id=r.unit.id, kind="unit", tool=tool, path=r.unit.path, text=text,
                             snippet=_snip(f"{label}: {r.extraction.purpose}")))
    for path in sorted(p.module_dir.glob("*.json")) if p.module_dir.exists() else []:
        try:
            m = read_artifact(path, Module).data
        except Exception:
            continue
        text = f"{m.path} {m.rollup.summary} " + " ".join(m.rollup.responsibilities)
        docs.append(IndexDoc(id=m.id, kind="module", tool=tool, path=m.path, text=text,
                             snippet=_snip(f"{m.path}: {m.rollup.summary}")))
    if p.tool_model.exists():
        try:
            tm = read_artifact(p.tool_model, ToolModel).data
            text = f"{tool} {tm.purpose} " + " ".join(a.name for a in tm.actors) + " " + " ".join(
                tm.internal_stack + tm.deployment_assumptions)
            docs.append(IndexDoc(id=f"tool:{tool}", kind="tool", tool=tool, path=None, text=text,
                                 snippet=_snip(f"{tool}: {tm.purpose}")))
        except Exception:
            log.warning("index: unreadable tool.json for %s", tool)
    if p.capabilities.exists():
        try:
            req = read_artifact(p.capabilities, RequirementsInventory).data
            for c in req.capabilities:
                label = f"{c.actor} can {c.action} {c.object}"
                docs.append(IndexDoc(
                    id=f"cap:{c.id}", kind="capability", tool=tool,
                    path=c.evidence[0].path if c.evidence else None,
                    text=f"{label}. {c.description}", snippet=_snip(f"{label}: {c.description}")))
        except Exception:
            log.warning("index: unreadable capabilities.json for %s", tool)
    if p.scanner_findings.exists():
        try:
            for f in read_artifact(p.scanner_findings, ScannerFindings).data.findings:
                docs.append(_finding_doc(tool, f))
        except Exception:
            log.warning("index: unreadable scanner-findings.json for %s", tool)
    if p.model_findings.exists():
        try:
            for f in read_artifact(p.model_findings, ModelFindings).data.findings:
                if f.verification != Verification.rejected:
                    docs.append(_finding_doc(tool, f))
        except Exception:
            log.warning("index: unreadable findings.json for %s", tool)
    return docs


def index_inputs(eng: Engagement) -> list[Path]:
    out: list[Path] = []
    for tool in eng.tool_names():
        p = eng.tool_paths(tool)
        out += [p.extract_state, p.modules_index, p.tool_model, p.capabilities,
                p.model_findings, p.scanner_findings]
    return out


def build_index(eng: Engagement) -> AskIndex:
    docs: list[IndexDoc] = []
    for tool in eng.tool_names():
        docs.extend(_tool_docs(eng, tool))
    return AskIndex(docs=docs, inputs_hash=hash_files(index_inputs(eng)))


def load_or_build_index(eng: Engagement) -> tuple[AskIndex, bool]:
    """The cached index when its inputs are unchanged, else a fresh build (and True)."""
    current = hash_files(index_inputs(eng))
    if eng.index_file.exists():
        try:
            cached = read_artifact(eng.index_file, AskIndex).data
            if cached.inputs_hash == current:
                return cached, False
        except Exception:
            log.warning("ask index unreadable; rebuilding")
    index = build_index(eng)
    write_artifact(eng.index_file, index, produced_by="ask", inputs_hash=current)
    log.info("ask index built: %d documents", len(index.docs))
    return index, True
```

In `src/unvarnish/engagement.py` add properties after `comparison_failures`:

```python
    @property
    def index_dir(self) -> Path:
        return self.cache_dir / "index"

    @property
    def index_file(self) -> Path:
        return self.index_dir / "index.json"

    @property
    def ask_sessions_dir(self) -> Path:
        return self.root / "ask-sessions"
```

and in `create`, include `eng.ask_sessions_dir` in the tuple of directories made.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_ask_index.py -q 2>&1 | tail -3`
Expected: all PASS. (`hash_files` treats a missing path as `<missing>`, so scanner-only tools and un-run tools hash stably. The `extract_state` and `modules_index` paths stand in for the unit and module directories, whose contents they summarise, so the hash stays cheap on a 1,000-file tool.)

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/ask src/unvarnish/engagement.py tests/test_ask_index.py
git add src/unvarnish/ask src/unvarnish/engagement.py tests/test_ask_index.py
git commit -m "feat: BM25 ask index over analysis artifacts with lazy rebuild"
```

---

### Task 2: The five read-only tools

**Files:**
- Create: `src/unvarnish/ask/tools.py`
- Test: `tests/test_ask_tools.py`

**Interfaces:**
- Consumes: `AskIndex`, `Engagement`, `resolve_source_root`/`load_tool_meta` (`phases/ingest.py`), `Census`, `read_artifact`, `redact_text`, `Finding`, `SEVERITY_ORDER`.
- Produces: `TOOL_SPECS: dict[str, str]` (name → one-line description for the prompt), `class AskTools(eng: Engagement, index: AskIndex)` with `search_index(query: str, tool: str | None = None) -> dict`, `get_unit(id: str) -> dict`, `get_module(id: str) -> dict`, `get_tool(name: str) -> dict`, `get_findings(tool: str | None = None, category: str | None = None, severity: str | None = None) -> dict`, `grep_source(pattern: str, tool: str, max_results: int = 20) -> dict`, and `dispatch(name: str, args: dict) -> dict` (never raises; errors are `{"error": "..."}`). Every result dict is JSON-serialisable, size-capped, and redacted.

- [ ] **Step 1: Write the failing tests**

`tests/test_ask_tools.py`:

```python
import json

from tests.conftest import LEAKED_KEY
from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.index import build_index
from unvarnish.ask.tools import TOOL_SPECS, AskTools


def _tools(engagement, synthetic_repo) -> AskTools:
    _two_tools(engagement, synthetic_repo, _compare_stub())
    return AskTools(engagement, build_index(engagement))


def test_tool_specs_match_spec_names():
    assert set(TOOL_SPECS) == {"search_index", "get_unit", "get_module", "get_tool",
                               "get_findings", "grep_source"}


def test_search_and_get_unit_module_tool(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    hits = t.search_index("does a thing", tool="alpha")["hits"]
    unit_hit = next(h for h in hits if h["kind"] == "unit")
    unit = t.get_unit(unit_hit["id"])
    assert unit["path"] and unit["extraction"]["purpose"] == "Does a thing." and "usage" not in unit
    module_hit = next(h for h in t.search_index("module", tool="alpha")["hits"]
                      if h["kind"] == "module")
    module = t.get_module(module_hit["id"])
    assert module["path"] and module["summary"] == "A module." and module["unit_ids"]
    tool = t.get_tool("alpha")
    assert tool["purpose"] == "Tracks expenses." and tool["capabilities"][0]["id"]
    assert "findings" not in tool  # findings come from get_findings
    assert t.get_tool("nope") == {"error": "unknown tool 'nope'; known: alpha, beta"}
    assert t.get_unit("nope")["error"].startswith("no unit with id")


def test_get_findings_filters_and_excludes_rejected(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    all_findings = t.get_findings()["findings"]
    assert any(f["source"] == "scanner" for f in all_findings)
    assert any(f["source"] == "model" for f in all_findings)
    assert not any(f["title"] == "No auth anywhere" and f.get("verification") == "rejected"
                   for f in all_findings)
    high = t.get_findings(severity="high")["findings"]
    assert high and all(f["severity"] == "high" for f in high)
    sec = t.get_findings(tool="beta", category="security")["findings"]
    assert sec and all(f["tool"] == "beta" and f["category"] == "security" for f in sec)
    assert t.get_findings(severity="loud")["error"].startswith("unknown severity")
    assert all({"id", "evidence"} <= set(f) for f in all_findings)


def test_grep_source_respects_exclusions_and_caps(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    out = t.grep_source("module.exports", tool="alpha")
    assert out["matches"] == [] and out["searched_files"] > 0  # node_modules is excluded
    out = t.grep_source(r"x\d+ = data", tool="alpha", max_results=5)
    assert len(out["matches"]) == 5 and out["truncated"] is True
    assert all(m["path"] == "app.py" and m["line"] > 0 and "data" in m["text"]
               for m in out["matches"])
    assert t.grep_source("anything", tool="nope")["error"].startswith("unknown tool")


def test_grep_source_invalid_regex_is_a_tool_error(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    out = t.grep_source("(unclosed", tool="alpha")
    assert "error" in out and "regex" in out["error"]


def test_tool_results_are_redacted(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    # the leaked key is only in git history; append one to a file the census already lists
    with (engagement.tool_paths("alpha").source / "README.md").open("a") as fh:
        fh.write(f'K = "{LEAKED_KEY}"\n')
    out = t.grep_source("K = ", tool="alpha")
    assert out["matches"] and LEAKED_KEY not in json.dumps(out)
    assert LEAKED_KEY not in json.dumps(t.get_findings(tool="alpha"))


def test_dispatch_errors_are_returned_not_raised(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    assert t.dispatch("fly", {})["error"].startswith("unknown tool 'fly'")
    assert t.dispatch("get_unit", {})["error"].startswith("get_unit needs")
    assert t.dispatch("grep_source", {"pattern": "x"})["error"].startswith("grep_source needs")
    assert t.dispatch("search_index", {"query": "thing", "tool": "alpha"})["hits"]
    assert t.dispatch("grep_source", {"pattern": "def", "tool": "alpha",
                                      "max_results": "3"})["matches"]  # coerces the int
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_ask_tools.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.ask.tools'`.

- [ ] **Step 3: Write the tools**

`src/unvarnish/ask/tools.py`:

```python
from __future__ import annotations

import json
import re
from typing import Any

from unvarnish.artifacts import read_artifact
from unvarnish.ask.index import AskIndex
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import load_tool_meta, resolve_source_root
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import SEVERITY_ORDER, Category, Finding, Severity, Verification
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import Module, module_file_id
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings

TOOL_SPECS: dict[str, str] = {
    "search_index": "search_index(query, tool?) - BM25 over unit purposes, module summaries, "
                    "findings, and capabilities; returns ids, kinds, and snippets",
    "get_unit": "get_unit(id) - one analysed unit of code: path, lines, extraction, findings",
    "get_module": "get_module(id) - one file's rollup: summary, responsibilities, dependencies",
    "get_tool": "get_tool(name) - the tool model: purpose, actors, entry points, stores, "
                "external systems, capabilities, business rules",
    "get_findings": "get_findings(tool?, category?, severity?) - findings with evidence",
    "grep_source": "grep_source(pattern, tool, max_results) - regex over the tool's source, "
                   "skipping excluded files; returns path, line, text",
}
MAX_HITS = 8
MAX_FINDINGS = 40
MAX_GREP = 50
MAX_LINE_CHARS = 200
MAX_TEXT_CHARS = 1500
RESULT_CHARS = 12_000


def _clip(v: Any) -> Any:
    if isinstance(v, str):
        return redact_text(v if len(v) <= MAX_TEXT_CHARS else v[:MAX_TEXT_CHARS] + "…")
    if isinstance(v, list):
        return [_clip(x) for x in v]
    if isinstance(v, dict):
        return {k: _clip(x) for k, x in v.items()}
    return v


def _finding_view(tool: str, f: Finding) -> dict:
    d = f.model_dump(mode="json", include={"id", "category", "severity", "title", "summary",
                                           "impact", "remediation", "source", "verification",
                                           "evidence"})
    d["tool"] = tool
    return d


class AskTools:
    def __init__(self, eng: Engagement, index: AskIndex) -> None:
        self.eng = eng
        self.index = index
        self.tools = eng.tool_names()

    # --- helpers -----------------------------------------------------------
    def _unknown_tool(self, name: str) -> dict:
        return {"error": f"unknown tool {name!r}; known: {', '.join(self.tools)}"}

    def _findings_for(self, tool: str) -> list[Finding]:
        p = self.eng.tool_paths(tool)
        out: list[Finding] = []
        if p.scanner_findings.exists():
            out += read_artifact(p.scanner_findings, ScannerFindings).data.findings
        if p.model_findings.exists():
            out += [f for f in read_artifact(p.model_findings, ModelFindings).data.findings
                    if f.verification != Verification.rejected]
        return out

    # --- tools ---------------------------------------------------------------
    def search_index(self, query: str, tool: str | None = None) -> dict:
        if tool is not None and tool not in self.tools:
            return self._unknown_tool(tool)
        hits = self.index.search(query, tool=tool, k=MAX_HITS)
        return {"hits": [h.model_dump() for h in hits]}

    def get_unit(self, id: str) -> dict:  # noqa: A002 - the spec's argument name
        for tool in self.tools:
            path = self.eng.tool_paths(tool).unit_dir / f"{id}.json"
            if path.exists():
                r = read_artifact(path, UnitResult).data
                return _clip({
                    "id": r.unit.id, "tool": tool, "path": r.unit.path,
                    "lines": [r.unit.line_start, r.unit.line_end], "kind": r.unit.kind.value,
                    "name": r.unit.name, "extraction": r.extraction.model_dump(mode="json"),
                    "findings": [_finding_view(tool, f) for f in r.findings],
                })
        return {"error": f"no unit with id {id!r}"}

    def get_module(self, id: str) -> dict:  # noqa: A002
        for tool in self.tools:
            d = self.eng.tool_paths(tool).module_dir
            candidates = [d / f"{id}.json", d / f"{module_file_id(id)}.json"]
            for path in candidates:
                if path.exists():
                    m = read_artifact(path, Module).data
                    return _clip({
                        "id": m.id, "tool": tool, "path": m.path, "unit_ids": m.unit_ids,
                        "summary": m.rollup.summary,
                        "responsibilities": m.rollup.responsibilities,
                        "interface": m.rollup.interface,
                        "dependencies_in": m.rollup.dependencies_in,
                        "dependencies_out": m.rollup.dependencies_out,
                        "findings": [_finding_view(tool, f) for f in m.findings],
                    })
        return {"error": f"no module with id or path {id!r}"}

    def get_tool(self, name: str) -> dict:
        if name not in self.tools:
            return self._unknown_tool(name)
        p = self.eng.tool_paths(name)
        if not p.tool_model.exists():
            return {"error": f"tool {name!r} has no tool model (model analysis not run or "
                             "failed); use get_findings and grep_source"}
        tm = read_artifact(p.tool_model, ToolModel).data
        return _clip(tm.model_dump(mode="json", exclude={
            "findings", "usage", "backend", "model", "prompt_version", "attempts",
            "dropped_findings"}))

    def get_findings(self, tool: str | None = None, category: str | None = None,
                     severity: str | None = None) -> dict:
        if tool is not None and tool not in self.tools:
            return self._unknown_tool(tool)
        if category is not None and category not in {c.value for c in Category}:
            return {"error": f"unknown category {category!r}; known: "
                             f"{', '.join(c.value for c in Category)}"}
        if severity is not None and severity not in {s.value for s in Severity}:
            return {"error": f"unknown severity {severity!r}; known: "
                             f"{', '.join(s.value for s in Severity)}"}
        rows: list[dict] = []
        for t in ([tool] if tool else self.tools):
            for f in self._findings_for(t):
                if category and f.category.value != category:
                    continue
                if severity and f.severity.value != severity:
                    continue
                rows.append(_finding_view(t, f))
        rows.sort(key=lambda r: (SEVERITY_ORDER[Severity(r["severity"])], r["tool"]))
        truncated = len(rows) > MAX_FINDINGS
        return _clip({"findings": rows[:MAX_FINDINGS], "total": len(rows),
                      "truncated": truncated})

    def grep_source(self, pattern: str, tool: str, max_results: int = 20) -> dict:
        if tool not in self.tools:
            return self._unknown_tool(tool)
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return {"error": f"invalid regex: {exc}"}
        max_results = max(1, min(int(max_results), MAX_GREP))
        p = self.eng.tool_paths(tool)
        if not p.census.exists():
            return {"error": f"tool {tool!r} has not been inventoried; run `unvarnish run`"}
        census = read_artifact(p.census, Census).data
        root = resolve_source_root(self.eng, load_tool_meta(p))
        matches: list[dict] = []
        searched = 0
        truncated = False
        for rec in census.files:
            if rec.excluded or rec.classification == "binary":
                continue
            searched += 1
            try:
                text = (root / rec.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), start=1):
                if rx.search(line):
                    if len(matches) >= max_results:
                        truncated = True
                        break
                    matches.append({"path": rec.path, "line": n,
                                    "text": redact_text(line.strip()[:MAX_LINE_CHARS])})
            if truncated:
                break
        return {"matches": matches, "searched_files": searched, "truncated": truncated}

    # --- dispatch --------------------------------------------------------------
    REQUIRED = {"search_index": ("query",), "get_unit": ("id",), "get_module": ("id",),
                "get_tool": ("name",), "get_findings": (), "grep_source": ("pattern", "tool")}

    def dispatch(self, name: str, args: dict) -> dict:
        if name not in TOOL_SPECS:
            return {"error": f"unknown tool {name!r}; known: {', '.join(TOOL_SPECS)}"}
        missing = [a for a in self.REQUIRED[name] if not args.get(a)]
        if missing:
            return {"error": f"{name} needs {', '.join(missing)}"}
        allowed = {"search_index": {"query", "tool"}, "get_unit": {"id"}, "get_module": {"id"},
                   "get_tool": {"name"}, "get_findings": {"tool", "category", "severity"},
                   "grep_source": {"pattern", "tool", "max_results"}}[name]
        kwargs = {k: v for k, v in args.items() if k in allowed and v not in (None, "")}
        try:
            result = getattr(self, name)(**kwargs)
        except (ValueError, TypeError) as exc:
            return {"error": f"{name}: bad arguments: {exc}"}
        encoded = json.dumps(result, ensure_ascii=False)
        if len(encoded) > RESULT_CHARS:
            result = {**result, "note": f"result truncated to {RESULT_CHARS} characters"}
            encoded = json.dumps(result, ensure_ascii=False)[:RESULT_CHARS]
            return {"truncated_json": encoded}
        return result
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_ask_tools.py -q 2>&1 | tail -3`
Expected: all PASS. If `test_grep_source_respects_exclusions_and_caps` finds `module.exports`, check that the synthetic repo's `node_modules` records are `excluded` in `census.json` (slice 1 marks vendored directories excluded).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/ask/tools.py tests/test_ask_tools.py
git add src/unvarnish/ask/tools.py tests/test_ask_tools.py
git commit -m "feat: ask tools over artifacts and source with exclusions and redaction"
```

---

### Task 3: The bounded loop, citations, and sessions

**Files:**
- Create: `src/unvarnish/model/prompts/ask_system.md`, `src/unvarnish/model/prompts/ask.py`, `src/unvarnish/ask/loop.py`
- Test: `tests/test_ask_loop.py`

**Interfaces:**
- Consumes: `AskTools`, `AskIndex`, `TOOL_SPECS`, `complete_structured`, `StructuredOutputError`, `ModelRefusal`, `BudgetTracker`, `BudgetExceeded`, `redact_text`, `strict_schema`, `CompletionRequest`, `Message`, `Usage`.
- Produces:
  - `unvarnish.model.prompts.ask`: `ASK_PROMPT_VERSION = "2026-10-17.1"`, `ASK_MAX_TOKENS = 4000`, `engagement_summary(eng, index: AskIndex) -> str`, `build_ask_system(summary: str, max_calls: int) -> str`, `build_ask_request(system, messages: Sequence[Message], effort) -> CompletionRequest` (schema_name `"AskStep"`).
  - `unvarnish.ask.loop`: `AskStep` (model output: `action: Literal["call","answer"]`, `tool: Literal[<the six names>] | None`, `query`, `tool_name`, `id`, `category`, `severity`, `pattern`: `str | None`, `max_results: int | None`, `answer: str | None`, `citations: list[str]`), `StepRecord(kind: Literal["call","answer","error"], tool, args: dict, result_preview: str | None, usage: Usage)`, `AskResult(question, answer, citations: list[str], verified: bool, completed: bool, steps: list[StepRecord], usage: Usage, tool_filter: str | None, stopped_for_budget: bool = False)`, `call_args(step: AskStep, tool_filter: str | None) -> tuple[str, dict]`, `find_citations(text: str, explicit: Sequence[str], index: AskIndex) -> list[str]`, `run_question(eng, backend, tools, index, question, *, tool_filter=None, budget, effort, max_calls) -> AskResult`, `write_session(eng, results: Sequence[AskResult], started: datetime) -> Path`.

- [ ] **Step 1: Write the failing tests**

`tests/test_ask_loop.py`:

```python
import json
from datetime import UTC, datetime

from tests.conftest import LEAKED_KEY
from tests.stub_backend import StubBackend
from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.index import build_index
from unvarnish.ask.loop import AskStep, call_args, find_citations, run_question, write_session
from unvarnish.ask.tools import AskTools
from unvarnish.model.budget import BudgetTracker
from unvarnish.schemas.cost import Usage


def _ready(engagement, synthetic_repo):
    _two_tools(engagement, synthetic_repo, _compare_stub())
    index = build_index(engagement)
    return index, AskTools(engagement, index)


def _answer(text: str, citations: list[str] | None = None) -> str:
    return json.dumps({"action": "answer", "answer": text, "citations": citations or []})


def _call(tool: str, **args) -> str:
    return json.dumps({"action": "call", "tool": tool, **args})


def _search_then_answer(req) -> str:
    """Call search_index on the first turn, then answer citing the first hit."""
    last = req.messages[-1].content
    if last.startswith("Result of search_index"):
        hits = json.loads(last.split("\n", 1)[1].rsplit("\n\n", 1)[0])["hits"]
        return _answer(f"It is handled in {hits[0]['id']} ({hits[0]['path']}).", [hits[0]["id"]])
    return _call("search_index", query="does a thing", tool_name="alpha")


def test_call_args_maps_step_fields_and_tool_filter():
    step = AskStep(action="call", tool="get_findings", severity="high")
    assert call_args(step, "beta") == ("get_findings", {"tool": "beta", "severity": "high"})
    step = AskStep(action="call", tool="grep_source", pattern="x", tool_name="alpha",
                   max_results=3)
    assert call_args(step, None) == ("grep_source", {"pattern": "x", "tool": "alpha",
                                                     "max_results": 3})
    step = AskStep(action="call", tool="get_tool", tool_name="alpha")
    assert call_args(step, None) == ("get_tool", {"name": "alpha"})


def test_find_citations_validates_ids_and_paths(engagement, synthetic_repo):
    index, _ = _ready(engagement, synthetic_repo)
    unit_id = next(d.id for d in index.docs if d.kind == "unit")
    cap_id = next(d.id for d in index.docs if d.kind == "capability")
    text = f"See {unit_id} and app.py:12-20, also {cap_id} and nothing.py:3 and deadbeefdeadbeef."
    cites = find_citations(text, ["tool:alpha", "bogus", "README.md"], index)
    assert unit_id in cites and cap_id in cites and "app.py:12-20" in cites
    assert "tool:alpha" in cites and "README.md" in cites
    assert "bogus" not in cites and "nothing.py:3" not in cites
    assert "deadbeefdeadbeef" not in cites


def test_loop_calls_tool_then_answers_with_citations(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _search_then_answer})
    res = run_question(engagement, stub, tools, index, "Where is the thing handled?",
                       budget=BudgetTracker(None), effort=None, max_calls=12)
    assert res.completed and res.verified and res.citations
    assert [s.kind for s in res.steps] == ["call", "answer"]
    assert res.steps[0].tool == "search_index" and res.steps[0].args["tool"] == "alpha"
    assert res.usage.total() == 240 and stub.count("AskStep") == 2
    path = write_session(engagement, [res], datetime.now(UTC))
    text = path.read_text()
    assert path.parent == engagement.ask_sessions_dir and path.suffix == ".md"
    assert "Where is the thing handled?" in text and res.citations[0] in text
    assert "Unverified" not in text


def test_uncited_answer_is_marked_unverified(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _answer("It just does.")})
    res = run_question(engagement, stub, tools, index, "Why?", budget=BudgetTracker(None),
                       effort=None, max_calls=12)
    assert res.completed and not res.verified and res.citations == []
    text = write_session(engagement, [res], datetime.now(UTC)).read_text()
    assert "Unverified: no citations" in text


def test_loop_stops_at_max_tool_calls(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _call("get_findings")})
    res = run_question(engagement, stub, tools, index, "Everything?", budget=BudgetTracker(None),
                       effort=None, max_calls=3)
    assert not res.completed and not res.verified
    assert sum(1 for s in res.steps if s.kind == "call") == 3
    assert "did not produce an answer" in res.answer
    forced = stub.requests[-1].messages[-1].content
    assert "no tool calls left" in forced.lower()


def test_tool_errors_are_fed_back_not_raised(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    seen: list[str] = []

    def script(req) -> str:
        last = req.messages[-1].content
        seen.append(last[:60])
        if last.startswith("Result of get_unit"):
            assert "no unit with id" in last
            return _answer("Could not find it; see README.md.", ["README.md"])
        return _call("get_unit", id="nope")

    res = run_question(engagement, StubBackend({"AskStep": script}), tools, index, "?",
                       budget=BudgetTracker(None), effort=None, max_calls=12)
    assert res.completed and res.verified and res.steps[0].result_preview
    assert "error" in res.steps[0].result_preview


def test_structured_failure_and_budget_stop(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    res = run_question(engagement, StubBackend({"AskStep": "garbage"}), tools, index, "?",
                       budget=BudgetTracker(None), effort=None, max_calls=2)
    assert not res.completed and res.answer.startswith("No answer:")
    assert res.steps[-1].kind == "error"
    tracker = BudgetTracker(10)
    tracker.add(Usage(input_tokens=11))
    res = run_question(engagement, StubBackend({"AskStep": _answer("x")}), tools, index, "?",
                       budget=tracker, effort=None, max_calls=2)
    assert res.stopped_for_budget and not res.completed


def test_answers_and_tool_results_are_redacted(engagement, synthetic_repo):
    index, tools = _ready(engagement, synthetic_repo)
    stub = StubBackend({"AskStep": _answer(f"The key is {LEAKED_KEY}, see app.py:2.",
                                           ["app.py:2"])})
    res = run_question(engagement, stub, tools, index, "key?", budget=BudgetTracker(None),
                       effort=None, max_calls=2)
    assert LEAKED_KEY not in res.answer and "redacted" in res.answer
    assert LEAKED_KEY not in write_session(engagement, [res], datetime.now(UTC)).read_text()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_ask_loop.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.ask.loop'`.

- [ ] **Step 3: Write the prompt**

`src/unvarnish/model/prompts/ask_system.md`:

```markdown
You answer a consultant's questions about internally built software under review. You may use
only what the engagement's analysis artifacts and source files show, reached through the tools
below. Never guess: when you do not know, call a tool; when the tools cannot show it, say so
plainly and say what was not analysed.

## Engagement

{{ENGAGEMENT}}

## Tools

{{TOOLS}}

Arguments: `tool_name` is the name of a tool under review (one of the engagement's tools);
`tool` is which of the functions above to call. `id` is a unit, module, finding, or
capability id from search results. You have at most {{MAX_CALLS}} tool calls per question;
each turn you make one call or give the final answer.

## Each turn

Return exactly one JSON object. Either a call (`action` "call" with `tool` and the arguments
it needs) or the final answer (`action` "answer" with `answer` and `citations`). The answer
must be backed by evidence: cite the ids (unit, module, finding, capability) or file paths
with line numbers you relied on, both inside the answer text and in `citations`. An answer
without citations will be marked unverified. Plain language for a reader who does not code.
Do not soften findings; if the analysis says a credential is embedded or there are no tests,
say so.

Schema:

{{SCHEMA}}
```

`src/unvarnish/model/prompts/ask.py`:

```python
from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.ask.index import AskIndex
from unvarnish.ask.tools import TOOL_SPECS
from unvarnish.engagement import Engagement
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema

ASK_PROMPT_VERSION = "2026-10-17.1"  # bump whenever ask_system.md changes
ASK_MAX_TOKENS = 4000


def engagement_summary(eng: Engagement, index: AskIndex) -> str:
    lines = [f"Client: {eng.config.client or 'unknown'}. Tools under review:"]
    for tool in eng.tool_names():
        docs = [d for d in index.docs if d.tool == tool]
        kinds = {k: sum(1 for d in docs if d.kind == k)
                 for k in ("unit", "module", "finding", "capability")}
        has_model = any(d.kind == "tool" for d in docs)
        lines.append(f"- {tool}: {kinds['unit']} analysed units, {kinds['module']} modules, "
                     f"{kinds['finding']} findings, {kinds['capability']} capabilities"
                     + ("" if has_model else " (no tool model: scanner analysis only)"))
    return "\n".join(lines)


@cache
def _template() -> str:
    return (resources.files("unvarnish.model.prompts").joinpath("ask_system.md")
            .read_text(encoding="utf-8"))


def build_ask_system(summary: str, max_calls: int) -> str:
    from unvarnish.ask.loop import AskStep  # local import: loop imports this module

    tools = "\n".join(f"- {spec}" for spec in TOOL_SPECS.values())
    schema = json.dumps(strict_schema(AskStep), indent=1, sort_keys=True)
    return (_template().replace("{{ENGAGEMENT}}", summary).replace("{{TOOLS}}", tools)
            .replace("{{MAX_CALLS}}", str(max_calls)).replace("{{SCHEMA}}", schema))


def build_ask_request(system: str, messages: Sequence[Message],
                      effort: str | None) -> CompletionRequest:
    return CompletionRequest(system=system, messages=list(messages), schema_name="AskStep",
                             max_tokens=ASK_MAX_TOKENS, effort=effort, cache_system=True)
```

- [ ] **Step 4: Write the loop**

`src/unvarnish/ask/loop.py`:

```python
from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.ask.index import AskIndex
from unvarnish.ask.tools import AskTools
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend, BackendError, Message, ModelRefusal
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.model.prompts.ask import build_ask_request, build_ask_system, engagement_summary
from unvarnish.model.structured import StructuredOutputError, complete_structured
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.ask")
ToolName = Literal["search_index", "get_unit", "get_module", "get_tool", "get_findings",
                   "grep_source"]
PREVIEW_CHARS = 300
HEX_ID_RE = re.compile(r"\b(?:cap:)?[0-9a-f]{12,16}\b")
PATH_RE = re.compile(r"(?<![\w/])([\w.\-]+(?:/[\w.\-]+)*\.[A-Za-z0-9]+)(:\d+(?:-\d+)?)?")
TOOL_REF_RE = re.compile(r"\btool:([a-z0-9][a-z0-9_-]*)")
NO_ANSWER = "The model did not produce an answer within the tool-call limit."


class AskStep(BaseModel):
    """One turn of the loop: a tool call or the final answer."""

    action: Literal["call", "answer"]
    tool: ToolName | None = None
    query: str | None = None
    tool_name: str | None = None  # a tool under review
    id: str | None = None
    category: str | None = None
    severity: str | None = None
    pattern: str | None = None
    max_results: int | None = None
    answer: str | None = None
    citations: list[str] = Field(default_factory=list)


class StepRecord(BaseModel):
    kind: Literal["call", "answer", "error"]
    tool: str | None = None
    args: dict = Field(default_factory=dict)
    result_preview: str | None = None
    usage: Usage = Field(default_factory=Usage)


class AskResult(BaseModel):
    question: str
    answer: str
    citations: list[str] = Field(default_factory=list)
    verified: bool = False
    completed: bool = False
    steps: list[StepRecord] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    tool_filter: str | None = None
    stopped_for_budget: bool = False


def call_args(step: AskStep, tool_filter: str | None) -> tuple[str, dict]:
    name = step.tool or ""
    under_review = step.tool_name or tool_filter
    args: dict = {}
    if name == "search_index":
        args = {"query": step.query, "tool": under_review}
    elif name in ("get_unit", "get_module"):
        args = {"id": step.id}
    elif name == "get_tool":
        args = {"name": under_review}
    elif name == "get_findings":
        args = {"tool": under_review, "category": step.category, "severity": step.severity}
    elif name == "grep_source":
        args = {"pattern": step.pattern, "tool": under_review, "max_results": step.max_results}
    return name, {k: v for k, v in args.items() if v is not None}


def find_citations(text: str, explicit: Sequence[str], index: AskIndex) -> list[str]:
    """Ids and paths that exist in the index, from the explicit list and the answer text."""
    ids = {d.id for d in index.docs}
    paths = {d.path for d in index.docs if d.path}
    tools = {d.tool for d in index.docs}
    found: list[str] = []

    def keep(c: str) -> None:
        if c not in found:
            found.append(c)

    candidates = list(explicit)
    candidates += HEX_ID_RE.findall(text)
    candidates += [f"tool:{t}" for t in TOOL_REF_RE.findall(text)]
    candidates += [p + (ln or "") for p, ln in PATH_RE.findall(text)]
    for c in candidates:
        c = c.strip()
        if c in ids or c in {f"tool:{t}" for t in tools}:
            keep(c)
            continue
        path = c.split(":", 1)[0]
        if path in paths and re.fullmatch(r"[^:]+(?::\d+(?:-\d+)?)?", c):
            keep(c)
    return found


def _preview(result: dict) -> str:
    text = json.dumps(result, ensure_ascii=False)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS - 1] + "…"


def run_question(eng: Engagement, backend: Backend, tools: AskTools, index: AskIndex,
                 question: str, *, tool_filter: str | None = None, budget: BudgetTracker,
                 effort: str | None, max_calls: int) -> AskResult:
    system = build_ask_system(engagement_summary(eng, index), max_calls)
    opening = question if tool_filter is None else f"{question}\n(Restrict to tool {tool_filter}.)"
    messages: list[Message] = [Message(role="user", content=opening)]
    result = AskResult(question=question, answer="", tool_filter=tool_filter)
    calls = 0
    forced = False
    while True:
        try:
            budget.check()
        except BudgetExceeded:
            result.answer = "Budget cap reached before an answer was produced."
            result.stopped_for_budget = True
            return result
        try:
            res = complete_structured(backend, build_ask_request(system, messages, effort),
                                      AskStep)
        except (ModelRefusal, StructuredOutputError) as exc:
            result.steps.append(StepRecord(kind="error", result_preview=str(exc)[:PREVIEW_CHARS]))
            result.answer = f"No answer: {exc}"
            return result
        except BackendError as exc:
            if getattr(exc, "fatal", False):
                raise
            result.steps.append(StepRecord(kind="error", result_preview=str(exc)[:PREVIEW_CHARS]))
            result.answer = f"No answer: {exc}"
            return result
        result.usage = result.usage + res.usage
        budget.add(res.usage)
        step = res.parsed
        if step.action == "call" and step.tool and calls < max_calls:
            name, args = call_args(step, tool_filter)
            tool_result = tools.dispatch(name, args)
            calls += 1
            result.steps.append(StepRecord(kind="call", tool=name, args=args,
                                           result_preview=_preview(tool_result),
                                           usage=res.usage))
            left = max_calls - calls
            messages += [
                Message(role="assistant", content=res.raw_text),
                Message(role="user", content=(
                    f"Result of {name}({json.dumps(args)}):\n"
                    f"{json.dumps(tool_result, ensure_ascii=False)}\n\n"
                    f"{left} tool call{'s' if left != 1 else ''} left.")),
            ]
            continue
        if step.action == "call":
            if not forced:
                forced = True
                messages += [
                    Message(role="assistant", content=res.raw_text),
                    Message(role="user", content=(
                        'You have no tool calls left. Answer now with action "answer" from '
                        "what you have, citing the ids or paths you relied on.")),
                ]
                continue
            result.answer = NO_ANSWER
            result.steps.append(StepRecord(kind="error", result_preview=NO_ANSWER,
                                           usage=res.usage))
            return result
        answer = redact_text((step.answer or "").strip())
        result.answer = answer or "(empty answer)"
        result.citations = find_citations(answer, step.citations, index)
        result.verified = bool(result.citations)
        result.completed = True
        result.steps.append(StepRecord(kind="answer", usage=res.usage,
                                       result_preview=answer[:PREVIEW_CHARS]))
        return result


def write_session(eng: Engagement, results: Sequence[AskResult], started: datetime) -> Path:
    eng.ask_sessions_dir.mkdir(parents=True, exist_ok=True)
    path = eng.ask_sessions_dir / f"{started.strftime('%Y%m%d-%H%M%S')}.md"
    lines = [f"# Ask session {started.strftime('%Y-%m-%d %H:%M UTC')}", ""]
    for i, r in enumerate(results, start=1):
        lines += [f"## Q{i}. {r.question}" + (f" (tool: {r.tool_filter})" if r.tool_filter else ""),
                  "", r.answer, ""]
        if r.verified:
            lines.append("Citations: " + ", ".join(f"`{c}`" for c in r.citations))
        elif r.completed:
            lines.append("**Unverified: no citations.**")
        else:
            lines.append("**No answer produced.**")
        calls = [s for s in r.steps if s.kind == "call"]
        if calls:
            lines += ["", "Tool calls:"]
            lines += [f"- `{s.tool}` {json.dumps(s.args)}" for s in calls]
        lines += ["", f"Tokens: {r.usage.total():,}", ""]
    path.write_text("\n".join(lines))
    return path
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_ask_loop.py -q 2>&1 | tail -3`
Expected: all PASS. The `AskStep` strict schema has no `title`-named field, and every field is nullable, so the fake server's autofill produces `action: "call"` (first enum value), which Task 4 relies on for the loop-limit CLI test.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/ask src/unvarnish/model/prompts/ask.py tests/test_ask_loop.py
git add src/unvarnish/ask/loop.py src/unvarnish/model/prompts/ask_system.md src/unvarnish/model/prompts/ask.py tests/test_ask_loop.py
git commit -m "feat: bounded ask loop with structured actions, citation checking, and sessions"
```

---

### Task 4: `ask` command, docs, smoke

**Files:**
- Modify: `src/unvarnish/cli.py`, `README.md`, `scripts/smoke.sh`
- Test: `tests/test_cli_ask.py`

**Interfaces:**
- Consumes: `load_or_build_index`, `AskTools`, `run_question`, `write_session`, `resolve_backend`, `resolve_model_ref`, `NoModelConfigured`, `BudgetTracker`, `record_cost`, `ENGAGEMENT_TOOL`, `setup_run_logging`.
- Produces: `unvarnish ask ["QUESTION"] [--tool NAME] [-v] [-e DIR]`: one question, or an interactive prompt loop until `exit`, `quit`, an empty line, or EOF. Prints the answer, the citations, and a warning for an unverified answer; writes one session file per invocation; records cost under `(engagement)` phase `ask`. Exit 0 on answers (verified or not), 1 when any question got no answer, 2 for configuration or backend errors, 3 on a budget stop.

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_ask.py`:

```python
import json

from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()


def _engagement(tmp_path, synthetic_repo, fake, **extra) -> Engagement:
    eng = Engagement.create(tmp_path / "acme", client="Acme")
    conf = {**eng.config.model_dump(), **model_config(fake), **extra}
    eng.config = EngagementConfig.model_validate(conf)
    eng.save_config()
    ingest_tool(eng, "alpha", str(synthetic_repo), "repo")
    fake.autofill = True
    assert runner.invoke(app, ["run", "-e", str(eng.root)]).exit_code == 0
    return eng


def _answer(text: str, citations=None) -> str:
    return json.dumps({"action": "answer", "answer": text, "citations": citations or []})


def test_ask_without_model_exits_2(tmp_path, synthetic_repo):
    eng = Engagement.create(tmp_path / "acme")
    ingest_tool(eng, "alpha", str(synthetic_repo), "repo")
    out = runner.invoke(app, ["ask", "anything?", "-e", str(eng.root)])
    assert out.exit_code == 2 and "needs a model" in out.output


def test_ask_one_shot_answers_and_saves_session(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("The entry point is app.py:5.", ["app.py:5"]))
    out = runner.invoke(app, ["ask", "Where is the entry point?", "-e", str(eng.root)])
    assert out.exit_code == 0, out.output
    assert "The entry point is app.py:5." in out.output and "app.py:5" in out.output
    assert "unverified" not in out.output.lower()
    sessions = list(eng.ask_sessions_dir.glob("*.md"))
    assert len(sessions) == 1 and "Where is the entry point?" in sessions[0].read_text()
    assert eng.index_file.exists()
    cost = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "ask" in cost.output


def test_ask_uncited_answer_warns(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("Trust me."))
    out = runner.invoke(app, ["ask", "Why?", "-e", str(eng.root)])
    assert out.exit_code == 0 and "unverified" in out.output.lower()


def test_ask_interactive_until_exit(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    fake_llm.script(_answer("One, see README.md.", ["README.md"]),
                    _answer("Two, see README.md.", ["README.md"]))
    out = runner.invoke(app, ["ask", "-e", str(eng.root)], input="first?\nsecond?\nexit\n")
    assert out.exit_code == 0, out.output
    assert "One, see README.md." in out.output and "Two, see README.md." in out.output
    session = next(eng.ask_sessions_dir.glob("*.md")).read_text()
    assert "## Q1. first?" in session and "## Q2. second?" in session


def test_ask_loop_limit_exits_1(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm, ask={"max_tool_calls": 2})
    # autofill answers every turn with action "call" (first enum value), so the loop hits
    # the limit, is asked to answer, still calls, and gives up
    out = runner.invoke(app, ["ask", "Everything?", "-e", str(eng.root)])
    assert out.exit_code == 1, out.output
    assert "did not produce an answer" in out.output


def test_ask_unknown_tool_filter_exits_2(tmp_path, synthetic_repo, fake_llm):
    eng = _engagement(tmp_path, synthetic_repo, fake_llm)
    out = runner.invoke(app, ["ask", "x?", "--tool", "nope", "-e", str(eng.root)])
    assert out.exit_code == 2 and "unknown tool" in out.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli_ask.py -q 2>&1 | tail -3`
Expected: FAIL (`ask` is not a command: exit code 2 with "No such command" for every test except the first, whose message differs).

- [ ] **Step 3: Implement the command**

In `src/unvarnish/cli.py` add imports:

```python
from datetime import UTC, datetime

from unvarnish.ask.index import load_or_build_index
from unvarnish.ask.loop import run_question, write_session
from unvarnish.ask.tools import AskTools
from unvarnish.model.budget import BudgetTracker, load_ledger, record_cost
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.compare import ENGAGEMENT_TOOL, EngagementContext, comparison_phases, run_comparison
from unvarnish.schemas.cost import CostEntry, Usage
```

(merge with the existing import lines; ruff will sort them). Then add the command after `compare`:

```python
@app.command()
def ask(
    question: str | None = typer.Argument(None, help="One question; omit for a session."),
    tool: str | None = typer.Option(None, "--tool", help="Restrict to one tool."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detail on the console."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Ask questions about the analysed tools; answers cite artifact ids and file paths."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, None)
    if tool is not None and tool not in names:
        err_console.print(f"[red]error:[/red] unknown tool {tool!r}; known: {', '.join(names)}")
        raise typer.Exit(code=2)
    try:
        backend = resolve_backend(eng, "ask")
    except NoModelConfigured as exc:
        err_console.print("[red]error:[/red] ask needs a model: set models.default in "
                          "engagement.yaml")
        raise typer.Exit(code=2) from exc
    except BackendConfigError as exc:
        err_console.print(f"[red]error:[/red] {exc}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    log_path = setup_run_logging(eng, verbose)
    index, rebuilt = load_or_build_index(eng)
    if rebuilt:
        console.print(f"[dim]Index built: {len(index.docs)} documents.[/dim]")
    tools = AskTools(eng, index)
    ref = resolve_model_ref(eng.config, "ask")
    effort = ref.effort if ref else None
    budget = BudgetTracker(eng.config.budget.max_tokens)
    max_calls = eng.config.ask.max_tool_calls
    started = datetime.now(UTC)
    results = []
    any_unanswered = False
    stopped = False

    def one(q: str) -> None:
        nonlocal any_unanswered, stopped
        res = run_question(eng, backend, tools, index, q, tool_filter=tool, budget=budget,
                           effort=effort, max_calls=max_calls)
        results.append(res)
        write_session(eng, results, started)
        if res.usage.total():
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase="ask", backend=backend.name,
                                       model=backend.model, usage=res.usage,
                                       at=datetime.now(UTC)))
        console.print()
        console.print(res.answer, soft_wrap=True)
        if res.verified:
            console.print("[dim]Citations:[/dim] " + ", ".join(res.citations))
        elif res.completed:
            console.print("[yellow]Unverified: the answer cites no artifact ids or paths.[/yellow]")
        else:
            any_unanswered = True
        stopped = stopped or res.stopped_for_budget
        calls = sum(1 for s in res.steps if s.kind == "call")
        console.print(f"[dim]{calls} tool call(s), {res.usage.total():,} tokens[/dim]")

    try:
        if question:
            one(question)
        else:
            console.print("Interactive session; type a question, or 'exit' to finish.")
            while True:
                try:
                    q = console.input("[bold]ask>[/bold] ").strip()
                except EOFError:
                    break
                if not q or q.lower() in ("exit", "quit"):
                    break
                one(q)
                if stopped:
                    break
    except BackendUnavailable as exc:
        err_console.print(f"[red]error:[/red] {exc}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    if results:
        console.print(f"[dim]Session saved to ask-sessions/{started.strftime('%Y%m%d-%H%M%S')}.md"
                      f" · log: {log_path}[/dim]")
    if stopped:
        err_console.print("Budget cap reached.")
        raise typer.Exit(code=3)
    if any_unanswered:
        raise typer.Exit(code=1)
```

`console.input` reads from stdin, which `CliRunner(input=...)` supplies; an empty line or EOF ends the session.

- [ ] **Step 4: README and smoke**

In `README.md`, after the "Comparing tools" section:

```markdown
## Asking questions

    unvarnish ask "Which tool talks to Stripe, and from where?"
    unvarnish ask --tool expense-bot        # interactive session restricted to one tool

Needs a model. Answers come from a bounded loop (at most `ask.max_tool_calls` tool calls,
default 12) over five read-only tools: a BM25 search of unit purposes, module summaries,
findings, and capabilities; the unit, module, and tool artifacts; filtered findings; and a
regex grep over the tool's source that skips excluded files. Every answer must cite artifact
ids or file paths; one that does not is printed with an "unverified" warning and marked so in
the session file under `ask-sessions/`. The search index is built on first use under
`cache/index/` and rebuilt when any tool's analysis changes. Tool results and answers pass
through the secrets redactor before they reach the console or disk.
```

In `scripts/smoke.sh`, after the `compare` line:

```bash
uv run unvarnish ask "What does the scanners tool do, and what is its most serious finding?" -e "$E" || echo "ask exited $?"
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest -q 2>&1 | tail -2`
Expected: the whole suite PASSES.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check .
git add src/unvarnish/cli.py tests/test_cli_ask.py README.md scripts/smoke.sh
git commit -m "feat: ask command with one-shot and interactive sessions, docs and smoke"
```

---

## Self-review notes

**Spec coverage.** 3 (`ask ["QUESTION"] [--tool NAME]`, interactive without a question: Task 4). 4 (`cache/index/`, `ask-sessions/<timestamp>.md`: Tasks 1, 3). 9 tools table (six tools with the named arguments: Task 2), loop with `ask.max_tool_calls` (Task 3), citation requirement with "unverified" marking and console warning, no rewriting (Tasks 3, 4), structured-output action schema (Task 3), lazily built pure-Python BM25 index rebuilt on change (Task 1), sessions with questions, answers, citations (Task 3). 10 (`ask.max_tool_calls` already in config). 13 (tool errors recorded in the transcript, never fatal: Tasks 2, 3).

**Known deviations, to ledger at execution.** The structured action schema is used on every backend, not only "weak tool-calling backends": native tool use would need new protocol methods on both backends and the fake server, and the structured loop already works everywhere. The index is rebuilt when any of six per-tool artifacts changes (a superset of "any `tool.json` is newer"). `get_module` accepts a file path as well as a module id, since models cite paths. Exit code 1 for "no answer produced" is this plan's choice; the spec is silent.

**Type consistency checked.** `AskIndex.search(query, tool, k)` consumed by `AskTools.search_index`; `AskTools.dispatch(name, args)` consumed by the loop with the arg names from `call_args`; `AskStep` field names match the prompt's instructions and `call_args`; `run_question` signature identical in Tasks 3 and 4; `write_session(eng, results, started)` in both; `ENGAGEMENT_TOOL` from `phases/compare.py` reused for cost. `build_ask_system` imports `AskStep` locally to avoid the `prompts.ask` ↔ `ask.loop` cycle.
