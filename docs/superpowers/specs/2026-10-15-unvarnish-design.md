# Unvarnish: Design Specification

**Date:** 2026-10-15
**Status:** Draft for review
**Repo:** https://github.com/Bonham-Technologies/Unvarnish
**Domain:** unvarnish.com

---

## 1. Purpose

Unvarnish is a portable command-line tool for vetting internally built, often
AI-generated ("vibe-coded") software at client organisations. A consultant points
it at one or more tools, as git repositories or loose piles of files in any
language, and it runs unattended to produce a set of documents that describe each
tool honestly: what it is, how it is built, what is wrong with it, what it
actually does, and how several overlapping tools could be consolidated into one.

The documents exist to do two jobs at once. They give the engineer or IT team who
inherits the tool an accurate architectural picture, and they give leadership an
unflinching, evidence-backed account of the risk they are carrying. Unvarnish
never softens a finding to make a report more comfortable.

### 1.1 Goals

- Run end-to-end without supervision on a repo or file pile and finish inside a
  working day on large codebases.
- Work online against Anthropic models and air-gapped against on-prem
  OpenAI-compatible endpoints (vLLM, Ollama, LM Studio, Azure OpenAI, internal
  gateways) with no code change, only configuration.
- Be language agnostic. Rust, TypeScript, Python, Go, Java, HTML, and anything
  else degrade gracefully rather than fail.
- Handle pathological inputs, including single files of 70K+ lines.
- Produce per-tool architecture, findings, and requirements documents plus a
  cross-tool comparison and consolidation proposal.
- Keep Markdown as the source of truth and export to DOCX, PDF, and
  self-contained HTML with the consultant's branding.
- Persist structured analysis so the consultant can ask questions afterwards
  without re-reading the code.
- Make every finding traceable to evidence: file, line range, and whether a
  deterministic scanner or a model produced it.
- Ship as a single portable artifact (Docker image) and as a laptop install.

### 1.2 Non-goals

- Pull-request or diff review. Unvarnish reviews whole codebases.
- Automated remediation or code generation.
- A web UI or multi-user server. It is a single-operator CLI.
- Replacing the consultant's judgment in requirements abstraction and target
  architecture. Unvarnish feeds that work; it does not finish it.
- Bedrock and Vertex native backends. Both have OpenAI-compatible fronts in
  practice; add native adapters only when a client demands them.

### 1.3 Users

- **Primary:** the consultant running the engagement. Technical, runs the CLI,
  edits templates, reads JSON when needed.
- **Secondary readers:** the client's engineering or IT staff (architecture and
  requirements documents) and the client's leadership (findings executive
  summary and "by the numbers").

---

## 2. Concepts and vocabulary

| Term | Meaning |
|---|---|
| **Engagement** | One client project. A directory on disk holding config, all tools under review, and all outputs. |
| **Tool** | One piece of software under review. Has a source tree, inventory, analysis, and documents. |
| **Phase** | One idempotent pipeline step that reads inputs from disk and writes a versioned JSON artifact. |
| **Unit** | The smallest chunk of source sent to a model: a function, class, script block, or line window. |
| **Module** | A grouping of units, normally one file or one directory. |
| **Finding** | A single problem, with severity, category, evidence, and provenance. |
| **Capability** | Something the tool lets an actor do; the atom of the requirements inventory. |
| **Scanner** | A deterministic, model-free check that emits findings or inventory facts. |
| **Backend** | A model provider adapter: `anthropic` or `openai_compatible`. |

---

## 3. CLI surface

Command name: `unvarnish`. Short alias `unv` installed alongside it.

```
unvarnish init <dir> [--client NAME]
    Create an engagement directory and engagement.yaml.

unvarnish add <name> (--repo URL|PATH | --files PATH) [--branch B] [--link]
    Register a tool. --repo clones with full history (or copies a local repo
    including .git). --files copies a loose directory. --link records a path
    instead of copying, for very large trees that must stay in place.

unvarnish run [TOOL ...] [--phase PHASE] [--force] [--dry-run]
    Run all outstanding phases for the named tools (default: all tools).
    --phase runs one phase. --force ignores freshness and reruns.
    --dry-run prints the plan and the token estimate without calling a model.

unvarnish compare [--force]
    Run the cross-tool phase. Works with one tool (skips matrix and proposal).

unvarnish ask ["QUESTION"] [--tool NAME]
    Q&A over the engagement. With no question, opens an interactive session.

unvarnish export [--format docx|pdf|html|all] [--template PATH] [--doc DOC ...]
    Render documents into exports/.

unvarnish status            Phase progress per tool, failures, unanalysed units.
unvarnish cost              Tokens and estimated spend per phase, versus budget.
unvarnish config check      Validate engagement.yaml and probe the backend.
unvarnish scanners list     List registered scanners and their thresholds.
unvarnish cache clear       Delete cached model responses (confirmation required).
```

All commands run from inside an engagement directory or take `--engagement DIR`.
Exit codes: 0 success, 1 run completed with recorded failures, 2 configuration or
backend error, 3 budget cap reached.

---

## 4. Engagement workspace

```
acme-2026-10/
  engagement.yaml
  tools/
    expense-bot/
      tool.yaml                  # name, origin, ingest metadata
      source/                    # clone or copy (absent when --link)
      inventory/
        census.json              # file census, languages, classification
        metrics.json             # size/complexity metrics
        dependencies.json        # declared deps + advisories
        git.json                 # history statistics (absent for file piles)
        scanner-findings.json    # all deterministic findings
      analysis/
        units/<unit-id>.json     # one per unit
        modules/<module-id>.json
        tool.json                # tool-level model
        findings.json            # model findings after verification
        capabilities.json        # requirements inventory
        failures.json            # units/phases that could not complete
      docs/
        architecture.md
        findings.md
        requirements.md
  comparison/
    comparison.json
    comparison.md
  exports/
    <doc>-<tool>-<timestamp>.<ext>
  cache/
    responses/<sha256>.json      # content-addressed model responses
    index/                       # BM25 index for ask mode
  logs/
    run-<timestamp>.log
  ask-sessions/
    <timestamp>.md
```

Design rules:

- **JSON is the source of truth.** Markdown documents are rendered from JSON.
  Editing Markdown by hand is allowed for the final deliverable, but a re-render
  overwrites it. The export step therefore always starts from the latest render.
- **Every artifact carries `schema_version`, `produced_by` (phase name and tool
  version), `produced_at`, and `inputs_hash`.** Phases compare `inputs_hash`
  against current inputs to decide freshness.
- **Secrets never live in the engagement.** Model keys come from environment
  variables or the OS keychain. The engagement directory is designed to be
  zipped and moved.
- **The engagement is portable.** Absolute paths are never stored; `--link`
  targets are stored relative to the engagement where possible and flagged as
  external otherwise.

---

## 5. Data model

All schemas are Pydantic v2 models. Every artifact is validated on write and on
read. Key models:

### 5.1 Finding

```
Finding
  id: str                  # stable hash of (tool, category, title, primary evidence)
  tool: str
  category: enum           # see taxonomy below
  severity: enum           # critical | high | medium | low | info
  title: str
  summary: str             # one paragraph, plain language
  impact: str              # business-terms consequence
  remediation: str
  evidence: list[Evidence] # at least one, enforced
  source: enum             # scanner | model
  scanner: str | None      # scanner name when source == scanner
  model: str | None        # model id when source == model
  verification: enum|None  # confirmed | downgraded | rejected | not_required
  confidence: float|None   # model findings only
  tags: list[str]

Evidence
  path: str                # relative to tool source root
  line_start: int | None
  line_end: int | None
  excerpt: str | None      # redacted for secrets
  fingerprint: str | None  # stable hash of the raw match, for secrets
  note: str | None
```

**Category taxonomy** (fixed, configurable per engagement, used for cross-tool
comparability): `security`, `data_handling`, `maintainability`, `reliability`,
`operability`, `compliance`, `process`, `dependency`.

### 5.2 Unit, Module, ToolModel

```
Unit
  id, tool, module_id, path, language
  kind: function | class | method | script_block | style_block | markup | window | file
  line_start, line_end, token_estimate
  split_method: structural | windowed
  extraction: UnitExtraction | None

UnitExtraction
  purpose: str
  interface: list[str]              # public functions/endpoints/exports
  external_calls: list[ExternalRef] # system, kind (http|db|file|queue|env|process), detail
  data_read: list[str]
  data_written: list[str]
  auth_behaviour: str | None
  error_handling: str | None
  risks: list[str]
  candidate_findings: list[Finding]
  confidence: float

Module
  id, tool, path, unit_ids
  summary, responsibilities, dependencies_in, dependencies_out
  candidate_findings

ToolModel
  tool, purpose, actors, entry_points, data_stores, external_systems
  internal_stack, module_map, data_flows, deployment_assumptions
  build_history_summary                # from git.json
  capabilities: list[Capability]

Capability
  id, tool, actor, action, object, description
  implementing_modules: list[str]
  data_touched: list[str]
  implicit: bool                       # true when inferred from hardcoded rules
  evidence: list[Evidence]
```

### 5.3 Comparison

```
Comparison
  tools: list[str]
  capability_matrix: list[MatrixRow]   # normalised capability, per-tool implementers
  integration_map: list[IntegrationRow]
  risk_table: list[RiskRow]            # per-tool "by the numbers"
  consolidation: Consolidation | None
  
Consolidation
  union_capabilities, abstract_requirements
  recommended_approach_per_capability  # which tool's approach is soundest, and why
  gaps, open_questions
```

---

## 6. Pipeline

Phases run in dependency order. Each is a class with `name`, `inputs()`,
`outputs()`, and `run(ctx)`. The runner skips a phase when its outputs exist and
`inputs_hash` matches, unless `--force`.

```
ingest ─> inventory ─> git ─> scan ─> split ─> extract ─> rollup_modules
       ─> rollup_tool ─> verify ─> render        (per tool)
                                      └──> compare ─> render_comparison   (engagement)
```

### 6.1 ingest

- `--repo`: `git clone --no-checkout` then checkout the requested branch, keeping
  full history. Local repo paths are copied including `.git`.
- `--files`: recursive copy.
- Exclusions are computed, not applied: `.gitignore` matches, vendored
  directories, build output, binaries, and lockfiles are flagged `excluded` with
  a reason but remain in the census so their size counts. "Half the repo is
  committed `node_modules`" is reported, not hidden.
- Writes `tool.yaml` with origin, commit SHA when applicable, and ingest time.

### 6.2 inventory

Writes `census.json`, `metrics.json`, `dependencies.json`.

- **Census.** Per file: path, bytes, lines, language (tree-sitter language pack
  detection by extension and shebang, with content sniffing fallback),
  classification (`source | config | test | docs | generated | vendored | data |
  binary`), excluded flag and reason.
- **Framework detection.** From manifests (`package.json`, `pyproject.toml`,
  `requirements*.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle*`,
  `*.csproj`, `Gemfile`, `composer.json`) and import patterns.
- **Metrics.** Per file: line count, function count, max function length, max
  nesting depth, comment ratio. For HTML: separate byte and line counts for
  inline `<script>`, inline `<style>`, and markup. Files over configurable
  thresholds are flagged. Unknown languages get line-based metrics only.
- **Dependencies.** Declared dependencies with version constraints per manifest.
  Advisory lookup via `osv-scanner --offline` against a local database when the
  binary is present (bundled in Docker, pre-seeded; refreshable online).
  Absent binary: dependency list only, with a "not checked" note in the report.

### 6.3 git

Skipped with a recorded reason when no `.git` exists. Writes `git.json`:

- Commit count, first and last commit dates, active span, active days.
- Authors with commit and line-change share. Bus factor computed as the smallest
  author set covering 80% of changes.
- Commit size distribution; commits over a configurable line threshold listed.
- Velocity: commits and lines changed per week.
- Churn hotspots: files by change count and by lines changed.
- AI tooling fingerprints: presence of `CLAUDE.md`, `.cursorrules`, `.cursor/`,
  `.github/copilot-instructions.md`, `.aider*`, `.windsurfrules`, `AGENTS.md`;
  `Co-Authored-By` trailers naming known assistants; commit message patterns.
  Reported as neutral evidence of how the tool was built.

### 6.4 scan

Runs every registered scanner and writes `scanner-findings.json`. Scanners
implement:

```python
class Scanner(Protocol):
    name: str
    category: Category
    def run(self, ctx: ToolContext) -> list[Finding]: ...
```

Built-in scanners:

| Scanner | What it finds | Default severity |
|---|---|---|
| `secrets` | API keys, tokens, passwords, connection strings, private keys. Regex rule set plus Shannon entropy on string literals. Scans working tree **and full git history** via `git log -p`. Uses `gitleaks` when present for its larger rule set; built-in rules otherwise. Excerpts redacted; fingerprint stored. | critical (history-only: high) |
| `oversized_files` | Files and functions over thresholds. Separate thresholds for HTML inline script. | high / medium |
| `hardcoded_infra` | URLs, IPs, hostnames, ports, absolute file paths, email addresses. Also feeds the architecture I/O map. | medium |
| `hygiene` | Missing tests, CI, README, license, linter config; TODO/FIXME/HACK density; empty catch blocks and bare excepts by language. | medium / low |
| `dependencies` | Known vulnerabilities from `dependencies.json`; unpinned versions; abandoned packages (last release age when online). | per advisory |
| `vendored_bulk` | Committed dependency or build directories; large binaries. | medium |
| `bus_factor` | Single-author concentration from `git.json`. | high when one author > 90% |
| `generated_bulk` | Single commits adding more than N lines. Evidence of unreviewed bulk generation. | medium |

Thresholds live under `scanners:` in `engagement.yaml`. Adding a scanner means
one new file registered via an entry point group `unvarnish.scanners`, so
client-specific checks can live in a private package.

Scanner findings are tagged `source: scanner` and `verification: not_required`.
No later phase may alter or drop them.

### 6.5 split

Produces units. Target size `unit_tokens` (default 8,000; per-backend override).

1. **Structural split.** Tree-sitter parses the file and the splitter walks
   top-level and nested definitions, emitting function/class/method units and
   grouping small adjacent definitions until the target size is reached.
2. **HTML and templates.** Markup, each `<script>` block, and each `<style>` block
   become separate streams. Script blocks are parsed as JavaScript and split
   structurally. Markup is split at top-level element boundaries.
3. **Fallback windowing.** Anything still over target, or in an unsupported
   language, is windowed with 10% overlap and tagged `split_method: windowed`.
   The render phase lists windowed regions in the findings appendix and the
   `oversized_files` scanner has already flagged them.
4. **Skips.** Excluded files, binaries, and `data` classification are not split.
   Generated files are split but tagged, and extraction uses a reduced prompt
   that asks only for purpose and external calls, since detailed review of
   generated code is rarely worth the tokens.

Every unit records its byte and line range so evidence can be mapped back.

### 6.6 extract

For each unit, one structured-output call producing `UnitExtraction`.

- **Prompt structure.** Fixed system prompt (cached prefix on Anthropic) with the
  schema and the finding taxonomy; tool-level context (language, framework,
  path); a compact neighbourhood summary made of the `purpose` fields of
  already-extracted units in the same module; the unit source.
- **Ordering.** Units within a module are extracted sequentially so the
  neighbourhood summary grows; modules run in parallel up to `concurrency`.
- **Validation.** Response parsed against the schema. Candidate findings
  without evidence inside the unit's line range are dropped with a log entry.
- **Retries.** Schema failure: retry once with the validation error appended.
  Second failure: a repair call that receives the malformed output and the
  schema. Third failure: record in `failures.json` and continue.

### 6.7 rollup_modules and rollup_tool

- **Module rollup.** One call per module over its unit extractions, producing
  `Module`. Emits candidate findings that only appear at module level, such as
  duplicated logic or inconsistent error handling across functions.
- **Tool rollup.** One or more calls over module summaries, producing
  `ToolModel` including capabilities. For tools with many modules the rollup is
  hierarchical: directory-level rollups first, then the tool.
- Both write candidate findings into a staging list for verification.

### 6.8 verify

- Collects all model candidate findings. Deduplicates by `Finding.id`, merging
  evidence lists.
- Findings rated `high` or `critical` get an independent verification call that
  sees only the evidence excerpts and the claim, with no access to the original
  reasoning, and returns `confirmed | downgraded | rejected` with a one-line
  reason. Downgraded findings drop one severity level.
- Lower severities are marked `verification: not_required`.
- Writes `findings.json`. Rejected findings are retained with their status for
  the consultant's inspection but are excluded from documents.

### 6.9 render

Renders the three per-tool documents from JSON using Jinja2 templates. The
model writes only designated prose blocks; every number, table, and list comes
from JSON. See section 8.

### 6.10 compare and render_comparison

Runs when at least one tool has `tool.json`.

- **Capability normalisation.** One call over all tools' capabilities producing
  a normalised capability list with per-tool mappings. This becomes the matrix.
- **Integration map and risk table.** Pure JSON joins, no model.
- **Consolidation proposal.** Only when two or more tools. One call over the
  matrix, integration map, and tool models producing `Consolidation`.
- Renders `comparison.md`.

### 6.11 Budget and estimation

Before any model phase, the runner estimates tokens from unit count and sizes,
plus fixed per-call overheads, and prints the estimate. A cost figure is shown
only when `budget.prices` is configured; otherwise tokens alone are reported. `--dry-run` stops there. During the run, actual
usage accumulates in `cost.json`. If `budget.max_tokens` is set and exceeded,
the run stops cleanly at the next unit boundary with exit code 3; a later `run`
resumes.

### 6.12 Caching and resumability

Every model call is keyed by SHA-256 of (backend, model, full prompt, schema
version). Responses are stored under `cache/responses/`. A crashed run resumes
by rerunning phases; cached units cost nothing. `--force` bypasses freshness
checks but still reads the cache; a separate `cache clear` subcommand exists.

---

## 7. Model layer

### 7.1 Adapter interface

```python
class Backend(Protocol):
    name: str
    capabilities: BackendCapabilities   # json_schema, tool_calling, context_window, prompt_caching
    def complete(self, req: CompletionRequest) -> CompletionResponse: ...

CompletionRequest
  messages, schema: type[BaseModel] | None, tools: list[ToolSpec] | None,
  max_tokens, temperature, cache_prefix: bool

CompletionResponse
  text | parsed: BaseModel | tool_calls, usage: Usage, model: str, cached: bool
```

### 7.2 Backends

- **anthropic.** Uses the official SDK. Structured output via native JSON
  schema support. Prompt caching on the fixed prefix for extraction. Tool use
  for ask mode.
- **openai_compatible.** Uses the OpenAI SDK against a configurable `base_url`.
  Structured output via `response_format` JSON schema when the endpoint declares
  support; otherwise **JSON-in-prompt mode**: schema embedded in the prompt,
  response extracted from the first balanced JSON object, validated identically.
  Tool calling when supported; otherwise ask mode uses the structured fallback
  (section 9).

Capabilities are declared in config and probed on `config check`, which sends a
tiny schema-constrained request and records what worked.

### 7.3 Per-phase model selection

```yaml
models:
  default: { backend: anthropic, model: claude-opus-5-5 }
  phases:
    extract: { backend: onprem, model: qwen3-coder-72b }
    verify:  { backend: anthropic, model: claude-opus-5-5 }
```

Mixed deployments (cheap extraction on-prem, expensive synthesis on Claude) are
supported when a site allows both.

### 7.4 Concurrency and rate limits

A per-backend semaphore sized by `concurrency`. HTTP 429 and 5xx trigger
exponential backoff with jitter; a configurable ceiling of consecutive failures
aborts the run with exit code 2.

---

## 8. Documents

### 8.1 Rendering principle

Templates (Jinja2, Markdown output) own structure. Within a template, a block
marked `{% prose "executive_summary" %}` is filled by a model call that
receives the surrounding JSON context and a tone instruction. Everything else
is rendered directly from JSON. Consultants can override any template by
placing a copy under `templates/` in the engagement or in the user config
directory.

### 8.2 Tone

A `tone` setting (`direct` default, `measured` optional) is injected into
every prose block prompt. The `direct` instruction: state problems plainly,
quantify where possible, never hedge or soften a scanner finding, avoid jargon,
write for a reader who does not code. The prompt forbids phrases that minimise
("minor", "simply", "just") when describing high or critical findings.

### 8.3 architecture.md

1. Purpose and users (prose).
2. Context diagram: inputs, outputs, external systems (diagram from
   `ToolModel.external_systems` and `data_flows`).
3. Internal stack: languages, frameworks, runtime, from inventory.
4. Module map and interactions (table plus diagram).
5. Data stores and flows.
6. Deployment and runtime assumptions (prose over `ToolModel`).
7. How this was built: git summary, velocity, authorship, AI tooling
   fingerprints (table plus one prose paragraph).
8. Analysis coverage: units analysed, windowed, failed.

### 8.4 findings.md

1. **Executive summary** (prose, written for leadership): what the tool is,
   headline risks in plain language, consequence of leaving it as is.
2. **By the numbers**: table of size, largest files, test presence, bus factor,
   secret count (current and historical), dependency vulnerabilities by
   severity, hardcoded hosts, AI tooling indicators.
3. **Findings by severity**: each with title, category, source badge, evidence
   with path and lines, impact, remediation. Scanner findings appear before
   model findings at equal severity.
4. **Not analysed**: excluded files, windowed regions, failed units, skipped
   scanners and why.

### 8.5 requirements.md

1. Actors.
2. Capability inventory: "actor can action object" rows with implementing
   modules and data touched. Implicit capabilities flagged and explained.
3. Data inventory: every store and external system, with which capabilities
   use it.
4. Business rules discovered in code (hardcoded lists, thresholds, exemptions).
5. Open questions for stakeholder interviews (prose: what the code could not
   tell us).

### 8.6 comparison.md

1. Tools reviewed (one paragraph each).
2. Capability matrix.
3. Integration and data map.
4. Risk comparison table.
5. Consolidation proposal (prose over `Consolidation`): union of
   capabilities, abstract requirements serving the widest population,
   recommended approach per capability, gaps, open questions. Explicitly
   labelled a starting point for the consultant's architecture work.

### 8.7 Diagrams

A `Diagram` model (nodes, edges, groups) is produced from JSON. Two emitters:
Mermaid for Markdown, and SVG via Graphviz `dot` for exports. Same model, two
renderings, no duplicated logic.

---

## 9. Ask mode

A bounded agentic loop, the only one in the system.

**Tools exposed to the model:**

| Tool | Behaviour |
|---|---|
| `search_index(query, tool?)` | BM25 over unit purposes, module summaries, finding titles and summaries, capability descriptions. Returns ids and snippets. |
| `get_unit(id)` / `get_module(id)` / `get_tool(name)` | Returns the JSON artifact. |
| `get_findings(tool?, category?, severity?)` | Filtered findings. |
| `grep_source(pattern, tool, max_results)` | Regex search over source files, respecting exclusions. |

**Loop.** System prompt describes the engagement and tools. Each turn: model
call, execute requested tools, append results, repeat until a final answer or
`ask.max_tool_calls` (default 12). The final answer must cite artifact ids or
paths. If the answer contains no citations, the transcript marks it
"unverified" and the console prints a warning; no automatic rewriting.

**Fallback for weak tool-calling backends.** A structured-output schema
`{ action: "call" | "answer", tool, args, answer }` drives the same loop.

**Index.** Built lazily on first `ask` from analysis JSON; rebuilt when any
`tool.json` is newer than the index. Pure-Python BM25 (`rank-bm25` or an
in-house implementation) so no embedding model is required.

**Sessions** are saved to `ask-sessions/<timestamp>.md` with questions,
answers, and citations.

---

## 10. Configuration

`engagement.yaml`:

```yaml
schema_version: 1
client: Acme Corp
consultant: Bonham Technologies
tools: []                         # tool names only, managed by `add`; per-tool metadata lives in tools/<name>/tool.yaml
backends:
  anthropic:
    type: anthropic
    api_key_env: ANTHROPIC_API_KEY
  onprem:
    type: openai_compatible
    base_url: http://llm.acme.internal:8000/v1
    api_key_env: ONPREM_LLM_KEY
    capabilities: { json_schema: true, tool_calling: false, context_window: 32768 }
models:
  default: { backend: anthropic, model: claude-opus-5-5 }
  phases: {}
pipeline:
  unit_tokens: 8000
  concurrency: 8
budget:
  max_tokens: null
  prices: null          # { input_per_mtok: X, output_per_mtok: Y } from the provider's rate card
scanners:
  oversized_files: { file_lines: 1500, function_lines: 150, html_script_lines: 500 }
  bus_factor: { single_author_share: 0.9 }
  generated_bulk: { commit_lines: 2000 }
report:
  tone: direct
  templates_dir: null
  branding:
    reference_docx: null
    html_css: null
ask:
  max_tool_calls: 12
```

User-level defaults at `~/.config/unvarnish/config.yaml` are merged underneath
the engagement file. Environment variables override both for key fields
(`UNVARNISH_BACKEND`, `UNVARNISH_MODEL`).

Secrets are read from the named environment variable, or from the OS keychain
via `keyring` when `api_key_keychain: <service>` is set. They are never written
to disk by Unvarnish.

---

## 11. Export

`unvarnish export` converts rendered Markdown with `pandoc`:

- **DOCX:** `--reference-doc` from `report.branding.reference_docx`, falling
  back to a bundled neutral reference.
- **HTML:** self-contained single file with embedded CSS from
  `report.branding.html_css` or the bundled stylesheet; diagrams inlined as
  SVG.
- **PDF:** via pandoc's HTML route using `weasyprint`, avoiding a LaTeX
  dependency.

Diagrams are rendered to SVG with Graphviz before conversion. If `pandoc` or
`dot` is missing on a laptop install, the command explains how to install them
and exits 2. The Docker image bundles both.

---

## 12. Distribution

- **Python package** `unvarnish` on PyPI, Python 3.13+ (3.12+ until UNVAR-27), installed with
  `uv tool install unvarnish`. Console scripts `unvarnish` and `unv`.
- **Docker image** `ghcr.io/bonham-technologies/unvarnish` bundling Python,
  tree-sitter grammars, pandoc, Graphviz, weasyprint, gitleaks, osv-scanner, and
  a seeded OSV database. Engagement directory mounted as a volume. Exportable
  with `docker save` for air-gapped transfer.
- Versioning: semantic. Artifact `schema_version` bumps are documented with a
  migration note; the runner refuses to mix incompatible schema versions in one
  engagement without `--migrate`.

### 12.1 Technology choices

| Concern | Choice |
|---|---|
| Language | Python 3.13+ (3.12+ until UNVAR-27) |
| Packaging | uv, hatchling |
| CLI | Typer, Rich for output |
| Schemas | Pydantic v2 |
| Parsing | tree-sitter, tree-sitter-language-pack |
| Git | subprocess `git` (no GitPython dependency) |
| Model SDKs | anthropic, openai |
| HTTP | httpx |
| Templates | Jinja2 |
| Search | rank-bm25 |
| Diagrams | graphviz (Python binding) + Mermaid emitter |
| Export | pandoc, weasyprint |
| Tests | pytest, pytest-recording for cached model fixtures |

---

## 13. Error handling

Principle: **one bad file never kills a run.**

- Per-unit and per-module model failures are recorded in `failures.json` and
  surfaced in `status`, the architecture coverage section, and the findings
  "Not analysed" appendix.
- Scanner exceptions are caught per scanner; the scanner is marked skipped with
  the error and the run continues.
- Only these stop a run: invalid configuration, unreachable backend after
  retries, budget cap, and disk write failure.
- Logs go to `logs/run-<timestamp>.log` at DEBUG and to the console at INFO
  with a Rich progress display per phase.

---

## 14. Testing

- **Fixtures.** `tests/fixtures/` holds small synthetic tools in Python,
  TypeScript, Go, Rust, Java, and a 70K-line HTML file generator, each seeded
  with known planted problems: a fake API key in history, a 3,000-line
  function, a committed `node_modules`, a single-author history.
- **Scanner tests.** Each scanner has unit tests asserting exact findings on
  fixtures, including redaction and fingerprint stability.
- **Splitter tests.** Unit boundaries never cut inside a definition; HTML
  streams separate correctly; windowing overlap is correct; every byte of a
  source file belongs to exactly one unit or an exclusion.
- **Schema tests.** Round-trip validation; `inputs_hash` freshness logic.
- **Model phase tests.** Run against recorded responses so CI is deterministic
  and offline. A separate `make smoke` runs a tiny fixture against a live
  backend configured by environment, intended before each engagement.
- **End-to-end.** A two-tool fixture engagement runs every phase with recorded
  responses and asserts that all documents render and export to HTML.
- **Backend contract tests.** Both backends run the same test suite through the
  `Backend` protocol, including the JSON-in-prompt fallback.

---

## 15. Extensibility

- **Scanners** via entry point group `unvarnish.scanners`.
- **Templates** via override directories.
- **Backends** via entry point group `unvarnish.backends`.
- **Taxonomy** via `scanners.categories` override, with a warning that
  cross-engagement comparability is affected.

---

## 16. Delivery slices

Guidance for the implementation plan. Each slice is independently useful.

1. **Skeleton and deterministic core.** CLI, engagement workspace, schemas,
   `ingest`, `inventory`, `git`, `scan` with `secrets`, `oversized_files`,
   `hygiene`, `bus_factor`. Renders a findings.md with scanner findings only.
   Already valuable on day one.
2. **Model layer and extraction.** Backends, caching, `split`, `extract`,
   budget estimation, `status` and `cost`.
3. **Rollups, verification, full documents.** `rollup_*`, `verify`, all three
   per-tool documents with prose blocks and diagrams.
4. **Comparison.** `compare` and `comparison.md`.
5. **Ask mode.**
6. **Export and distribution.** pandoc pipeline, branding, Docker image, PyPI.
7. **Remaining scanners and hardening.** `dependencies` with OSV,
   `hardcoded_infra`, `vendored_bulk`, `generated_bulk`; smoke tests; docs.

---

## 17. Open questions

Deferred, not blocking:

- Whether to add an embedding-based index for ask mode when a site provides an
  embedding model. BM25 is the baseline; this is an optional upgrade.
- Whether the consolidation proposal should accept consultant-provided
  constraints (target platform, approved stack) as input. Likely yes, in a
  later version, via `engagement.yaml`.
- Open-core licensing boundary if the tool is offered publicly: candidate split
  is deterministic core open, model phases and consolidation licensed.

---

## 18. Naming and market notes

Name chosen 2026-10-15 after availability checks: **Unvarnish**. `.com`,
`.dev`, `.io`, `.ai` and the PyPI and npm names were free at check time;
`unvarnish.com` is registered. The GitHub org name was taken; the repo lives
under Bonham-Technologies.

Market research the same day found no vendor producing unattended per-tool
architecture, findings, and requirements documents plus cross-tool
consolidation, and none offering air-gapped BYO-model operation at consultant
price points. Individual scanners are commodity; the differentiators are the
orchestration, the leadership-facing deliverable, requirements extraction, and
consolidation. Positioning: productized consulting tool first, possible
open-core product second.
