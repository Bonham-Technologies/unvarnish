# Unvarnish

The unvarnished truth about internally built software.

Unvarnish is a portable command-line tool for vetting internally built, often AI-generated
tools. Point it at a repository or a pile of files in any language and it produces an
evidence-backed findings document: embedded secrets, oversized files and functions, missing
tests and CI, single-author risk, and how the tool was built. Every finding is traceable to a
file and line.

It runs deterministic scanners (secrets, dependency advisories, end-of-life runtimes, hardcoded
infrastructure, hygiene, bus factor, hidden text) and model-assisted analysis against Anthropic or any
OpenAI-compatible endpoint, online or air-gapped, and writes three documents per tool
(architecture, findings, requirements) plus a cross-tool comparison. It answers questions over
the analysis and exports to DOCX, HTML, and PDF (findings also to SARIF and CSV, dependencies
to a CycloneDX SBOM), and ships as a Docker image too; [CHANGELOG.md](CHANGELOG.md) lists what
each release added.

The pipeline runs nine phases per tool: `inventory`, `git`, `scan`, `split`, `extract`,
`rollup_modules`, `rollup_tool`, `verify`, `render`. The first four and `render` need no model.

## Install

Requires Python 3.13+ and git; document exports also need pandoc 2.19+, Graphviz, and
weasyprint (or use the Docker image below). SARIF, CSV and CycloneDX exports need nothing more. Linux and
macOS run it natively; on Windows use the Docker image, since native Windows is unsupported.

    uv tool install git+https://github.com/Bonham-Technologies/unvarnish  # today, from git
    uv tool install unvarnish        # once published to PyPI (not yet)
    uv tool install .                # from a checkout
    uv sync && uv run unvarnish ...  # or run in place
    unvarnish grammars fetch         # once, while online: the tree-sitter grammars
    unvarnish eol refresh            # while online: end-of-life dates from endoflife.date
    unvarnish vulndata refresh       # while online: CISA KEV and EPSS exploit data

Or build the Docker image from a clone (see [Docker](#docker) for running it):

    git clone https://github.com/Bonham-Technologies/unvarnish && cd unvarnish
    docker build -t unvarnish .

The tree-sitter grammars that measure functions and split code into units download from GitHub
on first use; `grammars fetch` gets them ahead of time, so a later run needs no network for
them. A run that can't load one says so in the findings document. `eol refresh` does the same
for the end-of-life dates the `end_of_life` scanner reads; rerun it before each engagement.
`vulndata refresh` does the same for the exploit data that marks dependency advisories known
exploited (CISA KEV, raised to critical) and orders them by EPSS.

## Use

    unvarnish init acme-2026-10 --client "Acme Corp" --consultant "Your Firm"
    cd acme-2026-10
    unvarnish add expense-bot --repo https://github.com/acme/expense-bot.git
    unvarnish add receipt-ocr --files ~/Downloads/receipt-ocr
    unvarnish run
    open tools/expense-bot/docs/findings.md

`unvarnish status` shows which phases are fresh. `unvarnish run --phase scan --force` reruns one
phase. On a follow-up engagement, `unvarnish run --baseline ../acme-2026-04` compares with the
previous review (see [Follow-up reviews](#follow-up-reviews)). `unvarnish scanners list` shows scanners and their thresholds, which you can change under
`scanners:` in `engagement.yaml`.

## Scanners

Deterministic, no model needed; options live under `scanners:` in `engagement.yaml`
(`unvarnish scanners list` shows the effective values).

| Scanner | Finds | Options |
|---|---|---|
| `secrets` | keys, tokens, passwords, connection strings, private keys, in the working tree and the full git history; adds gitleaks results when gitleaks is on PATH (always redacted) | `use_gitleaks` |
| `oversized_files` | files and functions over size thresholds, HTML inline script | `file_lines`, `function_lines`, `html_script_lines` |
| `hygiene` | missing tests, CI, README, license, linter config; TODO density; swallowed errors | |
| `bus_factor` | single-author concentration | `single_author_share` |
| `dependencies` | published advisories (osv-scanner, offline by default) and unpinned dependencies without a lockfile; with an offline exploit data bundle (`unvarnish vulndata refresh`), an advisory in CISA's KEV catalog is critical and every advisory shows its EPSS score, which orders them (an older bundle than `max_data_age_days`, default 30, is noted); online (`offline: false`), package licences from deps.dev, and with a `licences` allowlist each licence outside it is a compliance finding (medium for copyleft, low otherwise) | `offline`, `enabled`, `osv_args`, `max_data_age_days`, `licences` |
| `hardcoded_infra` | URLs, internal hostnames, IPs, absolute paths, emails (credentials masked) | `max_evidence`, `include_tests` |
| `vendored_bulk` | dependency or build directories and large binaries in the source | `binary_bytes` |
| `generated_bulk` | single commits over a line threshold, noting AI co-author trailers | `commit_lines` |
| `client_exposure` | what AI-built web apps ship to the browser: Supabase service-role keys and Firebase config in client code, secret-named `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` variables, tables without row level security and `using (true)` policies in SQL migrations, CORS `*` with credentials, credentials in committed `.env` files and MCP configs, and route handlers with no auth check nearby (one review finding, passed to extraction to confirm). Values redacted | `client_roots`, `client_extensions`, `public_names`, `auth_window`, `cors_window`, `max_evidence`, `include_tests` |
| `ai_usage` | how the tool's own code uses AI: each provider, model id and `file:line`, hosted or local (from SDK imports, endpoints including raw HTTP, model ids and dependencies), in architecture.md and the comparison; request input built into a prompt (one review finding, OWASP LLM01), model output reaching eval/exec, a shell or SQL (high), model calls with no token limit or timeout, and model-callable tools beside powerful actions. Values redacted | `max_evidence`, `include_tests` |
| `deployment_exposure` | how the tool is exposed once deployed, read offline from its deployment files: Compose ports published on all interfaces (high for a database), `privileged`, `network_mode: host`, mounted Docker sockets, literal passwords and `${VAR:-fallback}` passwords; Dockerfiles whose final stage runs as root, `ADD <url>` without a checksum, secrets in `ENV`/`ARG`; Kubernetes `hostNetwork`, privileged containers, missing resource limits, `latest` or untagged images; Terraform ingress from `0.0.0.0/0` beyond ports 80 and 443 and public buckets or containers. One finding per rule, values redacted; `unvarnish scanners list` shows each rule's severity and effort band; architecture.md says what was checked | `compose`, `dockerfile`, `kubernetes`, `terraform`, `ignore_rules`, `max_evidence`, `include_tests` |
| `end_of_life` | runtimes, base images and frameworks past end of life (high) or within the warning window of it (medium), from `.python-version`, `requires-python`, Poetry's `python`, `Pipfile`, `setup.cfg` and `setup.py` `python_requires`, `runtime.txt`, `package.json` engines, `.nvmrc` (a version or `lts/<codename>`), `.tool-versions`, `go.mod`, project-file TargetFramework, Dockerfile `FROM`, `.ruby-version`, the Gemfile's `ruby`, `composer.json` and framework dependencies; dates from an offline endoflife.date bundle (`unvarnish eol refresh`; an older bundle than `max_data_age_days` is noted) | `warn_months`, `max_data_age_days` |
| `hidden_text` | characters that display as nothing: bidirectional controls (Trojan Source), Unicode tag characters and long runs of variation selectors or private-use characters (high), zero-width characters (medium) in source and config; any of them in an AI rule file (`.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, `.cursor/rules/`, `.claude/` and others, high); and MCP configs that start a server from an unpinned package or a piped download (review). Shown as `[U+XXXX]` escapes, never raw, in every document, export and model prompt | `long_run`, `max_evidence`, `include_tests` |
| `sast` | code-level flaws (SQL injection, `eval` of request input and whatever else your rules cover) from [Opengrep](https://github.com/opengrep/opengrep), when `opengrep` is on PATH and `rules` names a local rules directory; otherwise listed as not checked. Local rules only, never a registry; one finding per rule, excerpts redacted; `.semgrepignore` files and `nosem` comments are disregarded and reported as suppressions | `rules`, `max_evidence` |

## Model configuration

Without a model configured, `unvarnish run` still produces the scanner-based `findings.md` and
skips the model phases. To enable them, add a backend and a default model to `engagement.yaml`:

    backends:
      anthropic:
        type: anthropic
        api_key_env: ANTHROPIC_API_KEY
        # batch: true               # verify and prose via the Message Batches API, half price
      onprem:
        type: openai_compatible
        base_url: http://llm.client.internal:8000/v1
        api_key_env: ONPREM_LLM_KEY
        unit_tokens: 4000
        timeout_s: 1800             # per request; CPU-only servers are slow
        capabilities: { json_schema: true, tool_calling: false, context_window: 32768 }
    models:
      default: { backend: anthropic, model: claude-opus-5-5, effort: low }
      phases:
        extract: { backend: anthropic, model: claude-sonnet-5-5, effort: low }
    budget:
      max_tokens: 20000000
      prices:
        claude-opus-5-5: { input_per_mtok: 4, output_per_mtok: 20, cache_read_per_mtok: 0.2 }
        claude-sonnet-5-5: { input_per_mtok: 2, output_per_mtok: 10, cache_read_per_mtok: 0.2 }

To run air-gapped, point `models.default` and `models.phases.extract` at the `onprem` backend
instead; see [docs/operations.md](docs/operations.md) for server settings.

What you already know about the target shapes the consolidation proposal. Every field is
optional; edit them and run `unvarnish compare` again:

    consolidation:
      target_platform: Azure App Service, .NET 8
      approved_stack: [React, PostgreSQL]
      must_keep: [SAP integration, single sign-on]   # systems that must survive
      retire: [Access databases]                      # systems the client wants gone
      notes: One team of three; go live before year end.

comparison.md lists the constraints and every place they conflict with what the tools do.

Keys come from the named environment variable (or `api_key_keychain: <service>` with the
`keyring` package). They are never written into the engagement.

    unvarnish config check          # validates config and probes each backend
    unvarnish run --dry-run         # shows what would run and a token estimate per model phase
    unvarnish run                   # resumes where it stopped; exit code 3 on budget cap
    unvarnish cost                  # tokens spent, upper-bound cost when prices are set
    unvarnish cache clear --yes     # forget cached model responses

Every model response is cached under `cache/responses/`, so re-running after a crash or a
config tweak only pays for units whose inputs changed. Logs for each run land in `logs/`.

## Documents

`unvarnish run` renders three documents per tool into `tools/<name>/docs/`:

- `findings.md`: executive summary, by-the-numbers table, a remediation outlook (findings by
  effort band, S, M, L or XL, and severity), every scanner and model finding by severity
  (scanner findings first at equal severity, model findings with their verification status,
  each with its effort band), and a "Not analysed" appendix listing excluded files, windowed
  regions, failed units and modules, and rejected findings. Set
  `report.effort_days: {S: 0.5, M: 2, L: 5, XL: 15}` to add an engineer-day estimate.
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

## Follow-up reviews

    unvarnish run --baseline ../acme-2026-04     # a prior engagement folder

`--baseline` takes a previous engagement folder, a tool folder, or one findings artifact
(`scanner-findings.json` or `findings.json`), resolved per tool by name. Findings match by id,
then grouped scanner findings (oversized files, hardcoded URLs and the like) by scanner and
rule, then by title and path within `baseline.line_drift` lines (default 50), then by secret
fingerprint; a group whose count changed shows as changed, with both counts. Each tool gets
`analysis/delta.json`, and `findings.md` opens with "Since the
previous review (date, commit)": counts by severity (resolved, new, changed, persistent, risk
accepted), then tables of the resolved, new and changed findings. Exports carry the section,
and `unvarnish compare` adds a per-tool trend column. No model calls are made; the delta only
re-renders the documents. The baseline is copied into `analysis/baseline.json`, so later runs
keep comparing until you pass another or delete it. A baseline from an incompatible findings
schema version is refused. Without a baseline the documents are unchanged.

Findings the client has accepted the risk of are listed by id and shown as "Risk accepted",
never as resolved:

```yaml
baseline:
  accepted: [3f9c0a1b2c3d4e5f]
  line_drift: 50
```

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

## Asking questions

    unvarnish ask "Which tool talks to Stripe, and from where?"
    unvarnish ask --tool expense-bot        # interactive session restricted to one tool

Needs a model. Answers come from a bounded loop (at most `ask.max_tool_calls` tool calls,
default 12) over five read-only tools: a BM25 search of unit purposes, module summaries,
findings, and capabilities; the unit, module, and tool artifacts; filtered findings; and a
regex grep over the tool's source that skips excluded files and stops after
`ask.grep_timeout_s` seconds (default 5). Every answer must cite artifact
ids or file paths; one that does not is printed with an "unverified" warning and marked so in
the session file under `ask-sessions/`. The search index is built on first use under
`cache/index/` and rebuilt when any tool's analysis changes. Tool results and answers pass
through the secrets redactor before they reach the console or disk.

## Exporting

    unvarnish export                         # every rendered document, docx + html + pdf
    unvarnish export --format docx expense-bot
    unvarnish export --format html --doc findings --doc comparison
    unvarnish export --format docx --template brand.docx

Needs `pandoc` and Graphviz `dot` on PATH, plus `weasyprint` for PDF; if any is missing the
command says how to install each and exits 2. PDFs are tagged (PDF/UA-1) for screen readers
with weasyprint 66 or later; with an older one, such as Debian's or Ubuntu's, they are written
untagged and the command warns. Files land in `exports/<doc>-<tool>-<timestamp>.<ext>`
(`comparison-engagement-...` for the comparison). Diagrams are rendered to SVG (PNG for DOCX)
with Graphviz from the same model that produced the Mermaid in the Markdown. Branding: set
`report.branding.reference_docx` (a Word reference document) and `report.branding.html_css` in
`engagement.yaml`, or pass `--template`; the bundled neutral reference and stylesheet are the
fallback. Export always starts from the latest render; hand edits to the Markdown survive
until the next `run`.

### Findings for GitHub code scanning and issue trackers

    unvarnish export --format sarif expense-bot   # exports/findings-expense-bot-<timestamp>.sarif
    unvarnish export --format csv                 # exports/findings-<tool>-<timestamp>.csv per tool

`sarif` (SARIF 2.1.0) and `csv` write each tool's findings as data, one file per tool: the
scanner findings and the verified model findings, the same set the findings document lists
(findings verification rejected are left out), with every string passed through the secrets
redactor. They are opt-in (`all` and the default stay docx, html and pdf), need no pandoc, and
are skipped by `--doc` unless it includes `findings`.

Upload the SARIF file to the tool's own GitHub repository (code scanning must be enabled, and
the token needs the `security_events` scope); `commit` in `tools/<tool>/tool.yaml` is the
commit Unvarnish analysed:

    gzip -c exports/findings-expense-bot-<timestamp>.sarif | base64 | tr -d '\n' |
      gh api -X POST repos/ACME/expense-bot/code-scanning/sarifs \
        -f commit_sha=<commit from tool.yaml> -f ref=refs/heads/main -F sarif=@-

or, from a workflow in that repository, `github/codeql-action/upload-sarif` with
`sarif_file:` pointing at the file. Import the CSV into Jira with its CSV importer (Import
issues from CSV, or System > External System Import > CSV): map `Summary` and `Description`
to the fields of the same name, `Severity` to Priority, `Tool`, `Category` and `Source` to
labels or components, and keep `FindingId` (a custom field or a label) to recognise findings
already filed. `docs/operations.md` has the details.

### An SBOM per tool

    unvarnish export --format cyclonedx expense-bot  # exports/sbom-expense-bot-<timestamp>.cdx.json

`cyclonedx` writes a CycloneDX 1.6 JSON SBOM per tool from its inventory: each declared
dependency with its package URL, exact version (or the manifest's constraint) and manifest
path, and each known advisory under `vulnerabilities`, pointing at the package it affects.
Unvarnish writes it itself, without running osv-scanner, so it works offline; it is opt-in like
SARIF and CSV and ignores `--doc`. Licences are listed only when the scan ran online
(`scanners.dependencies.offline: false`), as deps.dev declares them; offline the SBOM lists none
and says "licences: not checked" in its metadata, as the findings document does under "Not
analysed". With `scanners.dependencies.licences` set to the SPDX identifiers the client
accepts, each licence outside it is a compliance finding naming the packages and manifest.

## Docker

    docker build -t unvarnish .
    docker run --rm -v "$PWD/acme-2026-10:/engagement" unvarnish run
    docker run --rm -v "$PWD/acme-2026-10:/engagement" -e ANTHROPIC_API_KEY unvarnish run

On a Linux host, run as your own user so files written into the engagement stay yours:

    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/acme-2026-10:/engagement" unvarnish run

Tools added with `--link` point at host paths the container cannot see; use `--repo` or
`--files` for engagements that will run in Docker. Inside the container the user-level config
is `/engagement/.unvarnish/config.yaml`, not the laptop's `~/.config/unvarnish`.

The image bundles Python, the tree-sitter grammars, git, pandoc, Graphviz, weasyprint 70, and
endoflife.date's end-of-life dates, fetched at build time (`--build-arg EOL_DATA=skip` builds
without them; runs then report end of life as "not checked").
`docker save unvarnish | gzip > unvarnish.tar.gz` moves it to an air-gapped site. Keys are
passed as environment variables; nothing is baked into the image or the engagement.

### Tone and templates

`report.tone` is `direct` (default) or `measured`. Override any template by placing a copy of
`src/unvarnish/render/templates/<name>.md.j2` under `templates/` in the engagement, under
`report.templates_dir`, or under `~/.config/unvarnish/templates/`. A prose block the template
names but Unvarnish does not know renders a fallback sentence and records a failure.
`report.lang` (default `en`, any BCP 47 tag such as `en-GB` or `de`) is the language that
exports declare to screen readers.

### Model phases and cost

| Phase | Calls | Notes |
|---|---|---|
| `extract` | one per unit | parallel across files; cached and resumable |
| `rollup_modules` | one per file with analysed units | parallel; per-module artifacts are resumable |
| `rollup_tool` | one, or one per directory chunk plus one | chunks when the module digests exceed `pipeline.rollup_input_tokens` (default 40,000) |
| `verify` | one per high or critical model finding | the verifier sees only the claim and the cited lines |
| `render` | five prose blocks per tool | |

`unvarnish run --dry-run` prints an estimate per model phase. `budget.max_tokens` caps the whole
run across phases and tools, with prompt-cache reads counted at a tenth; a capped run exits 3
and resumes on the next `run`.

## Layout of an engagement

    engagement.yaml            client, tools, scanner thresholds, model config
    tools/<name>/source/       the ingested code
    tools/<name>/inventory/    census, metrics, dependencies, git stats, scanner findings, AI
                               services used (JSON)
    tools/<name>/analysis/     units and modules, tool.json, capabilities.json, findings.json,
                               failures, phase state, baseline.json and delta.json (JSON)
    tools/<name>/docs/         architecture.md, findings.md, requirements.md
    templates/                 optional overrides for the bundled Jinja templates

JSON is the source of truth; Markdown is rendered from it.

## Develop

    uv sync
    uv run pytest
    uv run ruff check .

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/` for implementation plans.

## Project records

- [CHANGELOG.md](CHANGELOG.md): what each release delivered.
- [docs/decisions.md](docs/decisions.md): decisions taken where the spec was silent or overruled,
  with what each costs if wrong.
- [docs/known-issues.md](docs/known-issues.md): accepted minor gaps, kept as a backlog.
- [docs/operations.md](docs/operations.md): running an engagement, keys, cost, Docker, and traps.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (every commit needs a DCO `Signed-off-by` line) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
[SECURITY.md](SECURITY.md) describes, never in a public issue.

## License

Unvarnish is licensed under the Apache License, Version 2.0 (Apache-2.0); see
[LICENSE](LICENSE) and [NOTICE](NOTICE).
