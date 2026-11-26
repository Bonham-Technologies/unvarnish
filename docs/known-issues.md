# Known issues

Every gap accepted at a slice's final review was addressed in the known-issues burn-down (October 2026): fixed, or decided to be correct and recorded in [decisions.md](decisions.md) with the reason. New gaps found by later work are added here; the slice or run that found each is in brackets, and `[rc]` marks the release-candidate validation runs.

## Open

- [UNVAR-100] The `sensitive_data` scanner reads field names only, so a column whose name
  says nothing (`notes`, `payload`, `data`) is not classified, and a short or common word is
  not in the bundled set (`name`, `token`, `children`, `location`, `age`). It reads SQL
  `CREATE TABLE` and `ALTER TABLE ... ADD`, Python model and typed classes, Django and
  Alembic migrations, Prisma, TypeScript interfaces and object types, TypeORM entities and
  Mongoose, Zod and Drizzle schemas; Sequelize, Rails and other migration DSLs, GraphQL,
  OpenAPI and JSON Schema, schemas and migrations kept in configuration files (Liquibase or
  Hasura YAML), Go, Java, C# and other languages' types are not read (SQL in their
  strings is). A Python class counts when its base or decorator is recognised in the same
  file (a model whose base class is imported from another module counts only with a
  `__tablename__`). A TypeScript body is followed by counting brackets outside strings, so
  a bracket in a regular expression inside a type body can end it early. The destinations
  table joins stores to destinations by file and by the tool model's data-flow names, not
  by tracing the code. One file's table and type bodies are followed for at most four times
  the file's length in all (bodies that never close), and a declaration's name and its
  opening brace may be at most 300 characters apart (generics, `extends`), so a file built
  to defeat the parser is read in part without saying so. A decorator over 100 characters or
  a property name over 201 hides that property. In a `.sql` file where the standard and the
  backslash-escaped reading of string literals both close every string but disagree (mixed
  `\'` and `'...\'` strings), the text either reading puts in a string is blanked, so a
  `CREATE TABLE` after such strings can be missed; a value is never recorded instead.
- [UNVAR-91] The `ai_usage` checks follow data within one file, by assignment: request input
  passed through a function parameter, or a prompt built in one file and sent from another,
  is missed (a FastAPI or Gradio handler's parameters are not request input to it). A value
  ends at an unconditional reassignment or, in Python, at the end of its function; a value
  bound at module level reaches functions defined below it, so a later function whose
  parameter has the same name can give a false high. In JavaScript and TypeScript a value
  is not bounded by its function, and a `const` redeclared in another function does not end
  it, so a name reused in another function can give a false high; a value reassigned in a
  branch still counts.
  Statements are found by counting brackets outside string literals, approximately: a
  bracket in a JavaScript regular expression can join lines until the next top-level
  `function`, `const` or similar. The verify phase re-checks model findings only, so these
  scanner findings are not re-checked against the code: read the cited line. Finding
  excerpts redact the credential shapes listed in docs/decisions.md, not every credential:
  a short or letters-only value with no secret-like name beside it can still show. Imports
  are read for Python and JavaScript/TypeScript only; other languages are recorded through
  endpoints and model ids, and a provider host in a docstring counts. A local
  OpenAI-compatible server is recognised by Ollama's port, LM Studio's
  `localhost:1234/v1`, or a loopback URL beside an SDK import or an OpenAI-compatible
  client, or with an OpenAI-style path, not by other ports, hosts or by Anthropic's or
  Ollama's paths alone.
- [UNVAR-34] After a `touch`, `git checkout` or re-clone that leaves content unchanged, `run
  --dry-run` still lists every phase from the inventory on: it cannot know the census will
  come out the same without rebuilding it. The real run reruns only the inventory. The
  inventory now reads every file in full to digest it, binaries and excluded files included
  (the scan reads excluded files), so a tree with large binaries inventories more slowly. An
  edit to any file, even one excluded from analysis, still reruns every phase after the
  inventory; the unit, module and response caches answer the model calls.
- [UNVAR-6] Across kernels that don't share file locks (a process on the macOS host and one in
  a Docker Desktop container on the same folder, or two machines on a network share), the
  engagement lock relies on the lock file's contents and heartbeat: two commands that start
  in the same instant can both run, a holder that dies blocks others for
  `pipeline.lock_stale_minutes`, and a holder paused longer than that (a stopped container) is
  taken over while still alive.
- [UNVAR-6] `add` and `cache clear` don't take the engagement lock. `add` during a run edits
  `engagement.yaml`, which the run read at start; `cache clear` during a run deletes responses
  the run may write again.

- [UNVAR-41] SARIF locations are relative to the tool's root. For a tool added from a
  subdirectory of a repository, GitHub resolves them from the repository root and the alerts
  don't line up with the files; there is no option to add a path prefix. Repository-level
  findings (bus factor, repository hygiene) point at `.`, which has no file to show.
- [UNVAR-41] The SARIF export does not check GitHub's 10 MB (gzip) upload limit; a tool
  near 25,000 findings with long excerpts can exceed it.
- [UNVAR-41] Azure DevOps' CSV import expects `Title` and `Work Item Type` columns: rename
  `Summary` and add the type before importing there.
- [UNVAR-41] Only `security` findings carry GitHub's `security-severity`. Known-vulnerable
  dependency findings are category `dependency`, so GitHub lists them by level (error,
  warning, note) rather than as Critical/High/Medium/Low security alerts.

- [UNVAR-43] Rails is in the end-of-life bundle, but no manifest the inventory reads names
  it (the end-of-life scanner reads only the Gemfile's `ruby` line, and nothing parses its
  gems or Gemfile.lock), so Rails versions are not checked; nor are
  Java versions set in `pom.xml` or Gradle (only Docker `openjdk`/`eclipse-temurin` tags), a
  `python:3.9-slim-buster` image's Debian release, docker-compose `image:` lines, or a
  `FROM` whose tag comes from an `ARG`. Spring Boot is checked only where a `<dependency>`
  block names an `org.springframework.boot` artifact with a `<version>`; the usual
  `spring-boot-starter-parent` `<parent>`, which sets the version for versionless starters,
  is not read.
- [UNVAR-43] A finding's title says "near" or "past" end of life, and the title is part of
  the finding id, so a re-audit run after a near cycle has ended shows the near finding as
  resolved and the past one as new, rather than one finding whose severity rose.
- [UNVAR-43] A version that names no cycle in the data is skipped silently: a floating tag
  (`python:3`, `node:lts`, `mysql:8`), a cycle newer than the bundle, or a range with no
  lower bound (`<4`). Since UNVAR-59 a bundle older than `max_data_age_days` (default 90)
  is flagged under "Not analysed" and on the end-of-life row, so the likeliest cause of a
  missing newer cycle is visible; a skipped version itself is still not listed.
- [UNVAR-52] An `.nvmrc` of `lts/*` or `lts/-1`, and a `.tool-versions` `lts`, `latest` or
  `system`, float like `node:lts` and are skipped silently. An `lts/<codename>` (or
  `.tool-versions` `lts-<codename>`) resolves only through the scanner's table of Node.js LTS
  codenames (Argon, Node.js 4, to Lithium, 26; endoflife.date carries none), so a newer
  codename is skipped silently until it is added.
- [UNVAR-52] `setup.py` is never run: only a literal `python_requires="…"` (or `'…'`) on one
  line is read, so a value from a variable, an f-string, a `**kwargs` dict or a
  `python_requires` split across lines is missed. Only the first `python_requires` is read.
- [UNVAR-52] `.tool-versions` is read for `python`, `nodejs` (or `node`) and `ruby`, and only
  each line's first version, the default; fallback versions after it and other tools
  (`golang`, `java`, `php`) are not checked. The Gemfile's `ruby` is read only from literal
  string arguments at the start of a line (`ruby RUBY_VERSION` is not), and a `ruby` line
  that names an `engine` (JRuby, TruffleRuby) is skipped, as `.ruby-version`'s `jruby-` is;
  `gems.rb`,
  `Pipfile.lock`, `.node-version` and Poetry's `[tool.poetry.group.*]` are not read.
- [UNVAR-90] The Docker image and the site kit do not carry the exploit data bundle yet, so
  their runs say "exploit data: not checked" unless a bundle written by `vulndata refresh` is
  mounted (`docs/operations.md`, Exploit data). Bundling it is a separate change to the
  Dockerfile and `scripts/site-kit.sh`.
- [UNVAR-90] An advisory without a CVE alias (some GHSA-only or ecosystem advisories) cannot
  be matched to KEV or EPSS and shows "no EPSS score". As with end-of-life data, today's date
  is not in the scan's inputs hash, so a bundle that passes `max_data_age_days` between two
  runs with nothing else changed is noted only after the scan reruns.
- [UNVAR-44] The image's end-of-life bundle is as old as the image. A rebuild that changes
  nothing before the bundle's step reuses the cached layer and its older bundle (the
  site-kit check prints the date; `docker build --no-cache` refetches). The offline OSV
  databases have the same behaviour.
- [UNVAR-43] A private or registry image is judged by its last path component, so
  `team/python:3.9` is reported as Python 3.9 even when it is a team's own image built on
  something else, and any image under a `dotnet/` path component is judged as .NET.
- [UNVAR-43] Today's date is not in the scan's inputs hash, so a cached scan keeps its near
  and past verdicts until the scan reruns (a changed source, scanner options or a refreshed
  bundle); a cycle that ends between two runs with nothing else changed stays "near" until
  `--force --phase scan`. The old-data note (UNVAR-59) works the same way: a bundle that
  passes `max_data_age_days` between two runs with nothing else changed is noted only after
  the scan reruns.
- [UNVAR-42] A scanner band is fixed per rule, so a grouped finding (twelve oversized
  files, forty hardcoded URLs) carries the band of one fix, and the engineer-day range
  undercounts it. The count is in the finding's summary; raise the rule's band with
  `scanners.<name>.effort.<rule>` where it matters.
- [UNVAR-42] The SARIF and CSV exports, and `ask`'s finding view, do not carry the effort
  band; it is in `findings.json` and the documents.
- [UNVAR-42] The executive summary prose does not mention the remediation outlook.

- [UNVAR-93] An offline SBOM lists the declared dependencies and the packages advisories name,
  not the full set a lockfile resolves: osv-scanner's package list is kept only online, with
  the licences. A declared range shows as a constraint, without a version, unless online
  resolution found exactly one version for it.
- [UNVAR-93] Licence findings cover dev-only packages from a lockfile too, which are not
  distributed with the tool; the finding lists them by name for the consultant to judge.
- [UNVAR-93] Licence identifiers match exactly (case aside): an allowlist with `GPL-3.0-only`
  does not accept a package deps.dev reports as `GPL-3.0`, and `GPL-2.0+` needs listing as is.
- [UNVAR-93] An online inventory from before this change reruns once (osv-scanner, with the
  network); with more than one tool, `compare` then reruns and calls the model.

- [UNVAR-16] Ctrl-C in a terminal also sends SIGINT to gitleaks, osv-scanner and git if one is
  running. The scanners turn a killed child into a "failed" note, so the scan phase can write
  its artifact fresh and the next run keeps the note instead of rescanning; run with `--force
  --phase scan` after an interrupt during scanning. A follow-up should treat a negative return
  code as interrupted or start the scanners in their own session.
- [UNVAR-29] `verify` still records its full inputs hash when a verification call fails, so
  those findings stay "verification failed" on a plain rerun until the model findings change;
  `unvarnish run --phase verify --force` retries them.
- [UNVAR-31] A linked folder that is still there but empty, such as the mount point of a
  network share that is not mounted, passes the missing-source check and is analysed as an
  empty tool, so render rewrites its documents with "0 / 0" files. Mount the share before
  running; a follow-up could refuse an empty tree when the last census had files.
- [UNVAR-28] A `--link` to a subdirectory of a repo (no `.git` of its own) doesn't read the
  index, so a file there that is tracked but matches a `.gitignore` rule is still excluded as
  `gitignore`. Git history is skipped for such a link too ("no .git directory"). Nor are a
  parent directory's `.gitignore` rules applied to it.
- [UNVAR-22] Tagged PDFs are PDF/UA-1 as weasyprint writes them: the tests check the
  structure tree, `/MarkInfo`, `/Lang` and that links stay visible, but no veraPDF or PAC run
  checks full conformance, so a strict checker may still report errors (in the diagrams, for
  example, or in a branded stylesheet's page boxes).
- [UNVAR-22] The weasyprint in `docker/weasyprint.txt` is outside Dependabot's view: it and
  its dependencies (Pillow, fonttools, cffi and others) move only when someone regenerates
  the file.
- [UNVAR-22] CI puts the image's pinned weasyprint (`docker/weasyprint.txt`) first on PATH,
  so it runs the tagged test, which reads the link annotations; the real-PDF test of the
  untagged fallback runs only where an older weasyprint is on PATH (the fallback logic
  itself is unit-tested with mocked versions).
- [UNVAR-24] Documentation links in code, such as an install hint in an error message
  (`https://pandoc.org/installing`), still count as hardcoded URLs. Only package-manifest
  metadata keys and `.github/ISSUE_TEMPLATE/` are skipped; a link on a comment line already
  was.
- gitleaks' working-tree results in any file the census excludes are dropped, including a
  gitignored `.env`, which Unvarnish's own secret rules do scan. A secret only gitleaks
  recognises in such a file is not reported. [UNVAR-18]
- [UNVAR-39] `client_exposure` route detection is a heuristic: a handler protected by a
  router-level guard, a wrapper defined elsewhere, or Next.js `middleware.ts` is still listed,
  and one whose neighbouring lines mention a session or a logged-in check (`loggedIn`) is
  not. An Express-style file whose handlers use other parameter names and that imports the
  framework indirectly is not searched. Only the first
  `max_evidence` handlers are listed, and only those reach extraction as notes.
- [UNVAR-39] A dry run doesn't foresee `extract` rerunning when a scan finds different
  unprotected routes: extract hashes the route hints by content, so it is not a declared
  dependent of `scan`. The real run still sees the change and re-extracts the affected units.
- [UNVAR-39] Row level security set outside the repository's SQL files (in the Supabase
  dashboard, or by an ORM's own migration format) is invisible to `client_exposure`, so those
  tables read as open.
- [UNVAR-39] A credential passed as a positional `args` entry in an MCP config is not
  detected, and on a minified line it can appear unredacted beside a detected key/value
  credential unless the secrets redactor recognises its shape.
- Two private-key headers on one line (minified JSON) are both judged by the body after the first, so a placeholder key followed by a real one on the same line reports neither. [UNVAR-3]
- [UNVAR-36] `site/README.md` ("On launch day") still says
  `test_no_github_link_until_the_repository_is_public` skips itself once `LICENSE` no longer
  says proprietary. It now always runs and the launch thread deletes it; the README line is
  left for an owner-merged site change.
- [UNVAR-36] Git history still holds the whole-token test fixtures that the working tree now
  builds from fragments. The launch ticket decides how history is published.
- [UNVAR-36] `.github/dco.yml` does nothing until the owner installs the DCO GitHub App. Once
  it is installed, every commit needs a `Signed-off-by` line, and neither the CLAUDE.md commit
  conventions nor the autopilot builder use `git commit -s` yet, so every autopilot PR would
  fail the DCO check. Add sign-off to both before installing the app.
- [openrouter-sim] A placeholder credential on a line with other quoted values (a
  `Content-Type` header beside `Bearer REPLACE_ME`) still goes to the verifier, which may
  confirm it. The deterministic check only rejects when every value is a placeholder.
- [openrouter-sim] Small models fill a capability's object with a restatement of its action,
  so comparison matrix cells read "User can View the home page Home page content". Cosmetic;
  the cell template joins actor, action, and object as given.
- [UNVAR-45] The `split` phase loads grammars too, and only the inventory notes a missing
  one: if a grammar arrives or vanishes between the inventory and the split (a resumed run on
  another machine), the split's units can differ from what the note says. The split still
  logs its own warning.
- [UNVAR-45] The Docker build fetches grammars after the source is copied, so every source
  change downloads them again (about 22 MB). Fetching before `COPY src` would need the
  grammar list outside the package.
- [UNVAR-40] Model findings are not deterministic between runs: one reworded or moved more
  than `baseline.line_drift` lines shows in the delta as one resolved and one new. Scanner
  findings match by id, title and path, or fingerprint; a grouped scanner finding (oversized
  files and functions, hardcoded values of one kind, TODO density, swallowed errors) matches
  by scanner and rule whatever its count or first path (UNVAR-49).
- [UNVAR-49] Other scanner findings that list several places (dependency or build
  directories, large binaries, unpinned dependencies, suppression files, bulk commits,
  client-exposure groups) still match by title and first path: when the first listed place
  changes, they show as one resolved and one new.
- [UNVAR-49] A group's "changed" reflects its count and severity only: the same number of
  members with one swapped for another reads as persistent. Swallowed errors count at most 20
  (the evidence cap), so a change above 20 is not seen.
- [UNVAR-49] A TODO-density or swallowed-errors finding in a baseline written before UNVAR-49
  has no count, so a change in its count is not shown until the baseline is a newer review.
- [UNVAR-40] A tool renamed between reviews has no delta: a baseline is resolved by tool
  name, in a findings artifact too (its `tool` field), and the run warns "not in the
  baseline".
- [UNVAR-40] The executive summary prose does not mention the delta (it would cost a model
  call on every baseline change); the section above it carries the comparison.
- [UNVAR-60] A consultant named `true`, `false`, or a capitalised spelling of either (`True`,
  `FALSE`) gets no author in HTML and PDF exports: pandoc reads a command-line metadata value
  in those spellings as a YAML boolean. Word exports are unaffected.

- [UNVAR-64] A custom `report.branding.html_css` written before 0.1.1 has no `tbody th`
  rule, so the row headers in an HTML export's summary tables take its header styling (wash
  background, bold) until the rule is copied from the bundled `report.css`. PDF and Word are
  unaffected.
- [UNVAR-89] `sast` excerpts are redacted by Unvarnish's own secret rules only: a credential
  only gitleaks recognises can appear in an Opengrep excerpt. Opengrep's command line was
  checked against its source on main (November 2026), not run against a released binary in
  CI; `--x-ignore-semgrepignore-files` is marked internal upstream and may disappear, which
  turns the scan into a "not checked" note rather than wrong results. A new Opengrep version
  alone does not rerun a fresh scan. Two rules whose ids end in the same word get the same
  title (the full rule id is in the summary and the evidence notes).

- [UNVAR-92] An engagement extracted before the hidden-text escaping keeps those extractions:
  the extract phase reruns only when its units, model or prompt change, so a unit with hidden
  characters is asked again with escaped text only on such a rerun or `run --force`. The scan
  reruns once and reports the characters either way.
- [UNVAR-92] Hidden characters are reported in source, config and rule files only, not in
  Markdown or other documentation outside the rule-file list, generated or minified files, or
  (by default) tests. Runs of variation selectors or private-use characters shorter than
  `long_run` (32) are escaped in excerpts and prompts but not reported. A single variation
  selector after a visible character is treated as legitimate, so a payload spread one
  selector per character is neither reported nor escaped. A tag-character payload is shown
  as escapes, not decoded to the text it spells.
- [UNVAR-92] Right-to-left locale files are recognised by a language code (`ar`, `he`, `fa`,
  `ur` and others) in the path of a translation-shaped file (`.json`, `.po`, `.xliff`,
  `.properties`, ...; `.js` and `.ts` only inside a locale folder); one elsewhere reports its
  isolates, and so does a locale line with no right-to-left letter. A bidi mark on a line
  with a right-to-left letter is not reported in any file, and an override on such a line of
  a locale file is not either, so an attacker who adds such a letter hides a mark anywhere,
  or an override only in a translation file. Other invisible characters (U+00AD soft hyphen,
  U+034F, U+115F/U+1160/U+3164 Hangul fillers, U+180E) are neither reported nor escaped, and
  a path or file name with a hidden character is escaped in documents and exports but kept
  raw in the JSON artifacts, which need it to open the file.
- [UNVAR-92] The MCP check reads JSON configs (`.mcp.json`, `claude_desktop_config.json`,
  `.cursor/mcp.json`, `.vscode/mcp.json` with comments, and the Windsurf, Roo, Gemini, Kiro
  and Amazon Q names): `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run`,
  `pipx run` and `curl | sh`, also behind `cmd /c`, `sh -c` or `powershell -Command`. A
  Docker image tag, a TOML or YAML agent config and a remote server given by `url` are not
  checked.
- [UNVAR-94] Batch mode covers only verify and the render prose calls (option B). Batching
  every phase (option A: extract in waves that respect the neighbourhood order, the rollups
  after it) is a follow-up. In batch mode a request the batch could not answer, a structured
  reply that needs a retry or repair, a cut-off or miscounted prose block, and a refusal's
  retry and fallback are ordinary calls at the full price, so a refused request reaches the
  primary model once more than in a synchronous run. A batched phase waits for its whole
  batch (usually under an hour, at most 24 hours) before writing anything. The `compare` and
  `ask` calls are never batched.
- [UNVAR-94] A rerun whose prompts changed since a batch was stored (new inputs, another
  effort, a new prompt version) first waits for that old batch to end and caches its replies,
  which the new prompts never use, then submits a new batch and waits again.
- [UNVAR-94] A stored batch submitted for another backend or model than the phase now uses is
  dropped without being collected, although it was paid for.
- [UNVAR-94] Batch mode has not run against the live Message Batches API. Structured output
  (`output_config.format`), `effort` and `cache_control` inside a batch request's params, and
  the shapes of its results, are checked only against fakes built from the SDK's own types.

## Fixed

Fixed in the known-issues burn-down (see the CHANGELOG for details):

- `git log` failure reported as "no commits": the reason now quotes git's error; an empty repository still says "no commits".
- Renames in `--numstat` not parsed: parse `a/{old => new}` and `old => new` to the new path.
- Only the root `.gitignore` honoured: excluder loads every `.gitignore` and applies it below its directory.
- git subprocesses decode with the locale: `encoding="utf-8"` on every git call.
- `hygiene` uses `splitlines()`: split on `\n` only.
- All private keys share one fingerprint: fingerprint header plus the first body line.
- "Removed from the working tree" wrong for skipped files: say "removed" only when the path is absent from the census.
- No prefilter before history regexes: per-rule literal prefilter on each line.
- AI-tooling pattern matches Devin/Cline; misses email-only Anthropic trailers: bot names need a bot-like email; match `noreply@anthropic.com`.
- Extension map case-sensitive; `.ipynb` unmapped; `bin` over-excludes: case-insensitive suffix lookup; `.ipynb` maps to `jupyter`; drop `bin` from build dirs.
- History findings identified by title suffix: `history` tag.
- gitleaks note only in the log: scanner notes rendered under "Not analysed".
- Disable switches treat `0` as disable: only `1/true/yes/on` disable.
- Inventory freshness ignores osv-scanner and dependency options: both in the inventory inputs hash.
- Hostname pattern backtracks quadratically: find TLD occurrences, walk back over host characters (linear).
- gitleaks repeats one history secret at different lines: history results deduplicated by rule, path, and commit.
- "Files too large" paragraph wording: one listing, accurate about what is skipped, mentions the line cut-off.
- `generated_bulk` counts deletions: added lines only.
- Vulnerabilities not by severity: "9 (2 high, 7 medium)".
- Test files under `build/` treated as build output: not when a test directory contains the build directory.
- Doc links in comments reported as hardcoded URLs: skip URLs on comment-only lines.
- Token redaction hides commit SHAs and file names: keep hex SHAs and names with an extension.
- Unknown keys silently ignored: `config check` and every load warn with the dotted key.
- `report.templates_dir` resolves against the cwd: against the engagement root.
- `status`/`cost` crash on a corrupt artifact: shown as unreadable.
- Freshness re-reads whole artifacts: read only the `meta` object from the file's tail.
- Anthropic default `context_window` 200,000: 1,000,000 for `anthropic` backends unless set.
- Dry-run counts stale units; "≤ USD" label: count against the current index; label "≈ USD".
- HTML windows not flagged in the prompt: unit message says "window N of M" for windowed units.
- `max_completion_tokens` for newer OpenAI/Azure: capability `max_tokens_param`; switch automatically on the 400 that names it.
- `render` skipped after a budget stop: render runs after a budget stop; documents show what is complete.
- Verify dedupe merges distinct problems; missing confidence becomes 0.0: key includes overlapping lines; merged count kept; `None` stays `None`.
- `verify`/estimate read stale artifacts: read only ids in the current index.
- Store/system module lists unfiltered: filtered against known paths.
- Two chunks can share a prefix label: labels made unique.
- Prose tag accepts only double quotes: single quotes too.
- Truncated prose accepted: `max_tokens` stop retried once with twice the limit, else recorded.
- Module rollup prompts not trimmed to the window: units trimmed to fit, with an omitted count.
- Model lists uncapped in documents: caps with "(+N more)".
- `call_structured` records a fatal config error per item: re-raised.
- Empty module map renders an empty Mermaid: diagram omitted with a sentence.
- "Used by" matching is substring-based: whole-name matching.
- Prose fallback persists until `--force`: render stays stale while any fallback text is present.
- Model summaries not redacted: summaries, descriptions, purposes redacted at write time.
- `config check` cannot see a server context limit: `config check --probe-context` sends a long prompt with a marker at the start.
- "Serves" column unescaped: `cell` filter.
- `recommended_tool` not validated: unknown names marked "(not a reviewed tool)".
- Unmapped footnote wording without normalisation: says normalisation did not run.
- A crash in `compare` leaves `failures.json` empty: the crash is recorded.
- A failed consolidation is fresh: stays stale so `compare` retries.
- Exit-2 detection matches message text: a typed error.
- No caps on normalisation input or matrix rows: caps with a note.
- Call with no tool spends the forced-answer turn: treated as an invalid call, turn not spent.
- Unknown-tool branch unreachable: removed.
- Empty line ends a session; Ctrl-C prints nothing: `exit`/`quit` end it; Ctrl-C prints the saved line.
- Schema sent twice on non-native backends: once.
- BM25 rebuilt per query: built once per session.
- `grep_source` on unbounded lines: lines cut at 2,000 characters.
- `grep_source` hung on a catastrophic regex: bounded by `ask.grep_timeout_s` (UNVAR-9).
- Question unredacted; second-resolution names; log named `run-`: redacted; millisecond names; `ask-<ts>.log`.
- No tests for truncation or `get_module` by path: tests added.
- Second export in one second overwrites: suffix `-2`, `-3`.
- Export table truncates paths: paths fold instead of truncating.
- `--template` treats any non-`.docx` as CSS: only `.css`; anything else is an error.
- Exporting one tool exports the comparison: only when no tools are named or `--doc comparison`.
- Dependencies reinstall on every source change; `VOLUME` hides a missing `-v`: dependency layer before source; no `VOLUME`; warn when `/engagement` is not a mount.
- Windows paths in osv output: backslashes normalised before relativising.

Fixed earlier:

- The comparison risk table rendered as one line (a block tag ate each row's newline). [4 → fixed in 7]
- `GIT_TERMINAL_PROMPT=0` was not set, so a private URL could stall an unattended run. [1 → fixed in 7]
- Files over 5 MB were skipped without being listed under "Not analysed". [1 → fixed in 7]
- Text I/O did not declare UTF-8. [1 → fixed in 7]
- Model prompts other than ask lacked the "data, not instructions" line. [3, 4 → fixed in 7]
- A backtick in an excerpt broke the Markdown code span. [1 → fixed in 3]
- The run log file was missing. [1 → fixed in 2]
- `report.branding` paths resolved against the current directory. [1 → fixed in 6]
