# Known issues

Every gap accepted at a slice's final review was addressed in the known-issues burn-down (October 2026): fixed, or decided to be correct and recorded in [decisions.md](decisions.md) with the reason. New gaps found by later work are added here; the slice or run that found each is in brackets, and `[rc]` marks the release-candidate validation runs.

## Open

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
  findings match reliably.
- [UNVAR-40] A tool renamed between reviews has no delta: a baseline is resolved by tool
  name, in a findings artifact too (its `tool` field), and the run warns "not in the
  baseline".
- [UNVAR-40] The executive summary prose does not mention the delta (it would cost a model
  call on every baseline change); the section above it carries the comparison.
- [UNVAR-64] A custom `report.branding.html_css` written before 0.1.1 has no `tbody th`
  rule, so the row headers in an HTML export's summary tables take its header styling (wash
  background, bold) until the rule is copied from the bundled `report.css`. PDF and Word are
  unaffected.

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
