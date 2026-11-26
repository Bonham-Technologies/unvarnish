# Decisions

Engineering decisions taken while implementing the design spec
(`docs/superpowers/specs/2026-10-15-unvarnish-design.md`), where the spec was silent, ambiguous,
or overruled by evidence. Each entry gives the decision, why, and what it costs if it turns out
wrong. Process-only choices (branching, review mechanics) are omitted.

## Slice 1: deterministic core

- **`.gitignore` matching uses `pathspec.GitIgnoreSpec`.** The older `gitwildmatch` API is
  deprecated; semantics are the same. *Cost if wrong:* a gitignore edge case differs from git.
- **`tree-sitter` pinned to `>=0.23,<0.26`.** 0.26.0 segfaults freeing large parse trees
  (reproduced standalone on a 60K-line file). *Cost if wrong:* stuck on an older binding until
  upstream fixes it; revisit when 0.26.1+ ships.
  Dependabot's `uv` entry ignores tree-sitter 0.26.0, because its minor-and-patch group
  widened the cap to `<0.27` every week and CI segfaulted (#75, #82); a test keeps the ignore
  in place while the cap stands (UNVAR-46). Only 0.26.0 is ignored, so 0.26.1 and later still
  arrive as group PRs and CI is the check that the crash is gone (0.26.1 shipped on
  2026-11-09, so the next group PR is that check). *Cost if wrong:* a fixed
  rebuild published as 0.26.0 would be missed (low: the cap blocks it anyway), and if 0.26.1
  still crashes, the group PR is held up again until its version is ignored too.
  **Superseded 2026-11-16 (Dependabot #121): `>=0.23,!=0.26.0,<0.27`.** The group PR carrying
  0.26.1 passed the whole suite in CI (1176 passed; only the old cap test failed), as it did
  locally on 2026-11-11, so the cap becomes an exclusion of 0.26.0 alone and the Dependabot
  ignore stays for it. *Cost if wrong:* a parse tree larger than any the suite builds still
  crashes 0.26.1 mid-scan; the fix is restoring `<0.26` and re-locking 0.25.2.
- **Run log file deferred to slice 2.** `failures.json` and `status` covered slice 1's reporting.
  *Resolved in slice 2* (`logs/run-<timestamp>.log`).

## Slice 2: model layer

- **Files of many small top-level statements are grouped at statement boundaries, not
  windowed.** Groups respect `unit_tokens` and keep whole statements. *Cost if wrong:* none.
- **`CompletionRequest.schema` is named `output_schema`.** `schema` shadows a Pydantic method.
- **Backend configuration errors and outages are fatal** (exit 2) rather than recorded phase
  failures. *Cost if wrong:* a transient outage ends the run instead of continuing other tools;
  a rerun resumes from the cache.

## Slice 3: rollups, verification, documents

- **`rollup_tool` treats a missing `git.json` as "history unavailable".** File piles have no
  history and the phase can run alone. *Cost if wrong:* history facts absent from one prompt.
- **`status` shows one row per phase per tool.** Ten columns truncated at 80 characters.
- **Anthropic calls stay non-streaming with a timeout scaled to `max_tokens`** (600 s floor,
  0.05 s per token). *Cost if wrong:* a very slow model on a 32k-token tool rollup times out;
  the failure is recorded and retried next run. Streaming is a hardening candidate.
- **Verification re-sends raw cited source lines to the model.** The spec asks for evidence-only
  verification and the same bytes already went to the same backend during extraction; nothing
  unredacted is written to disk. *Cost if wrong:* a secret in a cited line reaches the model twice.
- **Directory chunking is by sorted-path contiguity**, labelled by common prefix, one level deep.
  A ~1,000-file tool yields under ten chunks. *Cost if wrong:* a 10,000-file tool sends dozens of
  chunk summaries to one final call.
- **Line-less (tool-level) high findings are left visibly unverified** rather than sent to a
  verifier that would reject them for lack of lines.
- **"How this was built" is a prose block**, not a `ToolModel.build_history_summary` field.
- **Module and unit input hashes omit detected frameworks.** *Cost if wrong:* a framework
  detection change does not re-analyse until `--force`.

## Slice 4: comparison

- **`compare` runs even when no tool has a tool model**, so a scanner-only engagement still gets
  the risk comparison; the matrix and proposal are skipped with a stated reason. The spec gates
  compare on at least one `tool.json`. *Cost if wrong:* a reader mistakes a scanner-only
  comparison for a full one; the document header states what was skipped.
- **The risk row carries more measures than spec §5.3 names**, matching `findings.md`.
- **Consultant-provided constraints (spec §17) are not yet an input to the proposal.** *Cost if
  wrong:* a proposal that ignores an approved stack.
- **`run` does not chain `compare`.** They stay separate commands, as in the spec.
- **No `--dry-run` estimate for `compare`.** It is two model calls and two prose blocks.

## Live smoke test (PR #7)

- **Strict schemas treat keys under `properties` and `$defs` as field names, never keywords.**
- **A schema the API rejects as too large is retried in JSON-in-prompt mode.** The tool-rollup
  schema exceeds the Anthropic grammar limit. *Cost if wrong:* slightly weaker output shaping on
  that one call; validation and repair still apply.

## Slice 5: ask mode

- **The structured action schema drives the loop on every backend**; the spec frames it as the
  fallback for weak tool-calling backends. Native tool use would need new protocol methods on
  both backends. *Cost if wrong:* answer quality on Anthropic may lag native tool use.
- **The action schema flattens the spec's free-form `args` into typed fields**, because a strict
  schema cannot carry an open object. *Cost if wrong:* a new tool argument is a schema change.
- **The index rebuilds when any of six per-tool artifacts changes**, a superset of the spec's
  "any `tool.json` is newer". *Cost if wrong:* an extra cheap rebuild.
- **`get_module` accepts a file path as well as a module id**, since models cite paths.
- **Exit 1 when a question got no answer; unverified answers exit 0.** The spec is silent.
- **The consultant's `--tool` overrides the model's choice of tool.**
- **The per-invocation budget starts at zero**, like `run` and `compare`.

## Slice 6: export and distribution

- **No `--migrate` yet.** An engagement with a newer `schema_version` is refused with an
  upgrade message. *Cost if wrong:* a future schema bump needs migrations before it ships.
- **`--template` applies to one output kind per invocation** (a `.docx` reference or a `.css`
  stylesheet). *Cost if wrong:* two invocations for a fully branded export.
- **DOCX diagrams are PNG; HTML and PDF diagrams are SVG.** Word's SVG support is uneven.
- **Graphviz is called as `dot` via subprocess**, not through the Python binding in spec §12.1.
- **Pandoc runs inside the export work directory**, inferred from `--resource-path`. Pandoc 3.1.x
  writes its PDF intermediate into the current directory and weasyprint resolves images
  against it. *Cost if wrong:* a future caller without `--resource-path` runs pandoc in the
  process directory.
- **Branding paths in `engagement.yaml` resolve against the engagement; `--template` against the
  current directory.** The engagement is meant to be zipped and moved.
- **gitleaks, osv-scanner, and the OSV database are not yet in the image**; they arrive with
  their scanners in slice 7.

## Known-issues burn-down

- **History scans use `--all` and skip merge diffs.** Secrets in any ref matter, and a merge
  commit's diff repeats its parents'. Full history (no shallow clone) is needed for the bus
  factor and secrets; submodules are separate tools; a worktree's `.git` file is not portable,
  so add such a repository by URL. *Cost if wrong:* a secret only in a merge resolution is
  missed.
- **`--link` paths are invisible inside Docker** by design: the container sees only mounted
  folders. The runbook and operations say to use `--repo` or `--files`.
- **No abandoned-package check.** It needs registry lookups over the network; Unvarnish is
  offline-first. *Cost if wrong:* an unmaintained dependency without advisories is not flagged.
- **Small local models' judgement is theirs.** Count mistakes in prose are retried; reporting
  intended content (a contact email in a privacy policy) as a finding is model quality, not a
  defect to code around.
- **`pipeline.concurrency` caps model calls across the engagement**, and
  `pipeline.parallel_tools` (default 4) sets how many tools run at once. Concurrency was per
  tool before. *Cost if wrong:* a multi-tool run with a small concurrency is slower than
  before, but never overloads an on-prem server.
- **The export style is neutral by default** (Inter with offline fallbacks, slate headings,
  "Confidential", page numbers, Letter paper); `branding/bonham/` is the copy to customise.
- **Documents cap model-written lists at 60 rows** with a "(+N more)" note; everything stays in
  the analysis files and `ask`.
- **URLs on comment-only lines are not hardcoded endpoints**: they are documentation links. A
  commented-out endpoint is not reported. *Cost if wrong:* a production URL kept only in a
  comment goes unmentioned.
- **`bin/` is not build output**, because Go, Ruby, and shell projects keep scripts there;
  compiled files in it are already classified as binary.
- **A failed prose call keeps `render` stale** so the next run retries it; a missing model
  does not, since retrying cannot help.

## Comparison validation and site kit

- **Constraints are trusted consultant input.** They sit in their own section of the
  consolidation request, outside the "data, never instructions" material, and are stored in
  `comparison.json` with the proposal they shaped. *Cost if wrong:* a constraint copied from a
  client document carries that document's wording into the prompt.
- **Conflicts are a separate list, not folded into gaps**, so the consultant sees exactly where
  their constraints bite. *Cost if wrong:* none known.
- **Large cited files are verified through windows** (up to six, twelve lines either side of
  the lines matching the claim's identifiers and longer words). A large file with no matching
  line leaves the finding unverified. *Cost if wrong:* a claim about something absent (no
  authentication anywhere) has no lines to match and stays unverified.
- **Prose count mismatches are retried, not rewritten.** The model may be describing a subset
  ("two of the high findings"), so a mismatch after the retry is recorded, not edited.
- **Store and system grouping is a model call**, like capability normalisation: names alone
  cannot tell that "Shared ESCAPE Suite IndexedDB" and "IndexedDB video-editor-db" are one
  database. In-process state is marked internal and left out of the map. If the call fails,
  entries join by name. *Cost if wrong:* two distinct stores with similar descriptions merge.
- **Refusals are retried once on the same model, then on an optional fallback.** Safety
  classifiers refuse benign review material intermittently (security findings, "execute
  arbitrary command" capabilities). Refusals are never cached. *Cost if wrong:* one extra call
  per genuine refusal.
- **The site kit carries all eight ecosystems** (about 290 MB of advisories, a 530 MB image
  tarball) so no client codebase arrives with an unchecked ecosystem.

## Release-candidate validation

- **A timeout is the unit's failure, not the run's.** A connection that cannot be made is still
  fatal (nothing else will succeed), but a server that is slow on one large unit is recorded in
  `failures.json` and the run moves on. Timeouts are not retried because the retry repeats the
  slowest work the server has. *Cost if wrong:* a server that is slow on every unit records every
  unit as failed instead of stopping early.
- **The OpenAI-compatible default timeout is 30 minutes.** CPU-only servers took up to 10 minutes
  for one 4,000-token unit in testing. *Cost if wrong:* a hung server holds a worker for 30
  minutes per unit before it is recorded.
- **Build output is recognised by directory pattern** (`dist-*`, `dist_*`, `playwright-report*`,
  `test-results`, `storybook-static`, `htmlcov`, framework caches) as well as the fixed list.
  `build-*` is not matched because it is often source. *Cost if wrong:* a source directory named
  like `dist-tools` is excluded and reported under vendored or build directories.
- **Files with no behaviour are not split.** Ignore files, licences, crawler files, editor and
  version pins. Documentation, CSS, and changelogs are still split, as the spec's split rules
  describe. *Cost if wrong:* nothing a model would say about these files is lost.
- **Oversized findings are grouped per severity**, like hardcoded infrastructure, so a large
  codebase gets one readable finding with its worst locations rather than dozens of sections.
  Test files keep the file-size check but not the function-length check. *Cost if wrong:* a
  giant test helper function is not reported.

- **Low and info findings are a table, not sections.** Spec 8.4 lists full fields for every
  finding; at 2,000+ findings that made a document no one reads. Sections stay for medium and
  above (configurable with `report.detail_from`); every field stays in `findings.json`.
  *Cost if wrong:* a reader of the document alone sees no impact or remediation for low
  findings.
- **One-unit modules skip the module rollup call.** Spec 6.7 says one call per module; the
  call exists for problems across units, which a single unit cannot have, and on ESCAPESUITE
  it restated the unit and added 1,009 low findings. *Cost if wrong:* a file-level observation
  the unit pass missed; `pipeline.rollup_single_unit_modules: true` restores the call.
- **Tool-level claims are verified against whole files** when every cited file is at most 600
  lines and all together at most 1,500. Larger citations stay unverified and say so. *Cost if
  wrong:* a verifier shown a whole file may miss a detail a targeted excerpt would show.
- **Near-duplicate tool findings are merged deterministically** (same severity, half the cited
  files shared, 30% of title words shared). *Cost if wrong:* two distinct problems in the same
  files with similar titles become one finding with both sets of evidence.

## Slice 7: remaining scanners and hardening

- **No "abandoned package" check.** It needs registry lookups over the network, and the tool
  defaults to no network at client sites. *Cost if wrong:* an unmaintained dependency is not
  flagged unless it also has advisories.
- **osv-scanner runs offline by default** (`scanners.dependencies.offline: false` allows online
  lookups). Without a local database, advisories show "not checked" with osv-scanner's reason.
- **The OSV database is seeded into the image only on request** (`--build-arg OSV_ECOSYSTEMS`),
  because the full database is large. osv-scanner 2.7 reads it from
  `$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scalibr/<ecosystem>/all.zip`. *Cost if wrong:* an
  unseeded image reports advisories as not checked.
- **The inventory hash does not include the OSV database**, so a refreshed database needs
  `unvarnish run --phase inventory --force`. *Cost if wrong:* stale advisories until forced.
- **Unpinned dependencies are reported only when no lockfile pins that ecosystem.** A lockfile
  makes ranges reproducible. Go modules always count as pinned; a bare Cargo version counts as
  a range.
- **`hardcoded_infra` skips tests by default** (`include_tests: true` to include them), reports
  ports only as part of `host:port`, and ignores loopback, example domains, schema and
  namespace URLs, and version-like dotted numbers. *Cost if wrong:* an endpoint used only in
  tests, or a bare port, goes unreported.
- **gitleaks only adds what the built-in rules missed.** A tree result at a line the built-in
  rules reported, or a history result for a commit and file they reported, is dropped; gitleaks
  always runs with `--redact`, so Unvarnish never sees the raw value. *Cost if wrong:* a second
  distinct secret on the same line is not double-reported.
- **Test-only switches `UNVARNISH_DISABLE_OSV` and `UNVARNISH_DISABLE_GITLEAKS`** keep the
  suite's results independent of what is installed on the machine running it.
- **Prompt version bumps for the data-not-instructions guard** invalidate cached responses for
  those prompts once. *Cost if wrong:* one re-analysis on engagements started before slice 7.
- **"Offline" means `--offline`, not `--offline-vulnerabilities`.** The latter still resolves
  transitive dependencies through api.deps.dev. Offline runs also pass `--all-packages`, so an
  ecosystem with packages but no loaded database is named in the note. *Cost if wrong:*
  transitive advisories that only network resolution finds are missed offline.
- **Scanner configuration comes from Unvarnish, not the vetted repo.** osv-scanner always gets an
  empty `--config`; gitleaks gets a config that extends its default rules, plus
  `--ignore-gitleaks-allow`. The repo's own suppressions are reported as a finding instead.
  *Cost if wrong:* findings the client deliberately suppressed reappear; the suppression
  finding explains why.
- **`.gitleaksignore` cannot be neutralised.** gitleaks 8.30.1 reads it from the scan root even
  when `--gitleaks-ignore-path` points elsewhere. Its presence raises the suppression finding to
  medium, and the built-in secret rules ignore it. *Cost if wrong:* a secret listed there is
  missed by gitleaks, though the file itself is named.
- **URL values keep scheme, host, port, and path only.** Credentials become `***@`; query
  strings and fragments are dropped; webhook hosts keep no path; path segments that look like
  tokens become `[redacted]`. *Cost if wrong:* a reader sees less of the URL than the code
  holds, including commit SHAs in links.
- **`hardcoded_infra` filters by file and context.** Ignore files are skipped, Dockerfile and
  compose paths are container paths, web-language paths are reported only under home or user
  directories, and URLs on `$schema`, `xmlns`, or `schemaLocation` lines are identifiers.
  *Cost if wrong:* a real absolute path in web code outside a home directory is missed.
- **git keeps the operator's SSH and credential setup.** `BatchMode=yes` is appended to
  `GIT_SSH_COMMAND` or `core.sshCommand`; `GIT_SSH` is left alone; a non-empty `GIT_ASKPASS` is
  kept. *Cost if wrong:* a `GIT_SSH` wrapper that prompts can still stall a run.
- **Final-review rulings on items the reviewer left open:**
  - Engagement artifacts such as `dependencies.json` keep raw constraints, like the source copy
    beside them; only rendered documents are scrubbed. *Cost if wrong:* an engagement folder
    shared whole carries what the repo carried.
  - `--repo <local path>` ingests the working tree, uncommitted files included, because that is
    what the consultant pointed at. *Cost if wrong:* scratch files are analysed.
    It leaves out only the untracked directories the inventory excludes anyway as
    dependencies or build output (`is_dependency_or_build_dir`: `.venv`, `node_modules`,
    `__pycache__`, `dist` and the rest of `VENDORED_DIRS` and `BUILD_DIRS`), names them in
    `tool.yaml` (`skipped_at_ingest`) and under "Not analysed" (UNVAR-8). A tracked one, such
    as a committed `vendor/`, is still copied so the vendored-code finding sees it, nothing
    under a submodule is left out (the index lists a submodule only as its commit), and other
    gitignored files such as `.env` are still copied and scanned. *Cost if wrong:* a secret
    kept only inside an untracked `.venv` or `node_modules` is not scanned.
  - Go `vendor/` counts as vendored code. *Cost if wrong:* none known.
  - The image stays about 1.4 GB (pandoc, weasyprint, Graphviz, scanners). *Cost if wrong:*
    slower transfer to air-gapped sites.
  - `uv:latest` in the Dockerfile and Windows paths in osv-scanner output are logged in
    known-issues rather than fixed here.

## Autopilot fixes

- **Git never runs an ingested repo's hooks, fsmonitor or ext:: transports (UNVAR-15).**
  `git_env()` appends `core.hooksPath=<empty dir>`, `core.fsmonitor=false` and
  `protocol.ext.allow=never` to `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`, keeping entries the
  operator already set. Command-scope config outranks the repo's `.git/config`, and the
  environment reaches gitleaks' own `git` child too. `core.sshCommand` comes from `--global`
  then `--system` only. Unvarnish's own git calls also pass the three settings as `-c`, which
  outranks a `-c` inherited from the operator's environment and works on git before 2.31,
  which ignores `GIT_CONFIG_COUNT`. The ingest checkout passes `--work-tree`, because a
  `core.worktree` in the copied config outranks even command-scope config and would send the
  branch's files anywhere on disk. *Cost if wrong:* a repo whose checkout needs its own hooks to produce
  the files (generated sources, for instance) is analysed as committed, without them. Git
  LFS is unaffected: it works through a filter driver, not hooks.
  Repo-defined filter and textconv drivers are covered by the next ruling (UNVAR-26).

- **A repo's own filter and diff drivers are disarmed by name, per git call (UNVAR-26).**
  Drivers are named, so no fixed override covers them. `repo_drivers()` reads the repo's own
  config files (`git rev-parse --git-dir --git-common-dir`, then `config` and
  `config.worktree`) with `git config --file … --no-includes --list`, and follows every
  `include.path` and `includeIf.*.path` whatever its condition: an `onbranch:` include that
  is false before the ingest checkout is true after it. Reading config runs nothing. Each
  `filter.<name>` gets empty `smudge`, `clean` and `process` and `required=false` (git skips an
  empty filter command, and `required` would otherwise fail the checkout); each
  `diff.<name>` gets `textconv=cat`, because git runs an empty textconv and fails, and `cat`
  passes the content through, and `cachetextconv=false`, since a cache writes notes refs into
  the repo it reads (the client's own, for `--link`). They go into the same command-scope environment as UNVAR-15's
  settings (so gitleaks' `git log -p` gets them) and, for Unvarnish's own calls, as `-c`. The
  names are read afresh for every call rather than cached, since a checkout can change which
  includes apply. Only the repo's own config is read: the operator's global and system
  drivers (git-lfs) are trusted and keep working. A diff driver's `command` is left alone: it
  runs only for `git diff` or `--ext-diff`, which neither Unvarnish nor gitleaks uses, and an
  empty one fails. More than 200 drivers, or more than 64 included files, is refused rather
  than handled in part. Names are matched as git matches them: byte for byte (a name that
  isn't UTF-8 is kept as its bytes), including the empty name `filter=` selects, and a
  relative include resolves from the directory the including file was opened from, not where
  a symlink leads; a file opened from two directories is followed from both.
  Removing the sections from the ingest copy's config was the alternative; it would not cover
  `--link`, which has no copy, so one mechanism serves both. *Cost if wrong:* a repo whose
  files need their filter to be readable (git-crypt, or LFS installed with `--local`) is
  analysed as stored in git (ciphertext or LFS pointers) rather than decoded; a driver name
  reached through an include path written with `%(prefix)` is not found; and a repo whose
  config includes more than 64 files can't be analysed.
- **Submodule recursion is off for every git child, and the driver lookup fails closed
  (UNVAR-26 QC).** A submodule's drivers live in its own gitdir config
  (`.git/modules/<name>/config`), which `repo_drivers()` does not read; one line in the
  client's config (`submodule.recurse=true`) made the ingest checkout run the submodule's
  smudge filter, and `diff.submodule=diff` made `git log -p` (gitleaks') run its textconv. The
  fixed overrides now include `submodule.recurse=false`, `fetch.recurseSubmodules=false` and
  `diff.submodule=short`, and `log.showSignature=false` (a repo's `gpg.program` would
  otherwise run for gitleaks' `git log`; Unvarnish's own calls already passed it as `-c`).
  Reading the submodules' configs too was the alternative; turning recursion off is complete
  and simpler. The lookup itself (`rev-parse`, then `git config --file` per file) now raises
  `UntrustedRepoError` on a timeout, an OSError or a failed read, instead of returning no
  drivers: the git call that follows has no time limit and would run them. Outside a
  repository it still returns none; the lookup's git children run with `LC_ALL=C` so git's
  "not a git repository" is read untranslated. `add` reports the refusal's reason instead of what failed
  as a result. *Cost if wrong:* submodule contents are analysed as the superproject records
  them (a commit id), never checked out; a repo whose config is too large to read in 30
  seconds is refused.
- **A local repo whose `.git` is a file or a symlink is copied with a real git directory
  (UNVAR-26).** The shared directory (`--git-common-dir`, without `worktrees/`) becomes the
  copy's `.git`, and a linked worktree's own `HEAD` and `index` are copied over it, so the copy
  starts where the client's worktree is. Every copy has `core.worktree` removed from its
  config. *Cost if wrong:* per-worktree refs (`refs/bisect`, `refs/worktree`) and the
  worktree's reflog are not copied; none of them is analysed.

- **Ctrl-C stops a run the way the budget cap does (UNVAR-16).** `BudgetTracker` carries an
  `interrupted` event; `check()` raises `RunInterrupted`, a `BudgetExceeded` subclass, so every
  phase's existing cap handling applies: pending work is skipped, running calls finish, the
  phase reports `stopped` and stays stale. `PhaseRunner` starts no phase after it, and
  `LimitedBackend` refuses a call that was waiting for a slot, because with tools in parallel
  most workers wait there after their budget check. The CLI waits on the tool futures with a
  0.1 s timeout so the interrupt reaches the main thread while tools run. *Cost if wrong:*
  calls in flight still finish and are billed; aborting them would lose work already paid for
  and leave no record of it.

- **A failed unit or module keeps its phase stale until it succeeds (UNVAR-29).** `extract`
  and `rollup_modules` record an empty inputs hash while they have failures, the mechanism a
  budget stop and render's failed prose already use, and `is_fresh` also treats them as stale
  while `failures.json` holds entries for them, so engagements written before the fix heal
  without `--force`. A plain `run` retries them; done items are kept by their per-item hashes. No attempt limit: a unit that always fails is retried on
  every run, as the docs promise for timeouts. *Cost if wrong:* each rerun spends up to three
  calls (two attempts and the repair call) per permanently failing item, and the later phases
  rerun on the rewritten state; their requests are unchanged, so the response cache answers
  them. `verify` still records its full hash when a verification fails; its findings stay
  "verification failed" until the model findings change or `--force`.

- **An unexpected error in an extract worker fails that module, not the phase (UNVAR-32).**
  A non-backend exception from a module's worker (its file deleted since split, a full disk
  on an artifact write) is recorded in `failures.json` against the module, with the unit in
  hand if there was one, as `run_parallel` does for the other model phases; the other
  modules finish, and the record keeps the phase stale so a plain rerun retries it. Fatal
  backend errors and Ctrl-C still stop the phase as before. Separately, extract-state records
  an empty inputs hash whenever units are left undone, so no other early exit (an interrupt
  re-raised through the `finally`) can leave it fresh. Tokens are charged before a unit's
  artifact is written, so a failed write still counts what it spent. *Cost if wrong:* the
  units after the failing one in the same module are left undone without their own failure
  records, so the run table says "1 failed" while `status` shows more units missing
  ("11/16 units (1 failed)"); the rerun does them all.

- **ask's grep uses the `regex` package for its timeout (UNVAR-9).** Python's `re` has no
  timeout and holds the GIL, so neither a thread nor a signal can stop a catastrophic
  pattern; a subprocess per grep would cost far more than a small, wheel-only dependency.
  `regex` in its default (V0) mode takes `re`'s syntax. Each line's search gets what is left
  of one `ask.grep_timeout_s` budget (default 5 s), and the grep stops once it is spent, file
  reads included, so a large tool can end early with the same error. `regex` writes out each
  repeat's minimum count at compile time, which the timeout does not cover, so a pattern
  whose nested minimums multiply past 20,000 nodes is refused before compiling. *Cost if
  wrong:* a pattern `regex` reads differently from `re` (rare edge cases in nested character
  sets) matches differently; a grep over a very large tool reports "too slow" for an ordinary
  pattern; a legitimate pattern with huge repeat counts is refused (none can match a
  2,000-character line anyway).
- **Exports declare a language and give diagrams sentence alt text (UNVAR-7).** pandoc gets
  `--metadata=lang:<report.lang>` (default `en`) for every format, and each diagram image's
  alt text comes from a fixed sentence per diagram name (`context`, `modules`,
  `integration`), else "Diagram: <title>". The language is per engagement, not per document,
  because the templates and prose are written in one language. *Cost if wrong:* a report
  whose prose is in another language says `en` until the engagement sets `report.lang`.
- **The coverage floor runs on plain `uv run pytest -q` (UNVAR-10).** `--cov` is in the
  pytest `addopts`, so the verify command, CI and every builder run enforce the same floor
  (branch coverage, `fail_under = 94`) with no extra flags. *Cost if wrong:* every partial
  run fails the floor unless it adds `--no-cov`, and the suite runs about a minute slower.
- **Exports load only their own diagrams and keep only web and mail links (UNVAR-12).** The
  bundled filter (`export/assets/inert-html.lua`) replaces any image whose source is not
  `images/<name>.<ext>` and present in the export's work directory, the files
  `prepare_markdown` writes, with its alt text, and any link that is neither an in-document
  `#anchor` nor `http`, `https` or `mailto` with its text and target. Paths (`/etc/passwd`,
  `//host/share`, `../x`) are made inert too, because weasyprint turns them into live `file:`
  links in the PDF. *Cost if wrong:* an image, a relative link or a custom-scheme link
  (`vscode:`, `ftp:`) that someone adds to a document by hand on purpose shows as text.
- **Exports treat raw HTML as text (UNVAR-2).** pandoc reads with `gfm-raw_html` and a bundled
  Lua filter (`export/assets/inert-html.lua`) turns any raw HTML that remains into visible text,
  because pandoc 3.1's gfm reader keeps raw HTML even with `-raw_html`. The fix is at export,
  so the Markdown documents stay readable. *Cost if wrong:* raw HTML someone adds to a document
  by hand on purpose, including comments, shows as text in HTML, PDF, and Word.
- **Documented example keys and placeholder PEM bodies are not secrets (UNVAR-3).** Every
  rule skips a value that is a vendor-documented sample or contains `EXAMPLE`; a private-key
  header whose body is `...`, `MIIE...`, or under 40 base64 characters is skipped. A body line
  with a colon (an encrypted key's `Proc-Type:` header) or no body at all still counts as a
  key. *Cost if wrong:* a real credential that happens to contain `EXAMPLE`, or a real key
  split so its first body line is under 40 characters, is missed.

- **A phase missing an earlier phase's artifact names that phase (UNVAR-5).** `PhaseRunner`
  catches the `FileNotFoundError`, finds the earlier phase whose `outputs()` include the
  missing file, and names the earliest phase up to it whose outputs are not all present. The
  phase stays `failed` (not `skipped`), so `run` keeps its non-zero exit and `status` counts
  it. Only a missing file that some earlier phase produces gets the message; any other
  `FileNotFoundError` is a crash, logged with its traceback as before. *Cost if wrong:* a
  phase that reads an earlier artifact without failing on its absence gets no hint; the
  message reports one phase, and the consultant may need several (`unvarnish run <tool>`
  runs them all).

- **The dry run plans downstream phases from declared dependencies; the real run still
  checks each phase's hash (UNVAR-30).** A phase's hash covers its upstream artifacts, which
  change only when the upstream reruns, so `PhaseRunner.plan` cascades: a phase is planned
  when it is stale or a phase in its `depends_on` is planned. `depends_on` is declared on each
  phase class (a phase without one depends on every earlier phase), and a test derives it
  from each `inputs_hash` by perturbing every other phase's outputs. `plan` is used only by
  the dry run; `run` keeps its per-phase freshness check, so the cascade never makes a real
  run redo work. When split would rerun, the extract estimate splits the current source in
  memory (and, when inventory would rerun too, builds the census's file records in memory)
  and compares each unit's expected hash with its artifact's; nothing is written. The
  engagement phases (`compare`, `render_comparison`) have no dry run and are not planned.
  *Cost if wrong:* a phase whose `depends_on` misses an input stays off the dry-run list
  (the test catches a hash that changes); the dry run reads and parses the whole source,
  which on a very large tool takes as long as inventory and split.

- **The secrets tree pass skips tool caches by path, and still reads build output and other
  gitignored files (UNVAR-18).** `tree_skip_reason` skips any file under a `TOOL_CACHE_DIRS`
  directory (`.pytest_cache`, `__pycache__`, `.mypy_cache`, `.ruff_cache`, `.gradle`,
  `.parcel-cache`, `.angular`), whatever the census's exclusion reason, and even under a test
  directory (`tests/.pytest_cache`). The path decides because gitignore outranks
  `build_output` in the census, and pytest writes a `.gitignore` into its own cache: its node
  ids, which hold test parameters, were reported as 20 critical GitHub tokens. The ticket
  asked for every `BUILD_DIRS` path to be skipped; that was narrowed to caches because build
  output is shipped code: a key a bundler inlined into a committed `dist/` bundle is a live,
  public leak, and skipping it would have dropped it to a high history finding, or to nothing
  in a copy without git history. Build output (`dist/`, `build/`, `out/`, `.next/`,
  `.vercel/`, coverage and test reports) is still read, as before. Every gitignored text file
  outside a cache, a vendored directory or the 5 MB limit (a `.env`, a local config, a local
  build) is read; "Not analysed" says so. The census's `gitignore` reason comes from the
  ignore rules alone, not from git's index, so a `.env` committed and ignored later still gets
  it. The note on a secret therefore depends on what git says: in a repository, a file
  `git ls-files` does not list says "gitignored: present in the ingested copy, not in the
  repository", and a tracked file gets no note, because it is in the repository; in a copy
  without git, or when `git ls-files` fails, the note says only "matches a .gitignore rule:
  may be absent from the repository". *Cost if wrong:* a credential that exists only in a
  tool cache, for example in a test parameter whose test was deleted, goes unreported in the
  working tree;
  and a key baked into build output is reported twice, once in the bundle and once in the
  source or `.env` it was built from, and a vendored test key copied into a bundle is still a
  false positive the consultant dismisses. `git ls-files` reads only the checked-out branch,
  so a file committed on another branch and untracked on this one is called absent from the
  repository; the history pass reads every branch and adds "also appears in N commit(s)" to
  the same note.

- **The engagement lock is `flock` on `.unvarnish/run.lock`, judged by kernel identity, with a
  heartbeat for the rest (UNVAR-6).** `run`, `compare` and `ask` hold it; `status`, `cost`,
  `export` and `run --dry-run` read only and don't. The file is opened (never replaced or
  deleted, so every process locks the same inode) and locked with `LOCK_EX | LOCK_NB`; the
  kernel drops the lock however the holder exits, so there is no read-then-write race and no
  PID check on the common path. The holder writes its PID, hostname, start time, the
  kernel's `boot_id` and its PID namespace into the file and empties it on release; a file
  with contents and a free `flock` is a leftover. A leftover from the same kernel (equal
  `boot_id`, or equal hostname where neither side has one, as on macOS) is stale at once:
  this covers every container on one Docker host, whose hostnames and PID namespaces differ
  but whose kernel and `flock` are shared, which a hostname-plus-PID check gets wrong both
  ways. A leftover from another kernel may belong to a live holder whose lock this kernel
  can't see, so it is stale only once the holder's heartbeat (the file's mtime, refreshed
  every 30 seconds) is older than `pipeline.lock_stale_minutes` (default 10), with one
  exception: a leftover naming this machine's hostname, from an earlier `boot_id`, whose last
  heartbeat predates this kernel's boot (`/proc/stat` `btime`) is a reboot and is stale at
  once, so a scheduled run after a restart doesn't fail. Age is measured
  from the heartbeat, not the start time, so a long run is never taken for a dead one; and a
  live holder on the same kernel is never taken over, however old, because the kernel says it
  is alive (a hung or Ctrl-Z'd run is stopped by the operator, not by a timer). Where the
  filesystem refuses `flock` (`ENOLCK` on some NFS setups) the lock falls back to the file's
  contents: a dead PID in the same kernel and PID namespace, or an old heartbeat. The stale
  age is an engagement setting, like the other pipeline tunables, so it travels with the
  engagement into a container. An interactive `ask` session holds the lock while it waits for
  input, since it writes `cost.json` and the ask index. Checks that refuse a command
  outright (no tools, an unknown or missing tool, no model for `ask`) run before the lock is
  taken, so a refused command never blocks another run or is blocked by one; a `run` with a
  missing tool and others to run takes the lock, runs the others and exits 2. *Cost if wrong:* where `flock` does
  not span the processes involved (the macOS host beside a Docker Desktop container, SMB
  shares) mutual exclusion rests on the contents, so two runs starting in the same instant
  both run; a dead holder there blocks for up to `lock_stale_minutes`; a container sharing a
  `boot_id` but not the mount's lock (a network filesystem mounted separately in each
  container) would be judged dead while alive; two machines given the same hostname on one
  share, one of which booted within a heartbeat of reading the other's live lock, would both
  run; and a forgotten `ask` session blocks the scheduled run until it is closed.

- **`config check` records its probes in the ledger without taking the engagement lock; each
  ledger write holds its own `flock` on `.unvarnish/cost.lock` instead (UNVAR-33).** Taking
  the engagement lock would refuse `config check` during a long run, when checking a backend
  is still useful. The ledger lock is held for one read-modify-write, so a blocking wait is
  short; where the file can't be opened or `flock` is refused, the write goes ahead unguarded
  as before. *Cost if wrong:* across kernels that don't share `flock` (the macOS host beside a
  Docker Desktop container) a `config check` and a run writing the ledger in the same instant
  can still lose an entry or leave `cost.json` unreadable.

- **The git index outranks `.gitignore` in the census (UNVAR-28).** Git never ignores a
  tracked file, so a file `git ls-files` lists is never excluded with reason `gitignore`; it
  is named in the census's `tracked_despite_gitignore` and under "Not analysed". Only the
  `gitignore` reason changes: a tracked file under `build/` or `node_modules/` is still
  `build_output` or `vendored`, as the vendored-code finding expects. The index is read only
  for a `--repo` or `--link` tool whose source root holds `.git`, as the git phase does; a
  `--files` pile keeps its `.gitignore` as written even if a `.git` came along in the copy,
  and a repo git refuses (untrusted) or can't read falls back to the same. The tracked list
  is part of the inventory's inputs hash, so `git rm --cached` on a linked repo reruns it.
  *Cost if wrong:* a `--link` to a subdirectory of a repo has no `.git` of its own, so its
  tracked-but-ignored files are still excluded, as before.

- **PDFs are PDF/UA-1 whenever weasyprint can tag them without hiding links (UNVAR-22).**
  pandoc passes `--pdf-variant=pdf/ua-1` to weasyprint for every PDF, with no setting to turn
  it off: tagging changes nothing a sighted reader sees, and an untagged report fails any
  client policy that requires tagged PDFs. weasyprint 61 to 65 set every link annotation's
  Hidden flag (`/F 2`) in PDF/UA mode, so Acrobat drew no link and none could be clicked;
  66.0 is the first release whose `pdf/pdfua.py` no longer does (checked in the 61.2 to 70.0
  wheels on PyPI). *Cost if wrong:* a later weasyprint that hides links again would ship
  unclickable reports; `test_pdf_export_is_tagged_and_its_links_stay_visible` reads the
  annotations and fails on it wherever weasyprint 66+ is installed.
- **An old weasyprint exports untagged with a warning, rather than failing (UNVAR-22).**
  `export` reads `weasyprint --version` once when PDF is asked for. Below 66.0, or when the
  version can't be read, it leaves the PDF/UA option out and prints one warning naming the
  version and the upgrade; the PDFs are written as before. A consultant on a laptop with
  Debian's or Ubuntu's weasyprint still gets a usable report, and the warning says why it is
  untagged. *Cost if wrong:* a consultant who misses the warning hands a client an untagged
  PDF where the client's policy requires tagging; they would have to read the export output
  to notice, where a hard failure would have stopped them.
- **The Docker image installs weasyprint from PyPI, in a venv of its own (UNVAR-22).**
  Debian trixie ships 62.3, which hides links when tagging. `docker/weasyprint.txt` pins 70.0
  and every dependency with hashes (`uv pip compile --universal --generate-hashes`, so amd64
  and arm64 resolve the same file), installed with `--require-hashes` into `/opt/weasyprint`
  and linked into `/usr/local/bin`. Its own venv keeps its Pillow, fonttools and cffi from
  ever constraining Unvarnish's lock, and keeps weasyprint out of `pyproject.toml`; apt still
  supplies the libraries it loads (pango, pangoft2, harfbuzz-subset). *Cost if wrong:*
  Dependabot doesn't read `docker/weasyprint.txt`, so weasyprint and its dependencies are
  bumped by hand (regenerate with the command at the top of `docker/weasyprint.in`) and can
  fall behind on a security fix.
- **Word Title and Author are written after pandoc, not through its metadata (UNVAR-21).**
  pandoc fills `dc:title` and `dc:creator` only from `title` and `author` metadata, and its
  docx writer then also prints both as Title and Author paragraphs above the report's own H1.
  So the exporter rewrites `docProps/core.xml` in the finished `.docx` (entry order kept):
  Title is the document's H1, Author is the engagement's `consultant`, else "Unvarnish". The
  body is unchanged, and `dc:language` already came from `--metadata=lang` (UNVAR-7). *Cost
  if wrong:* a later pandoc that names the core-properties part differently leaves Title and
  Author empty again, as before; `test_docx_core_properties` fails on it.
- **Links are underlined in print rather than followed by their URL (UNVAR-23).** Both
  satisfy the ticket; an underline keeps tables and finding paragraphs readable, where a
  printed `(https://…)` after every source link would double their width. *Cost if wrong:* a
  printed report shows where a link is but not where it goes; the PDF keeps the live link.
- **Package-manifest metadata URLs are not infrastructure (UNVAR-24).** The hardcoded-URL
  scan skips URLs on the lines of named metadata keys only: `[project.urls]`,
  `[tool.poetry.urls]` and Poetry's `homepage`/`repository`/`documentation` in
  `pyproject.toml`; the same three under `Cargo.toml` `[package]`; `url`, `download_url` and
  `project_urls` under `setup.cfg` `[metadata]`; and, in `package.json`, the URLs inside the
  top-level `homepage`, `repository`, `bugs` and `funding` values (parsed and matched by
  value, so a nested `repository` key in a tool's own config and another URL on the same
  minified line are still scanned). A `[[tool.uv.index]]` or `[[tool.poetry.source]]` table
  ends the metadata section, so private package-index URLs are still reported. Markdown and
  YAML files under `.github/ISSUE_TEMPLATE/` are skipped whole. Install hints in code (a
  `pandoc.org/installing` link in an error message) are still reported: telling them from
  endpoints needs more than a line. *Cost if wrong:* an internal
  URL a team put in `[project.urls]` (an internal wiki, a self-hosted GitLab) is not listed;
  it names where the project lives, not a service the tool calls.
- **Tree-sitter grammars are fetched ahead of time with the pack's own API, into the pack's
  own cache (UNVAR-45).** `unvarnish grammars fetch` calls `tree_sitter_language_pack.prefetch`
  for `grammar_languages()`: every language the census can detect except `text` and
  `jupyter`, which have no grammar (43, about 70 MB unpacked; config and docs languages
  included so test-folder YAML keeps its tree-sitter metrics). It retries with exponential
  backoff (5 s, then doubling; 4 attempts by default, 5 in CI). The runtime location is the
  pack's own `TREE_SITTER_LANGUAGE_PACK_CACHE_DIR` (the image sets `/opt/tree-sitter`;
  laptops keep `~/.cache`), not an Unvarnish variable, and no version string is hard-coded:
  the pack nests its cache by its own version. `get_parser` no longer asks the pack for a
  language outside that list, so `text` never triggers a download. Bundling grammars in the
  wheel was rejected: they are per-platform binaries the pack already distributes. *Cost if
  wrong:* the pack renames that environment variable or the `prefetch` API in a later major,
  and the image falls back to first-use downloads; `grammars status` in the site-kit check
  and the CI fetch step would fail on it.
- **A missing grammar is a note, not a failure (UNVAR-45).** The run still finishes with line
  counts; the warning is logged once per language per process, the census records
  `grammars_unavailable` and a note per language, and the findings document lists the notes
  under "Not analysed". It is not a recorded failure, because nothing is retried by rerunning
  alone. *Cost if wrong:* a reader skims past the note and trusts function lengths that were
  never measured; the "Very large function" finding is then absent, not false.
- **The inventory reruns only when a missing grammar has arrived (UNVAR-45).** Its inputs hash
  gains a `grammars-now:` part only when a grammar the last census lacked is now in the
  cache, so complete inventories keep the hash they always had, a still-missing grammar
  doesn't rerun the inventory (and the tool rollup that hashes the census) on every run, and a
  run after `grammars fetch` measures again. *Cost if wrong:* "on disk" is not "loads": a
  grammar present but failing to load (a corrupt `.so`) is recorded with its `grammars-now:`
  part, so the inventory stays fresh, and after `grammars fetch` replaces the file nothing
  marks it stale; `unvarnish run --phase inventory --force` measures again.

- **A tool whose source directory is missing fails inventory instead of being analysed as
  empty (UNVAR-31).** Inventory checks that the source root is a directory before it walks
  it; the failure skips every later phase, so the last good documents stay as they were.
  The runner applies the same check to every phase that reads the source (marked
  `reads_source`), so `--phase scan` alone cannot rewrite an artifact from an empty tree;
  render and the rollups read only saved artifacts and still run.
  `walk_files` and `hash_tree` still treat a missing root as empty, since a dry run's
  estimate and freshness checks must not raise. The same check covers copied tools, whose
  `tools/<name>/source` should never be missing. *Cost if wrong:* a tool that is genuinely
  meant to have no files (none exist) cannot be run until its folder is recreated, even
  empty.

- **Freshness hashes an artifact's content, not its write time; the census carries a
  content digest of the tree (UNVAR-34).** `hash_files`, which every downstream phase's inputs
  hash uses, hashes a JSON artifact as its `data`, `meta.schema_version` and
  `meta.inputs_hash` in canonical form, and any other file (a document, a non-artifact JSON,
  an unparsable file) as its bytes. It leaves out `meta.produced_at`, which changes on every
  write, so a rerun that writes the same artifact leaves the phases downstream fresh. The
  recorded inputs hash stays because a phase's data does not always show what it read: a split
  of a same-length edit cuts the same byte ranges, an extract state counts units without
  naming their content, and git's statistics can survive a history rewrite; each inputs hash
  is built from its own inputs' content, so it changes when they do and carries that change
  down the pipeline. An artifact a phase writes while still incomplete records an empty inputs
  hash and so counts by its data alone; the extract state's `units_digest` covers that case
  for extract (UNVAR-47). The inventory is the exception: its inputs hash holds file mtimes
  (a stat walk, so a fresh check stays cheap), so its artifacts (`produced_by` in
  `STAT_HASHED_PRODUCERS`) count by data alone, and a touch, a `git checkout` or a re-clone
  reruns the inventory and nothing else. In its place the census gains `content_digest`, a
  sha256 over every walked file's path and content, excluded files included, because the scan
  reads them (the secrets pass reads a gitignored `.env` and build output; gitleaks reads the
  whole tree). Hashing data alone everywhere was the first version and was rejected: a
  same-length edit left extract fresh and the edited unit's analysis stale. Per-artifact
  digests (a source digest in the units index, a unit digest in the extract state, the HEAD
  in the git statistics) were the precise alternative, at a schema field per summary artifact
  and a rule every future phase must remember. *Cost if wrong:* inventory now reads every file
  in full, binaries and excluded files included, to hash it (it already read every text file
  to count lines), which slows inventory on a tree with large binaries; any content edit, even
  to an excluded file, reruns every phase after the inventory as before this change, answered
  by the unit, module and response caches; a phase whose inputs hash ever folds in something
  volatile other than the inventory's mtimes would stale everything downstream on each rerun.
  A census without the digest (written by an earlier version) makes the inventory stale
  through `retry_pending`, so the first run after upgrading reruns the inventory and every
  phase after it once, together, instead of once for the new hash and again when the digest
  first appears; an engagement without `cache/responses` re-spends the tool rollup, verify and
  prose once.

- **The extract state records a digest of its done units' inputs hashes (UNVAR-47).** While a
  unit keeps failing, extract writes its state with an empty inputs hash so the next run
  retries, and freshness downstream then sees only the state's data: counts, backend, model,
  prompt version and usage. Switching the extract effort away and back, with the reverted
  units answered from the response cache at zero usage, left that data identical to the run
  before, so `rollup_modules` and every later phase stayed fresh on the other effort's
  extractions. `ExtractState.units_digest` is `hash_inputs` over `"<unit id>=<inputs hash>"`
  for each unit done this run (extracted or kept from its artifact), sorted by id; a unit's
  inputs hash already folds in its source, backend, model, effort, prompt version and scanner
  notes, so any change to what a done unit was extracted with changes the state. Recording the
  effort alone was the narrower fix, and was rejected: it covers this scenario but not the
  next field a unit's hash gains. A unit not done this run (failed, or left by a stop) enters
  as `"<unit id>~<recorded inputs hash>"` when it has an artifact on disk, because the rollups
  read that artifact too, and a run the rollups never followed (an interrupt, a budget stop,
  `--phase extract`) can have rewritten it. *Cost if wrong:* the digest covers what the
  units were extracted with, not anything the rollups read from elsewhere (they hash the units
  index themselves); a state written by an earlier version loads with an empty digest, and
  where extract is still incomplete the first run after upgrading rewrites the state and
  reruns the rollups once, answered from the module and response caches.

- **More version declarations feed the end-of-life check, with the same constraint reading
  (UNVAR-52).** Poetry's `[tool.poetry.dependencies] python`, the Pipfile's `[requires]`
  (`python_full_version` when given, else `python_version`), `setup.cfg`'s
  `[options] python_requires` and `.tool-versions` go through the same `lowest_version` as
  `requires-python`, so Poetry's `^3.7` and `>=3.6,<4` are ranges judged by their lowest
  version (3.7, 3.6) and the evidence says so. Bundler's pessimistic `~> 2.6.0` is read as
  `~=`, whose lower bound is the same. `setup.py` is matched by a regular expression for a
  literal `python_requires="…"` keyword and never executed or evaluated: running a client's
  `setup.py` would run its code. A pyproject with both `requires-python` and Poetry's
  `python` yields both, as two evidence lines. `.tool-versions` contributes each line's first
  version only, the one asdf and mise run by default. *Cost if wrong:* a dynamic
  `python_requires` or an end-of-life fallback interpreter in `.tool-versions` is not
  flagged (known-issues lists both).

- **`.nvmrc` `lts/<codename>` (and the asdf nodejs plugin's `.tool-versions`
  `lts-<codename>`) resolves through a fixed table of Node.js LTS codenames in the scanner,
  case-insensitively; `lts/*`, `lts/-1` and codenames not in the table are skipped without a
  note (UNVAR-52).** endoflife.date's Node.js releases carry no codename (every
  `codename` is null in API v1, and the label is only "18 (LTS)"), so the bundle cannot
  resolve one; the table (`argon` 4 through `lithium` 26) maps each codename to its major
  version, which then matches a cycle like any other version. A codename never changes once
  Node.js assigns it, so the table only grows. nvm installs the newest LTS line for `lts/*`,
  which is supported when installed, so a finding would be noise; a codename not in the table
  is the same "names no cycle" case as `node:lts`, which UNVAR-43 already skips silently.
  *Cost if wrong:* a new LTS codename (after Lithium, Node.js 28 onwards) is skipped silently until it is
  added to the table; a long-lived `lts/*` checkout pinned by a lockfile to an old line is
  not flagged.

- **Python 3.13 only (UNVAR-27).** CI, the image and `requires-python` move to 3.13 in one
  change, so the image never runs a Python that CI did not test; 3.12 is dropped rather than
  kept in a matrix, because the image is the release users run and a two-version matrix
  doubles CI time for a line no one ships. Dependabot ignores semver-minor bumps of the
  `python` image, so the next line (3.14) is again a deliberate change. *Cost if wrong:* users
  on Python 3.12 can no longer install Unvarnish from a checkout or wheel and must upgrade or
  use the Docker image.

## Product site (UNVAR-38)

- **The site lives in `site/` of this repository** (owner, BORG-70 question 1, option A), so
  the product's own autopilot keeps it in step with the code. Guardrails: every `site/` change
  is `ap-owner-merge`, no fork PR is merged, and the Vercel project builds only when `site/`
  changed and holds no secrets. *Cost if wrong:* someone with write access to the repo can
  change the public site; a separate repo would have isolated it.
- **The demo is a real scanner-only run on OWASP NodeGoat, published unedited** (owner, BORG-70
  question 2, option A: recorded walkthrough plus static output, no live model calls). A
  deliberately insecure training app gives a report full of findings without publishing
  anyone's production flaws. The walkthrough is the terminal transcript, not a video: it is
  accessible, searchable and diffable. *Cost if wrong:* the demo shows no model-written
  findings, architecture or requirements documents; adding them needs a run with an API key,
  and the demo page says so.
- **No GitHub link and no "is open source" claim until the repository is public.** The licence
  is decided (Apache-2.0 + DCO, BORG-69) but `LICENSE` is still the proprietary notice, so the
  site says it will be Apache-2.0 when the repository goes public, and `tests/test_site.py`
  fails on a repository link while `LICENSE` says proprietary. *Cost if wrong:* none; the
  launch thread edits two marked lines. (Changed by UNVAR-36: `LICENSE` is Apache-2.0 before
  launch, so the test no longer keys on it; see below.)
- **CSP is stricter than bonham.tech's: `script-src 'self'` without `'unsafe-inline'`.** The
  site has no JavaScript (the JSON-LD block is data, not script). *Cost if wrong:* a future
  inline script is blocked until it moves to a file.

## Public-release hardening (UNVAR-36)

- **Apache-2.0 with a DCO, not a CLA** (owner, BORG-69). `LICENSE` is the verbatim
  apache.org text, `NOTICE` names Bonham Technologies, LLC, and `pyproject.toml` uses the
  PEP 639 `license = "Apache-2.0"` expression with `license-files`, so the wheel and sdist
  carry both files. Contributors sign off each commit (`git commit -s`); `.github/dco.yml`
  sets `require: members: false`, so organisation members sign off too. The repository stays
  private until the launch ticket. *Cost if wrong:* relicensing later needs every
  contributor's consent; a DCO gives no copyright assignment, so a future licence change is
  harder than with a CLA.
- **Credential-shaped fixtures are built from fragments, not allow-listed.** The secrets
  scanner's tests need real-format tokens; each one is now joined at runtime (`"sk_" +
  "live_…"`, `"-----BEGIN RSA " + "PRIVATE KEY-----"`), so the tests see the same values while
  no file holds a whole token. Historic plan documents got the same treatment. No
  `.gitleaksignore` is added here; that waits on the owner. `tests/test_repo_hygiene.py` fails
  on a whole Stripe live key, GitLab PAT, Slack webhook, private-key header, AWS key ID (the
  documented `EXAMPLE` keys aside) or Anthropic key in any tracked file. Git history still
  holds the old literals; the launch ticket chooses how to publish history (a fresh history is
  recommended). *Cost if wrong:* a contributor who adds a whole-token fixture gets a failing
  test and has to fragment it; a token format the test's six patterns don't cover can still
  slip in, and GitHub would then flag it on push.
- **The site's "no repository link" guard no longer keys on `LICENSE`.**
  `test_no_github_link_until_the_repository_is_public` skipped itself once `LICENSE` stopped
  saying proprietary; with the licence changed before launch it would have lapsed while the
  repository is still private. It now always runs, and the launch thread deletes it when it
  adds the link. *Cost if wrong:* none; the launch thread deletes one test.
- **Workflows declare least privilege and pin actions by SHA.** CI gets `permissions:
  contents: read` at the top level; actions are pinned to full commit SHAs with the tag in a
  comment, and Dependabot's `github-actions` entry bumps them weekly. No workflow uses
  `pull_request_target` or `workflow_run`, and no secret is read by a `pull_request` job;
  `tests/test_repo_hygiene.py` checks the first three. *Cost if wrong:* a job that later needs
  a write scope fails until it asks for it in its own `permissions:` block.
- **History-only gitleaks fixtures are allow-listed by fingerprint (UNVAR-14; superseded by
  UNVAR-72 once the history was replaced).** After the
  fragmenting above, `gitleaks git .` still found 17 fixtures in old commits; the owner
  confirmed each fake on 2026-11-13 and `.gitleaksignore` lists them by commit, path, rule
  and line, so the list can't hide a new finding elsewhere. *Cost if wrong:* a rewrite of the
  history (the launch ticket's option 1) changes every commit id, so the fingerprints go
  stale and the 17 show again unless the rewrite also removes the fixture values; regenerate
  the file from a fresh `gitleaks git . --report-format json` after any rewrite.
- **Publish with fresh history, not a rewrite (owner, UNVAR-37, 2026-11-13).** The public
  repository starts from a single snapshot commit of `main`; this private repository, with its
  history, issues and pull requests, is kept as the archive. A rewrite would not have reached
  GitHub's `refs/pull/*` (every pull request keeps its old commits, fetchable once public) or the
  92 issue and pull request threads, which link the internal tracker. Before the snapshot no
  tracked file outside `.claude/` may link the internal Jira or Confluence site
  (`tests/test_repo_hygiene.py`); the vendored `.claude/` policy still names the site and is
  changed in bonham-ops, not here. In the new repository `.gitleaksignore` matches nothing,
  because its fingerprints name commits of the old history; remove it and its hygiene test
  after the cut-over. *Cost if wrong:* the public repository has no blame or history before the
  snapshot, and links to old pull requests in tickets and docs resolve only in the private
  archive.

## SARIF and CSV export (UNVAR-41)

- **One file per tool, both formats, in `exports/` as `findings-<tool>-<timestamp>.<ext>`**,
  next to the document exports and named like the findings document's. GitHub code scanning
  works per repository and the client's tools live in separate repositories, so each SARIF
  file is one run for one tool; GitHub's limit of 20 runs per file can't be reached. The CSV
  follows the same rule so a tool's findings go to that tool's team. *Cost if wrong:* a
  consultant who wants one engagement-wide CSV concatenates the files (same header).
- **A tool over 25,000 results is split, not refused or truncated:** `-part1`, `-part2`, ...
  files of at most 25,000 results, each its own run with its own `automationDetails.id`
  (`unvarnish/<tool>-partN/`), which GitHub takes as the category, so the uploads don't
  replace each other. Refusing would leave the consultant with nothing; truncating would drop
  findings from a vetting report. Each part carries only the rules its results use. *Cost if
  wrong:* the parts are separate categories in GitHub, so alerts can move between parts when
  the count changes and show as fixed in one and new in the other. GitHub's 10 MB
  compressed upload limit is not checked (`docs/known-issues.md`).
- **One rule per (source, category, title)**, as the ticket asks. The rule id is
  `<source>/<category>/<title slug>-<8 hex of sha256>`: readable in GitHub's rule list and
  unique when two titles slug the same. The rule's texts come from its most severe finding
  (findings arrive by severity): `shortDescription` the title, `fullDescription` the summary,
  `help` the remediation, `defaultConfiguration.level` its level. *Cost if wrong:* model
  findings with near-identical titles become separate rules, and a rule's description quotes
  one finding's summary.
- **Severity to level: critical and high `error`, medium `warning`, low and info `note`.**
  SARIF has no level between `error` and `warning`, and `note` is the level GitHub shows for
  advice. Security rules also carry `security-severity` (critical 9.5, high 8.0, medium 5.5,
  low 3.0, within GitHub's bands), so GitHub's Critical/High/Medium/Low match the documents;
  info gets none. Unvarnish's own severity is in each result's `properties`. *Cost if wrong:*
  a branch protection rule on "error" blocks on high findings as well as critical ones.
- **Rejected findings are left out with the documents' own filter**
  (`render.findings.merged_findings`), and every finding goes through
  `redact_model_text` before either file is built; the finding id is the unredacted
  finding's, so it matches `findings.json` and the documents. *Cost if wrong:* none known.
- **`all` and the default stay docx, html and pdf; `sarif` and `csv` are named explicitly**
  and don't touch the pandoc check, so a machine without pandoc can still export them. They
  follow the findings document: asking for either with a `--doc` list that leaves out
  `findings` exits 2 (UNVAR-58), and `--template` with only data formats is refused. *Cost if
  wrong:* a user expecting `all` to mean every format misses the data files; the help text
  says what `all` is.
- **A mixed request that can't be met in full is refused whole (UNVAR-58).** `--format sarif
  --format docx --doc architecture` exits 2 and writes nothing, rather than writing the docx
  and skipping the SARIF: like the template and format checks, the user's own mistake is
  reported before any work, and a script never gets exit 0 with a file missing. *Cost if
  wrong:* the user reruns once with `--doc findings` added or the data format dropped.
- **The SARIF test vendors the OASIS schema (`tests/sarif-schema-2.1.0.json`, errata 01) and
  validates with a small draft-04 checker in the test** over the keywords that schema uses,
  rather than adding `jsonschema` to the dev group. The copy is byte-identical to OASIS's and
  carries the OASIS notice its permission requires (`tests/sarif-schema-2.1.0.NOTICE.txt`). *Cost if wrong:* `format` (uri,
  date-time) is not checked; the export writes no dates and percent-encodes paths.
- **CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage return get a leading `'`**
  (OWASP's CSV-injection advice): the text comes from the vetted code and the model, and the
  file is likely to be opened in a spreadsheet before import. *Cost if wrong:* a Jira summary
  that starts with one of those characters shows the apostrophe.
- **CSV is UTF-8 without a byte-order mark, `\r\n` line ends, minimal quoting** (Python's
  default dialect, which quotes every multi-line cell). *Cost if wrong:* Excel on Windows may
  show non-ASCII characters wrongly when it opens the file directly; Jira's importer reads it
  as UTF-8.

## Client exposure scanner (UNVAR-39)

- **A client root is a directory name at any depth, minus server directories.** `src/`,
  `public/` and `dist/` match `apps/web/src/` too; a file under `api/`, `server/`,
  `backend/`, `functions/` or `lambda/`, or named `*.server.*`, is not browser-facing even
  inside one, and only `.js .ts .jsx .tsx .html .vue .svelte` files count. `dist/` is read
  although the inventory excludes it as build output: it is what ships. *Cost if wrong:* a
  service-role key in server code under `src/` (an Express app's `src/db.ts`) is reported as
  client exposure; it is still a hardcoded secret. A client tree under another name is missed
  until `client_roots` names it.
- **The anon key is not a finding on its own.** It is public by design. It becomes one
  critical finding when the migrations also leave a table without row level security or
  disable it. The Firebase web config is a low finding for the same reason: its `apiKey` is
  an identifier, and the finding asks for a rules review. *Cost if wrong:* an app whose RLS
  lives outside the repository's SQL (set in the dashboard) shows its tables as open; a
  Firebase app with open rules gets only a low finding.
- **Public-prefixed names are judged by name, with an allowlist.** A `NEXT_PUBLIC_` (and
  `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) name with a `SECRET`, `KEY` or `TOKEN` word is a
  high finding unless it contains a public-by-design marker from `public_names`:
  `ANON_KEY`, `PUBLISHABLE`, `PUBLIC_KEY`, `SITE_KEY`, `FIREBASE_API_KEY`, `MAPS_API_KEY`,
  `MAPBOX_TOKEN`, `POSTHOG_KEY`. Words are split on `_`, so `KEYBOARD` is not `KEY`. *Cost if
  wrong:* another public-by-design key (an analytics write key) is reported until it is
  added to `public_names`; a secret whose name happens to carry a marker is missed.
- **Only public-schema tables need row level security.** A table in another schema is not
  served by the Supabase API by default; `disable row level security` is reported in any
  schema. Comments are ignored, a dropped table is not open, and RLS enabled in any migration
  counts regardless of order. *Cost if wrong:* a schema the project exposes through the API
  is not checked; a table dropped and recreated without RLS is missed.
- **A table without RLS is open only in a Supabase-shaped tool.** The SQL must sit under a
  `supabase/` directory, or the tool must use RLS somewhere in its SQL (an `alter table …
  row level security` or a `create policy`), depend on a `supabase` package, or ship a
  Supabase key in client code. Otherwise a `schema.sql` of a Flask, Go or SQLite app would
  report every table as served to the anon key. *Cost if wrong:* a Supabase project with
  plain SQL outside `supabase/`, no RLS statement anywhere and no Supabase dependency in a
  manifest the inventory reads has its open tables missed.
- **An update policy without `with check` is reported only when it has no `using` either.**
  Postgres applies the `using` expression to the new row when `with check` is absent, so the
  common `for update using (auth.uid() = id)` is safe; an insert policy has only `with
  check` and is reported without one. *Cost if wrong:* none known; this is the documented
  Postgres behaviour.
- **Committed `.env` files and agent configs report one finding per file**, with a line of
  evidence per credential-like value (a key naming a key, secret, token, password,
  credential or authorization, holding a non-placeholder value that is not a bare URL).
  `.env.example`, `.env.sample`, `.env.template` and any name containing those words are
  skipped; gitignored files are not "committed" and are skipped too. *Cost if wrong:* an MCP
  config that the secrets scanner also matches shows the value twice, under two titles.
- **Unprotected routes are one grouped medium finding, and extraction confirms.** The
  heuristic looks for an authentication identifier (auth, session, jwt, bearer, current
  user, guard, permission, passport, clerk, API key) from the line before each handler up to
  `auth_window` lines after it, stopping at the next handler, and skips a file that
  installs auth middleware with `.use(...)` and routes named like health, login or webhook.
  A JavaScript file counts only when it looks like server code (`req, res`, `request,
  reply`, or an `express`, `fastify`, `koa` or `hono` import), because `api.get("/users")`
  is an axios call in browser code; generated files are not searched for routes or CORS,
  since a committed server bundle repeats its source.
  The listed lines reach extraction as a scanner note in the unit message; a unit's cache
  key includes its notes only when it has some, so `PROMPT_VERSION` did not change and units
  without notes keep their cache. *Cost if wrong:* the review finding lists handlers that a
  router-level guard protects, and misses one whose neighbour mentions a session.
- **Counts come from tags.** "Client-exposed credentials" sums each credential finding's
  `exposed:<n>` (one per service-role key or public variable name, one per value in an
  `.env` or agent config); "open tables" counts distinct tables without RLS, with RLS
  disabled, or with a non-select `using (true)` policy. Both read "not checked" for a tool
  scanned before the scanner existed. *Cost if wrong:* none beyond the row's wording.

## Re-audit delta (UNVAR-40)

- **The entry point is `unvarnish run --baseline <path>`, not a separate compare-runs command**
  (owner's ruling on UNVAR-40), so the delta renders in the same pass as the documents and
  exports carry it with no extra step. *Cost if wrong:* comparing two finished runs without
  running needs a run on the newer engagement (every phase is fresh, so only `render` runs).
- **The baseline is snapshotted into `tools/<name>/analysis/baseline.json` when the run
  starts**, not re-read from the path each run: a plain rerun or a resume after a budget stop
  keeps the section, the prior engagement can move or be archived, and a baseline taken from
  this engagement's own folder holds the results as they were before the run. A new
  `--baseline` replaces it (the same baseline passed again leaves the file untouched, so
  nothing re-renders); deleting the file stops the comparison. *Cost if wrong:* a
  baseline folder edited after the snapshot is not picked up until `--baseline` is passed
  again.
- **A `--baseline` that resolves to the tool's own folder, or to an artifact inside it, never
  replaces an existing, readable `analysis/baseline.json`** (UNVAR-48, refining the ruling
  above); a broken or old-schema one is still replaced, as render's failure advises. By
  the second run that folder holds the first run's results, so a replacement would compare
  the review with itself; rerunning the same command is the natural way to resume after a
  budget stop or Ctrl-C. The run keeps the snapshot and prints a line naming the file to
  delete to take a new one. Deleting the file is the explicit action rather than a new flag:
  it is already how the comparison is dropped, and it adds no option to `run`. A baseline in
  another folder still replaces the snapshot. *Cost if wrong:* a consultant who deliberately
  re-points the own-folder baseline at newer results must delete the file first; one whose
  stored snapshot came from another engagement keeps it when passing `--baseline .`.
- **The delta is computed in the `render` phase, not a phase of its own.** The baseline and
  `baseline.accepted` enter only `render`'s inputs hash (and the deltas only
  `render_comparison`'s), and only when a baseline exists, so a baseline change re-renders
  without rerunning any model phase and a run without one hashes as before. Render's prose
  calls are answered from the response cache because their facts do not change. *Cost if
  wrong:* `unvarnish status` shows no separate row for the delta.
- **Matching order: finding id, then title and path within a line drift, then secret
  fingerprint.** The id already hashes tool, category, title, path, line and fingerprint, so
  it catches the untouched; title and path catch a finding that moved or was re-rated (the
  nearest pair across all candidates wins, so the result does not depend on finding order);
  the fingerprint catches a secret that moved files. Two secrets with
  different fingerprints never match on title and path. "Changed" means moved or re-rated.
  *Cost if wrong:* a model finding reworded between runs shows as one resolved and one new.
- **Grouped scanner findings match by scanner and rule (UNVAR-49)**, after the id and before
  title and path. One finding stands for every oversized file or function, every hardcoded
  value of a kind, every TODO or swallowed error; its title follows the count ("Oversized
  file" or "files") and its id and path the first member, so partly fixing a group read as one
  resolved plus a new finding of the same severity. Scanners now tag such a finding
  `group:<rule>` and `count:<n>` (hardcoded_infra keeps `distinct:<n>`); findings written
  before the tags are recognised by a frozen table of scanner and title, and by
  `hardcoded:<kind>`, so existing baselines match with no schema bump. A matched group is
  "changed" when its count or severity changed, never because its first member moved, and
  `delta.json` entries gain optional `group`, `previous_count` and `count` fields (matched by
  `group`); the document shows "count 2 → 1". The matching carries a version
  (`MATCH_VERSION` in `analysis/delta.py`) in the render phase's inputs hash when there is a
  baseline, so a change to it re-renders a resumed run's delta. *Cost if wrong:* a group whose members were
  swapped one for one reads as persistent, and a scanner that adds a grouped finding without
  the tag falls back to title and path matching.
- **Line drift defaults to 50 lines** (`baseline.line_drift`): it covers an import block or a
  new function above the finding while keeping two same-titled findings in one file apart.
  *Cost if wrong:* a finding pushed further down shows as resolved plus new; raise the setting.
- **Only sources both reviews hold completely are compared.** A scanner-only baseline against
  a model-analysed run (or a budget-stopped model run on either side) compares scanner
  findings only and says so in the section, rather than listing every model finding as new or
  resolved. *Cost if wrong:* model findings go uncompared until both reviews have them.
- **A baseline whose findings artifact has another schema version is refused (exit 2) before
  anything runs.** `FINDINGS_SCHEMA_VERSION` (now 1) names the findings schema whose ids this
  version can match; bump it when the id formula or the Finding model changes. Older baselines
  get "re-run the previous review with this version"; newer ones "upgrade Unvarnish". *Cost if
  wrong:* a consultant with an old engagement must re-run it before comparing.
- **`baseline.accepted` findings render as "Risk accepted", never as resolved**, whether still
  present or gone: an accepted risk was not fixed, and a finding the run no longer sees cannot
  be claimed as fixed. *Cost if wrong:* a genuinely fixed accepted finding is undercounted as
  resolved until it is removed from the list.
- **The executive summary prose does not mention the delta.** Adding it to the prose facts
  would cost a model call on every baseline change. *Cost if wrong:* the summary reads as a
  first review; the section above it carries the comparison.

## End-of-life scanner (UNVAR-43)

- **The data is one dated JSON file, `endoflife.json`, in our own format (`format: 1`)**, not
  endoflife.date's responses as fetched: `fetched`, `source`, `attribution` and `products`
  keyed by endoflife.date slug, each with a `label` and `cycles` (`cycle`, `codename`,
  `eol_from`, `is_eol`, `is_maintained`, `latest`). It keeps only what the scanner reads, so a
  site kit carries 76 KB, and an API change is absorbed by `eol refresh`, not by every reader.
  A bundle of another format is reported as unreadable, never guessed at. *Cost if wrong:* a
  field we did not keep (LTS, extended support) needs a format 2 and a refresh.
- **The data directory follows the OSV database's pattern:** an environment variable
  (`UNVARNISH_EOL_DIR`) that an image or site kit sets, else `$XDG_DATA_HOME/unvarnish/eol`,
  else `~/.local/share/unvarnish/eol`, where `eol refresh` writes by default. It is not under
  `UNVARNISH_CONFIG_DIR`, which the image points at the mounted engagement. *Cost if wrong:*
  a consultant with two bundles must set the variable to choose one.
- **"Java" is Eclipse Temurin and "alpine" is `alpine-linux`.** endoflife.date has no `java`
  product; Temurin is the OpenJDK build the deprecated `openjdk` Docker image points to, and
  both images map to it. `spring-boot` rather than `spring-framework`, because the
  inventory recognises Spring Boot starters. *Cost if wrong:* a tool on Oracle JDK or
  Corretto is judged by Temurin's dates, which can differ by months.
- **The scan's date decides, not the fetch date.** A cycle is past end of life when its
  `eolFrom` is on or before the date the scan ran (the scanner takes an injectable `today`),
  so an old bundle still flags a cycle that has since ended; `isEol` is used only when no
  date is published. The date is not in the scan's inputs hash, so a cached scan keeps the
  verdicts of the day it ran until something else makes it rerun. The report shows the data
  date so a reader can judge how current the list of cycles is. *Cost if wrong:* a date
  endoflife.date later moves (an extended support window) is wrong until the next refresh.
- **High when past, medium within six months (`warn_months`).** Six months is one planning
  cycle for an internal tool's upgrade. *Cost if wrong:* a team that plans quarterly sees the
  warning too early; set `warn_months: 3`.
- **A range is judged by its lowest allowed version, and the evidence says so.** `>=3.9`
  admits 3.9, so the tool can be installed and run on an unsupported release, and the
  manifest is what the consultant can change. The go directive is a minimum too; a
  `toolchain` line, when present, wins over it. *Cost if wrong:* a project that pins 3.9 as a
  floor but deploys on 3.12 gets a high finding to explain; the evidence note names the range.
- **One finding per release and status, with every place it is declared as evidence**, so
  three Dockerfiles on `python:3.9` are one finding with three lines, and its id is stable
  while the first location stays. Dependency versions come from the inventory's records, so
  they carry the manifest path and no line. Files classified as tests are not read. *Cost if
  wrong:* fixing one of three places leaves the finding open, as it should.
- **Registry hosts are dropped from the evidence**: a `FROM registry.acme.internal/python:3.9`
  is shown as `FROM python:3.9`, as the hardcoded-infrastructure scanner would redact it.
  *Cost if wrong:* the reader must open the Dockerfile to see which registry.
- **The bundle date enters the inventory's inputs hash, and only when there is a bundle**, so
  a refresh reruns inventory and scan while an engagement without one keeps its hash; the
  date is also stored in `dependencies.json` (`eol_data_date`) for the report's row. *Cost if
  wrong:* a refresh reruns every later phase too (artifacts carry their write time); model
  calls come from the response cache.
- **A missing or unreadable bundle is one scanner note, never a failure**, and the note names
  no local path, since the findings document goes to the client. *Cost if wrong:* the
  consultant has to look up where the bundle was expected (`docs/operations.md`).

## Remediation effort (UNVAR-42)

- **Four bands, S, M, L and XL, each with a ceiling: S up to half a day, M up to two days, L
  up to a week, XL weeks.** Every prompt and both documents use the same scale
  (`model/prompts/effort.py`). The bands are an input to the consultant's judgment, not a
  quote, and the documents say so. *Cost if wrong:* a client reads a band as a commitment;
  the consultant restates it.
- **Scanner bands are fixed per rule, whatever the finding's size** (`scanners/effort.py`,
  `EFFORT_RULES`). A grouped finding ("Oversized files", 12 files) has the band of one fix of
  that kind; the count is in the finding. The table:

  | Scanner | Rule | Band |
  |---|---|---|
  | secrets (and gitleaks) | `credential` (working tree) | S |
  | secrets (and gitleaks) | `credential_history` | M |
  | secrets | `suppression` | S |
  | oversized_files | `inline_script` | M |
  | oversized_files | `file` | L |
  | oversized_files | `function` | M |
  | oversized_files | `very_large_function` (over 5× the threshold) | L |
  | hygiene | `no_tests` | XL |
  | hygiene | `no_ci`, `todo_density`, `swallowed_errors` | M |
  | hygiene | `no_readme`, `no_license`, `no_linter` | S |
  | bus_factor | `single_author` | L |
  | bus_factor | `low_bus_factor` | M |
  | dependencies | `advisories`, `unpinned` | S |
  | dependencies | `licences` (UNVAR-93) | M |
  | hardcoded_infra | `url`, `host`, `ip`, `path` | M |
  | hardcoded_infra | `email` | S |
  | vendored_bulk | `vendored_directories` | M |
  | vendored_bulk | `binaries` | S |
  | generated_bulk | `bulk_commits` | L |
  | client_exposure | `firebase_config`, `credentials_file`, `policy_without_check`, `cors_any_origin` | S |
  | client_exposure | `policy_readable`, `policy_open`, `service_role_key`, `public_secret_var`, `table_without_rls`, `rls_disabled` | M |
  | client_exposure | `anon_key_open_tables`, `unauthenticated_routes` | L |
  | end_of_life | `past`, `near` (UNVAR-43) | L |

  A secret only in history is M, not S: rotating it is quick, but the remediation also
  rewrites history, which every clone must take. A dependency advisory is S: one upgrade,
  more across a major version (the note says so). *Cost if wrong:* a band misstates one
  rule's cost in every engagement; `scanners.<name>.effort.<rule>` in engagement.yaml
  replaces it, and the scan reruns (scanner options are in its inputs hash). An unknown rule
  or a value that is not a band fails the configuration at load, not the scanner. The table
  itself is in the scan's inputs hash too, so a scan written before the bands existed, or with
  other bands, reruns once (deterministic, no model calls) instead of leaving its findings
  "not estimated".
- **The band lives on the finding, as two optional fields** (`effort`, `effort_note`), not in a
  side table, so `findings.json` and `scanner-findings.json` carry it to any later tool (`ask`'s
  finding view and the SARIF and CSV exports do not show it yet; see known-issues). The
  baseline snapshot redacts `effort_note` like every other free-text field. The finding id does not include them, so ids, the baseline match
  and `FINDINGS_SCHEMA_VERSION` (still 1) are unchanged. *Cost if wrong:* none known; an
  artifact without the fields loads with "not estimated".
- **A model band is nullable.** The structured-output schemas require the field (strict mode)
  but allow null, so a model that cannot tell says so instead of guessing; "m" and "None" are
  read as M and no band, anything else fails validation like any other schema error. *Cost if
  wrong:* a weak model leaves most findings "not estimated".
- **The verifier may change a band only on the findings it checks** (high and critical with
  cited lines); a rejected finding keeps the claimed band, and an adjusted one says so in its
  note. *Cost if wrong:* a medium finding's band is never checked.
- **Totals are counted from the findings, never written by a model.** The outlook table, the
  comparison's cost row and the consolidation prompt's "Cost to fix" section all come from
  `analysis/effort.py`; no structured-output schema has a total or a day field (a test
  checks). *Cost if wrong:* none.
- **Bands always show; engineer-days are opt-in** (`report.effort_days`). A day figure reads
  as a quote, and the right figures depend on the client's team, so Unvarnish prints none
  until the consultant sets them. Each figure is a band's ceiling, and the range runs from the
  band below's figure to the band's own (S from 0): with `{S: 0.5, M: 2, L: 5, XL: 15}`, two S
  and one XL give 5–16 engineer-days. Findings not estimated are left out and counted. The
  mapping joins the `render`, `compare` and `render_comparison` inputs hashes only when set,
  so an engagement without it hashes as before. *Cost if wrong:* a consultant who wants a
  point estimate takes the midpoint by hand.
- **Prompt bumps: extract, module rollup, tool rollup, verify and compare** (each to
  `2026-11-10.1`), because their output schemas or prompt text changed. Ask and prose are not
  bumped: their prompts are unchanged, and the response cache is keyed by the request, so
  compare's normalisation and integration calls (unchanged requests) are still answered from
  the cache. `tests/test_remediation_effort.py` fingerprints every prompt and fails when one
  changes without a bump or is bumped without a change. *Cost if wrong:* the first run after
  upgrading repeats every extraction and rollup call (a full model rerun's cost).
- **The executive summary prose is not given the outlook.** Adding it would change every
  findings prose request. *Cost if wrong:* the summary does not mention cost; the table
  follows it.

## End-of-life data in the image and site kit (UNVAR-44)

- **The image fetches the bundle by default (`ARG EOL_DATA=fetch`) and the build fails when
  the fetch fails; `EOL_DATA=skip` is the documented way to build without it.** A plain
  `docker build` then gives a `--network none` run its end-of-life checks, as the image
  already does for tree-sitter grammars, rather than leaving them opt-in like the OSV
  databases (which are hundreds of MB; the bundle is under 100 KB). A failed fetch never
  falls back to "skip" on its own: an image that silently lacks the data would report "not
  checked" at a site with no way to fix it. Any value other than `fetch` or `skip` fails the
  build, so a typo is not a silent skip. No partial bundle can ship: `eol refresh` builds
  every product in memory and writes the file atomically only when all succeed, and a
  failed RUN step leaves no image. *Cost if wrong:* a build on a network that blocks
  endoflife.date fails until the builder passes `EOL_DATA=skip`.
- **The bundle lives in `/opt/eol` with `ENV UNVARNISH_EOL_DIR=/opt/eol`**, beside `/opt/osv`
  and `/opt/tree-sitter`, readable by any `--user`. The step runs after the project is
  installed, because it is `unvarnish eol refresh` itself, so the image's data is exactly
  the format and product list that version of Unvarnish reads. *Cost if wrong:* the step
  reruns on every source change (the layer after `COPY src`), which costs 19 small
  downloads per build.
- **No separate `DATE` file**, unlike `/opt/osv/DATE`: the bundle records its own
  `fetched` date, which is what the report shows. The site-kit image check reads the bundle
  through `unvarnish.analysis.eol.bundle_date()` under `--network none`, so it proves the
  scanner can read it, and prints that date. *Cost if wrong:* a reader looking for the date
  must open `endoflife.json` rather than `cat` a file.
- **The site kit carries the bundle inside the image only, not as a second file**, so the
  data the run uses and the data the kit lists cannot differ. At a site, newer data is
  mounted over `/opt/eol`, written by the image's own `eol refresh` on a connected machine.
  *Cost if wrong:* the date is visible only in the build log and the reports, not from the
  kit's file list.

## Old end-of-life data is flagged (UNVAR-59)

- **A bundle more than 90 days old (`scanners.end_of_life.max_data_age_days`) adds a note
  under "Not analysed" and a warning on the end-of-life row; the findings are unchanged.**
  The age is the scan's date (the scanner's injectable `today`) minus the bundle's
  `fetched` date; exactly 90 days is not "older". Ninety days is about one quarter:
  endoflife.date's 19 products publish a new cycle or move a date every few weeks, so by
  then a newer Node.js, Python or .NET release is likely missing and skipped, while a
  shorter limit would flag nearly every site-kit run (the runbook asks for "a few weeks"
  but a kit is often carried for an engagement of a month or more). The data is still used
  because past-end-of-life verdicts come from published dates and remain right on old
  data; withholding them would hide real findings. The setting is a scanner option in
  `DEFAULT_SCANNER_OPTIONS`, like `warn_months`, so no schema changes, old engagement files
  load as before, a bad value falls back to 90, and changing it reruns the scan through
  the options in its inputs hash. Adding the default changes every engagement's scan hash
  once, so the first run after upgrading reruns the scan, render and the engagement's
  comparison (the per-tool model phases stay fresh: extract reads only the findings, and
  the comparison's prompts do not include the scan's notes, so its model calls are
  answered from the response cache). Leaving the default out of the hash would avoid that
  rerun, but then an engagement already scanned with old data would not show the note
  after upgrading, which is the case this change is for. The
  summary row reads the warning back from the scan's note rather than recomputing it, so
  the row and the note always agree. *Cost if wrong:* too short, and consultants learn to
  ignore a warning on every report; too long, and a report presents months-old data as
  current with only its date as a hint. Either is one setting in the engagement file.

## Export author in HTML and PDF (UNVAR-60)

- **HTML and PDF get the author as pandoc `author` metadata; Word keeps its post-pandoc
  rewrite.** The value is the one Word gets (`consultant`, else "Unvarnish"). pandoc's html5
  template prints `author` as a visible byline only inside the title block, which it emits
  only when `title` is set; the exporter sets `pagetitle` and never `title`, so `author`
  becomes `<meta name="author">` alone, and weasyprint turns that into the PDF's `/Author`.
  `author` metadata rather than an `author-meta` variable because pandoc escapes metadata
  for the attribute (`"`, `&`, `<`), while a variable is inserted raw. Tests check the meta
  tag, the PDF's `/Author`, and that neither the HTML nor the PDF's source HTML has the
  author in its body. *Cost if wrong:* a later pandoc template that prints authors outside
  the title block would add a visible byline; `test_html_export_carries_author_meta_without_a_byline`
  fails on it. A consultant named `true` or `false` (also `True`, `TRUE`, `False`, `FALSE`)
  is read by pandoc as a YAML boolean and the author is left out; every other string,
  including `null`, `~`, `1.0`, `[a]` and values with colons, reaches the meta tag verbatim
  (known-issues.md).

## Native Windows (UNVAR-35)

- **Docker only on Windows; the CLI refuses native Windows with a clear message.** The owner
  chose this over native support (`msvcrt` locking plus a Windows CI job). The check sits in
  `unvarnish/__init__.py`, before any other import, so it fires for every entry point and
  before rich or typer load their Windows console code. *Cost if wrong:* a consultant whose
  client laptop can't run Docker can't run Unvarnish at all; native support (option 2 on the
  ticket) is the follow-up if that happens.

## Configuration errors (UNVAR-50)

- **An invalid `tool.yaml` stops the command; a missing one does not.** A missing
  `tool.yaml` (UNVAR-17) means the tool was dropped, so `run` carries on with the others. One
  that is present but unreadable is a mistake to fix, and `status`, `run`, `export` and `ask`
  refuse with the file, key and exit 2 before any work. *Cost if wrong:* one tool's broken
  `tool.yaml` holds up a run of the others until the one line the error names is fixed.
- **A bad value is blamed on `engagement.yaml` unless only the user config sets that key.**
  The two files are merged before validation, so the error names the user config only when
  `engagement.yaml` does not set the key itself. *Cost if wrong:* none in practice;
  `engagement.yaml` always wins over the user config for keys it sets.
- **Every configuration error and unknown-setting line is redacted; a shown value is also
  shortened.** The value is what makes `got 'zero'` obvious, but a key pasted into the wrong
  place can turn up in the value, the dotted key (a key used as a backend name) or a
  validator's message (an effort band or rule name), so each whole line, and each
  unknown-setting warning, goes through the secrets scanner's redaction. A shown value is
  redacted before it is cut to 60 characters, since a key cut short is no longer recognised.
  *Cost if wrong:* a secret no scanner rule recognises is still printed (a value at most its
  first 57 characters) on the consultant's own terminal.
- **Built-in scanner option types are checked by `config check`, not on load.** Scanner
  options stay free-form (a plugin scanner reads its own), and refusing them on load would
  stop every command, `status` included, for a value only one scanner reads. Types come from
  `DEFAULT_SCANNER_OPTIONS`: a whole number where the default is one, any number where it is
  a float, true or false, a string, or a list of strings. *Cost if wrong:* someone who skips
  `config check` still sees the bad option only as a recorded scanner failure in `run`.

## One walk per syntax tree (UNVAR-54)

- **Node kinds are matched by `kind_id`, with every id whose name is a wanted type.** Reading
  `node.type` builds a string per node; the integer id does not, and the walk visits millions
  of nodes on a large tool. The id sets are built from the grammar's own kind names
  (`node_kind_for_id`), so aliased kinds that share a name match exactly as `type` did, and
  `ERROR` nodes (an id outside the kind table) match nothing, as before. *Cost if wrong:* a
  binding where `kind_id` and `type` disagree would miscount; the equivalence test across 18
  languages would catch it on the next tree-sitter bump.
- **The three helpers (`function_spans`, `max_nesting`, `comment_lines`) are gone, replaced
  by `tree_metrics`.** Only the metrics module called them. The old code is kept in
  `tests/test_metrics.py` as the reference the single walk is checked against. *Cost if
  wrong:* none outside the package.
- **The split still parses every file again.** Handing trees from the inventory to the split
  would mean keeping them in memory across phases or a resumed run, for parsing that is now
  about half of the inventory's remaining time; it is not worth the coupling yet. *Cost if
  wrong:* the split phase pays one more parse per file (about 3.7 s per 144,000 dense lines).

## Login guards (UNVAR-67)

- **`AUTH_RE` gains `logged_?in` and `require_?login`, not `login`.** `auth` already matches
  `isAuthenticated`, `login_required` was listed, and `ensureLoggedIn` is caught by `logged_?in`.
  A bare `login` would also match route paths and handler names like `loginHistory`, hiding
  real findings. `SCANNER_TEXT_VERSION` is bumped (2026-11-16.1) though no wording changed:
  without it an earlier scan keeps its false positives. *Cost if wrong:* a handler that only
  mentions `loggedIn` in a comment within the window is treated as guarded (a false negative).

## Plural words (UNVAR-57)

- **Scanner text has a version in the scan's inputs hash** (`SCANNER_TEXT_VERSION` in
  `phases/scan.py`), bumped whenever scanner summaries or notes are reworded, as the effort
  band table is (UNVAR-42). The scan does not hash scanner code, so without it an engagement
  scanned before an upgrade keeps the old wording in every document until something else
  changes. *Cost if wrong:* every existing engagement rescans once after the upgrade (gitleaks
  and osv-scanner included; no model calls) and `compare` reruns, answered by the response
  cache; a reworded scanner whose author forgets the bump keeps old text until the next rescan.
- **Pluralisation is a small English helper, not a library** (`util/plural.py`): regular `-s`,
  `-es` after a sibilant, `-ies` after a consonant `-y`, and an explicit plural for anything
  else. *Cost if wrong:* an irregular noun passed without its plural reads wrongly; the
  documents are English-only.

## gitleaks working directory (UNVAR-66)

- **gitleaks runs in an empty temp folder of its own**, not in the folder Unvarnish was started
  from. gitleaks 8.30.1 reads `.gitleaksignore` from the scanned directory and from
  `--gitleaks-ignore-path`, which defaults to `.`; an ignore file in the consultant's working
  directory suppressed client findings (tree and history) with no trace. Verified with real
  8.30.1: setting the working directory, or pointing `--gitleaks-ignore-path` at an empty
  folder, both stop the working-directory file and both keep the scanned tree's own file in
  force (the flag adds a lookup, it does not replace the scan-root one). The working directory
  was chosen because it also covers any other `.`-relative default gitleaks has or adds, and
  needs no flag. The scan root is resolved first so a relative root still works. *Cost if
  wrong:* a gitleaks release that reads ignore files from somewhere else (the home directory, an
  environment variable) would bring the gap back; the real-gitleaks test catches only the
  working-directory case.
- **No scanner text version bump.** The fix changes no wording, and a scan is affected only if
  it ran from a folder whose `.gitleaksignore` listed that client's fingerprints (commit, path,
  rule, line). Upgrades from 0.1.0 already rescan once for UNVAR-57. *Cost if wrong:* a scan
  made on unreleased `main` from such a folder keeps the hidden finding until its next rescan.

## CI time limit (UNVAR-65)

- **The `test` job's limit is 45 minutes**, about seven times a normal run and above the
  32 minutes a slow apt mirror once took. *Cost if wrong:* a legitimately slow run is
  cancelled and fails `ci-status`, and needs a rerun.

## CI builds and runs the image (UNVAR-80)

- **The `docker` job lives in `ci.yml` and decides for itself whether to build.** `ci-status`
  can only wait for jobs in its own workflow, so a separate workflow with a `paths:` filter
  could not gate the merge. On a pull request the job diffs its merge commit against the
  first parent (renames listed as a delete and an add) and builds only when `Dockerfile`,
  `.dockerignore`, `docker/`, `pyproject.toml`, `uv.lock`, `README.md`, `LICENSE`, `NOTICE`,
  `ci.yml` or its fixture changed; otherwise its steps skip and
  the job passes. Every push to `main` builds. The built image then runs `--version`, `init`,
  `add --files`, a no-model `run` and `export --format html` on `tests/data/docker-smoke/`
  with `--network none` and the caller's uid, as the site kit runs it, and checks that the
  bundled gitleaks and osv-scanner start and that the scan noted no missing tool or
  end-of-life bundle (a broken scanner is a note, not a failed run). *Cost if wrong:* a
  change outside those paths that breaks only the image (a source file the image needs at
  build time, say) is caught on `main` after the merge, not on its pull request.

## No gitleaks ignore file (UNVAR-72)

- **`.gitleaksignore` is gone.** Its 17 fingerprints named commits of the private archive, so
  in the public repository they suppressed nothing, and `gitleaks git` and `gitleaks dir` find
  nothing on `main` without it (gitleaks 8.30.1, 2026-11-20). This closes the step the
  fresh-history ruling (UNVAR-37) left for after the cut-over. The file may come back for a
  fingerprint in this history, as the security sweep's allow-list and revoked-leak steps add
  one; `tests/test_repo_hygiene.py` fails only if it names an archive-only commit again.
  *Cost if wrong:* none beyond re-adding an entry; whole-token fixtures are still built from
  fragments (UNVAR-36).

## Model text is inline Markdown only (UNVAR-76)

- **Model-written fields in paragraph slots go through `inert_block`; prose blocks go through
  `cap_headings`.** The vetted code is untrusted and can steer the model, and the templates
  render with `autoescape=False`, so model text could otherwise change a document's
  structure. `inert_block` keeps each line of a finding's text, and each model-written list
  item, inside its paragraph: a line Markdown would read as the start of a block gets a
  backslash before its marker, and indentation is dropped; inline emphasis, code spans and
  links still render. Prose blocks keep lists and `###` and deeper headings, but a `#` or `##`
  heading or an HTML block opener is made literal wherever it sits, because every prose block
  sits under a `##` section. Scanner findings pass through the same filter, which leaves their
  single-line text unchanged. *Cost if wrong:* a list in a finding's remediation shows as one
  paragraph with its markers visible.

## A backend outage is recorded as one (UNVAR-78)

- **`ExtractState.backend_unreachable` is a new field, separate from `stopped_for_budget`.**
  A `BackendUnavailable` (connection refused, bad key, server errors after retries) sets it,
  and the phase stays stale, so a rerun resumes as after a budget stop. Older states read it
  as false. When a fatal backend error stops a tool, `PhaseRunner` attaches the results so far
  to the exception and `run` records them, so `status` shows the failed phase. The error names
  the base URL with any user info and query removed (`display_url`). *Cost if wrong:* a state
  written by this version and read by an older one ignores the new field and shows neither
  reason; an outage in a later phase still shows only through "last run".

## Attribute access is not a hostname (UNVAR-75)

- **In code, a dotted name ending in an internal TLD is a hostname only inside a string or a
  comment, or where it is not used as an expression.** A small per-file lexer
  (`code_masks` in `scanners/hardcoded_infra.py`) marks strings (escapes; triple quotes in
  Python, Java, Kotlin, Scala, Swift, C#, Dart and Groovy, and JavaScript/Go backticks, across
  lines) and comments (Python `#`, `//`, `/* */`) for the languages in `CODE_LANGS`. A match
  wholly in code and followed by a colon, a closing bracket, a separator, an operator (`<`,
  `>`, `/` and `-` only after whitespace, so JSX text is not code) or the end of the line is
  attribute access and is dropped. Shell, Make, Dockerfiles, HTML, Vue and Svelte templates,
  and the config languages are not lexed, because a bare hostname in them can be real. Nor
  are Ruby, Perl, PHP, Lua, R and Elixir, whose heredocs, word lists, multi-line strings and
  PHP's HTML mode this lexer would read as code. A file with no internal-TLD candidate is not
  lexed at all. *Cost if wrong:* a real hostname written bare in code is missed; in most
  lexed languages that is a syntax error, but JSX text with a host followed by `,`, `:` or the
  end of the line is not. A string the lexer misreads (Rust `r#"…"#`, C# `@"…\"`, nested block
  comments) can hide a host on that line.

## Temperature on the Anthropic backend (UNVAR-69)

- **`CompletionRequest.temperature` is honoured by the OpenAI-compatible backend only.** The
  anthropic SDK (2.7.0 and 2.8.0) has no `temperature` argument on `messages.create`, so the
  Anthropic backend drops the field with a debug log line instead of raising `TypeError`
  before the call. The field stays on the request because on-prem model servers use it.
  *Cost if wrong:* a later change that relies on a temperature for Anthropic models gets the
  model's default, visible only at debug level.

## Fork pull requests and the self-hosted runner (UNVAR-70)

- **`vars.RUNS_ON` applies only to a pull request whose head is a branch of this repo.** A
  fork's pull request, a push to `main` and any other event run `ci-status` on the hosted
  `ubuntu-24.04`. Once the repo is public anyone can open a pull request, and a self-hosted
  runner would run their code on the owner's machine. The guard is in the expression, not in
  the variable, so it holds whatever `RUNS_ON` is set to. It covers only this workflow as
  written: a fork's pull request runs the workflow from its own branch and can name a
  self-hosted label directly, so the runner must also be closed to the public repo
  (`docs/operations.md`, CI runners). *Cost if wrong:* a push to `main`
  no longer uses the self-hosted runner for the one-second `ci-status` gate; the `test` job
  was already hosted.
- **Checkout keeps no credentials** (`persist-credentials: false`). No step after checkout
  fetches or pushes, so the token in `.git/config` only widened what a compromised dependency
  or test could reach. *Cost if wrong:* a future step that needs to push must pass a token
  explicitly.
- `tests/test_repo_hygiene.py` checks both for every workflow, so a new job or workflow
  inherits the rule.

## HTML landmarks and row headers (UNVAR-64)

- **Only HTML gets the structure filter (`export/assets/html-a11y.lua`).** It wraps the report
  in `<main>`, gives column headers `scope="col"` and turns summary tables' first column into
  `<th scope="row">`. pandoc.py adds it for `--format html` alone, after `inert-html.lua`;
  the PDF (HTML through weasyprint, untagged) and Word commands are exactly as before, so
  their output cannot change. *Cost if wrong:* a future tagged-PDF export (weasyprint's PDF/UA
  variant) would need the filter added to the PDF command too.
- **A summary table is one whose first column header is `Severity`, `Measure` or `Layer`.**
  Those are the severity count tables in findings.md, the Measure | Value and Layer | Value
  tables, and the comparison's per-tool Measure table, where the first cell labels the row.
  Lists (Finding, File, System, Store, Entry point, Kind) keep data cells: their first column is an item, the placeholder rows ("—")
  would become headers, and a general rule such as "every first column" would mark those
  too. *Cost if wrong:* a renamed header silently loses its row headers (a test pins the
  severity table in a rendered findings document), and other label tables, such as the
  comparison's Capability table, stay without them until added to the set.
- **`report.css` styles `tbody th` like `td`** (same rule, no wash, normal weight, body colour),
  so the HTML looks as it did: headless Chrome and weasyprint screenshots of a findings page
  before and after were pixel-identical. *Cost if wrong:* a custom `report.branding.html_css`
  written before 0.1.1 shows row headers with its header styling until it copies the rule.

## On-prem simulation through OpenRouter

- **OpenRouter stands in for an on-prem GPU server** (there is no GPU on hand): an
  OpenAI-compatible backend, an open-weights coder model, `context_window: 32768`, and
  `provider.require_parameters` so only providers that enforce the schema are used. It tests
  correctness and model quality, not speed. *Cost if wrong:* a behaviour specific to vLLM or
  Ollama (batching, a server's own truncation) is not exercised; the Ollama run covers the
  latter.
- **JSON repair is limited to unquoted keys and trailing commas.** Those were every local
  parse failure seen; anything else still goes to the retry and repair calls. *Cost if wrong:*
  another slip costs a retry call, as before.
- **A non-verbatim excerpt becomes the evidence note, not an error.** Sonnet's elided or
  descriptive excerpts carry useful pointers; matching ignores whitespace and accepts `...`
  elisions. *Cost if wrong:* an excerpt that differs from the file only trivially (a quote
  style) is shown as a note in parentheses instead of as code.
- **Placeholder credentials are rejected deterministically, and only when certain:** the claim
  names a credential and says it is in the source (hardcoded, embedded, committed, in config),
  and every value in the excerpt (or, without one, at most five cited lines) is a template
  marker: `REPLACE_ME`, `your_…`, `<…>`, `${…}`, `{{…}}`, `xxxxxxxx`. This is narrower than the
  secrets scanner's placeholder rule: `password`, `secret`, `changeme`, `admin`, and an empty
  string are weak real credentials when a model reports them, so they still go to the
  verifier. Values are string literals that are not object keys
  (escapes honoured, backticks included, an apostrophe inside a word never opens one) plus
  unquoted values of credential-like keys (`.env`, YAML). A line with any other value, a stray
  quote (a truncated excerpt), or a redaction marker goes to the model as before. A claim
  about handling ("password kept in localStorage") is never judged by its literals. *Cost if
  wrong:* a production credential literally set to a template marker (`REPLACE_ME`) is
  rejected; such a value is not a working secret.
- **Severity inflation by a small model is its judgement.** qwen3 rated 38 of 112 findings high
  or critical on headless-artist where Sonnet rated one; its own verification rejected 23 and
  downgraded 5. Verification on a stronger model (`models.phases.verify`) is the remedy where
  one is available.
- **unvarnish.com follows the parent design system and carries one product identity
  (UNVAR-74, owner's choice).** The site uses Bonham Technologies' tokens, type and shapes;
  Unvarnish's own part is no accent colour (`--product-accent` is the ink) and the
  stripped-layers motif. The site stays free of JavaScript, so Night follows the system
  setting with no toggle, and fonts are self-hosted with `font-src 'self'`. *Cost if wrong:*
  a reader who wants the other theme changes a system setting; and the site is plainer than
  its siblings by design, which a later identity pass can revisit by changing one token and
  one drawing.

## The site moves to unvarnish.tech (UNVAR-96)

- **unvarnish.tech is the primary address; unvarnish.com redirects to it (owner's choice,
  2026-11-22).** The .tech No Excuses Fund asks that an applicant's site live on its .tech
  domain and that the project's own links point there, and that the domain stay on .tech for
  24 months if awarded. Vercel serves `unvarnish.tech`; `www.unvarnish.tech`, `unvarnish.com`
  and `www.unvarnish.com` answer with a 308 to it, so old links and search results keep
  working. *Cost if wrong:* search engines re-index the site under the new host, and the
  .com keeps renewing as a redirect.

## `config check` without a model (UNVAR-83)

- **No model anywhere prints one sentence and no table; a partly configured engagement keeps
  the per-phase "no model configured" lines and the table.** A header-only table read as a
  failure, while a run with no model is a supported scanners-only run. *Cost if wrong:* a
  script that parsed the empty table finds a sentence instead.
- **The table's headers are "json schema" and "tool calling", and each column is at least as
  wide as its longest word.** At 80 columns Rich cut `json_schema` and `tool_calling` to
  "json_sche…" and "tool_call…"; two-word headers wrap onto two lines instead. The config
  keys keep their underscores. *Cost if wrong:* a reader matches the header to the config key
  by eye rather than by exact text.

## Known-exploited and likely-exploited advisories (UNVAR-90)

- **A KEV-listed advisory is raised to critical; EPSS is shown and orders, never re-rates
  (owner's choice, option A).** CISA's catalog is evidence of exploitation in the wild, which
  outweighs a CVSS base score; an EPSS probability is a forecast, so it ranks advisories
  (within a finding, and findings within a severity, known exploited first) but leaves the
  CVSS-derived severity alone. *Cost if wrong:* a KEV entry for a code path the tool never
  reaches still reads critical (the consultant can accept the risk in `baseline.accepted`),
  and a high-EPSS medium stays medium.
- **One gzip bundle beside the end-of-life bundle, read by the inventory.** The first line is a
  JSON header with the KEV catalog; each other line is one EPSS score. One file is replaced
  atomically, so a failed refresh never leaves a header without scores; the default folder is
  the end-of-life one, so the image's existing mount and environment variable cover both
  (`UNVARNISH_VULNDATA_DIR` overrides it). A run streams the 300,000-odd scores once and keeps
  only the CVEs its advisories name, and the whole file is read so a truncated bundle is
  "unreadable", not partly used: on the real feeds the bundle is 2.9 MB and a lookup takes
  about 0.1 s. *Cost if wrong:* that read per inventory with advisories; a SQLite index
  would answer faster at several times the size.
- **The inventory marks advisories, not the scanner**, because `dependencies.json` is the
  inventory's artifact and must carry `kev`, `kev_date_added`, `epss` and `epss_percentile`
  per advisory; the bundle date joins the inventory's inputs hash as the end-of-life date
  does, and nothing joins it without a bundle, so existing engagements do not rerun. The
  dependencies scanner turns the marks into text, ordering, `Finding.exploits` (left out of
  the artifact when there is no data, so findings without a bundle are byte-identical) and
  the "not checked" or old-data note. *Cost if wrong:* none known.
- **Exploit data is old after 30 days by default** (`scanners.dependencies.max_data_age_days`),
  not the end-of-life data's 90: EPSS is republished daily and CISA adds to its catalog most
  weeks. The default lives in the scanner, not in the configuration defaults, because a new
  `dependencies` option would change every engagement's inventory hash. *Cost if wrong:* the
  note appears on a kit image a month after it was built; raise the limit per engagement.
- **An advisory's EPSS is the highest of its CVE aliases'**, and its KEV date the earliest.
  Its aliases are osv-scanner's group aliases plus each grouped vulnerability's own, so a
  report without `groups` still joins a GHSA advisory to the CVE it aliases.
  Both feed URLs were checked by downloading them on 2026-11-23 (KEV: `catalogVersion`
  2026.11.20, 1,790 entries; EPSS: a 302 to the dated file, 411,000 lines, the
  `#model_version`/`score_date` comment then `cve,epss,percentile`), and both can be
  overridden (`--kev-url`, `--epss-url`) if a feed moves again. *Cost if wrong:* a feed that
  changes shape fails the refresh by name and leaves the old bundle in place.

## Hidden text (UNVAR-92)

- **Scanner and escaping both (owner's choice, option A).** A scanner alone would report a
  rule file's hidden instructions while the model phases read and followed them; escaping
  alone would hide the problem from the report. One detector (`util/hidden_text.py`) decides
  what is hidden for the scanner, the excerpts and the prompts, so all three agree. *Cost if
  wrong:* none known beyond the escapes' length in prompts.
- **What counts as hidden:** bidirectional embeddings, overrides and isolates (U+202A-202E,
  U+2066-2069) and marks (U+200E, U+200F, U+061C); zero-width characters (U+200B-200D,
  U+2060-2064, U+FEFF past the start of a file); tag characters (U+E0000-E007F); and two or
  more variation selectors (U+FE00-FE0F, U+E0100-E01EF) or private-use characters in a row.
  Not hidden: a BOM at the start of a file, a ZWJ between emoji (skin tones and VS16 skipped),
  a ZWJ or ZWNJ beside an Arabic-script, Indic, Tibetan, Myanmar or Khmer letter, a single
  selector or private-use character (an emoji's VS16, an icon-font glyph) and an emoji
  subdivision flag's tag sequence. *Cost if wrong:* a joiner planted next to such a letter is
  missed; a legitimate pair of selectors is escaped (never reported below `long_run`).
- **Severity by what the characters can do.** Bidi controls (Trojan Source), tag characters
  and runs of 32 or more selectors or private-use characters (`long_run`; GlassWorm's
  payloads run to thousands) are high; zero-width characters in source are medium, because
  copy-pasted text often carries a stray ZWSP. Any hidden character in an AI rule file is
  high, one finding per file, because the file steers every later generation; source findings
  are grouped per rule across files, capped at `max_evidence`. Bidi marks beside
  right-to-left letters or in a right-to-left locale file, and isolates, embeddings and
  overrides on a locale file's lines of right-to-left text, are normal text. A `.js` or `.ts`
  file is a locale file only inside a locale folder (`locales/`, `i18n/`, ...), so
  `fa-icons.js` or `he/auth.ts` is code and its Trojan Source lines, which carry no
  right-to-left letter, are still reported (review fix). *Cost if wrong:* a stray ZWSP in
  `CLAUDE.md` reads high; a payload of 31 selectors in source is escaped but not reported; an
  isolate around a placeholder on a locale line with no right-to-left letter is reported.
- **Rule files are found by name and directory, whatever the census calls them:**
  `.cursorrules`, `.windsurfrules`, `.clinerules`, `.roorules`, `.goosehints`, `CLAUDE.md`,
  `CLAUDE.local.md`, `AGENTS.md`, `AGENT.md`, `GEMINI.md`, `.github/copilot-instructions.md`,
  and any file under `.cursor/rules/`, `.windsurf/rules/`, `.clinerules/`, `.roo/`,
  `.continue/rules/`, `.kiro/steering/`, `.claude/`, `.github/instructions/`,
  `.github/prompts/`, `.github/chatmodes/`, `.junie/`, `.amazonq/rules/` and
  `.augment/rules/`, at any depth. Other Markdown is not read. *Cost if wrong:* a new
  assistant's rule file is read as ordinary source (or not at all, if Markdown) until it is
  added to the list.
- **Escapes are `[U+XXXX]`, eight per run, then `[+N more]`.** Visible in every renderer,
  inside a code span in findings.md, plain text in SARIF and CSV, and never a newline, so a
  line number cited from an escaped prompt is the source's. *Cost if wrong:* a reader who
  needs the exact bytes of a long run opens the file.
- **Escaping happens at three shared points.** Prompts: `complete_structured`, the one
  function every model phase calls (extract, rollups, verify, compare, ask, `config check`),
  escapes the system prompt and every message, and returns the request unchanged when there
  is nothing to escape, so cache keys of ordinary requests do not move. Evidence:
  `Evidence.excerpt` and `note` are escaped by the schema, so no scanner or model finding,
  old artifact included, can carry raw characters into a document or export. Model text:
  `redact_model_text` escapes every string it redacts, which covers extractions, rollups and
  every finding the SARIF and CSV exports load. Verification compares a model's quote with the
  escaped source, as the model saw it. `PROMPT_VERSION` did not change; a unit's cache key
  gains a marker only when its text has hidden characters. Render's prose
  calls (`backend.complete` directly) escape their request with the same `escape_request`, and
  their text; the ask answer and its tool previews are escaped; and `render_document` escapes
  the whole rendered Markdown, so a path or name with a hidden character in any table reaches
  no document or export raw (review fix). *Cost if wrong:* an engagement extracted earlier
  keeps those extractions until extract reruns.
- **MCP configs that fetch code at launch are a medium review finding**, one per file with a
  line per server: `npx`/`bunx`/`pnpm dlx`/`yarn dlx`/`npm exec` with a package that has no
  exact version (`@latest` counts as none), `uvx`/`uv tool run`/`pipx run` without `==` or
  `@version`, and a shell command that pipes `curl` or `wget` into a shell. A command run
  through a shell wrapper (`cmd /c npx -y pkg`, `sh -c "uvx srv"`, `powershell -Command`) is
  judged as the command it runs (review fix). Local paths and
  servers given by `url` are not reported; only the command up to the package is shown, so
  arguments that carry tokens stay out of the report. *Cost if wrong:* a team that vets
  `@latest` on purpose gets a review line per server; a Docker image tag is not checked.

## AI services a tool uses (UNVAR-91)

- **One deterministic scanner with an inventory and four checks (owner's choice, option A).**
  The consultant needs to tell leadership which internal tools send data to which model
  provider, and the inheriting engineer where prompt injection and excessive agency start;
  both come from the code without a model. The provider, endpoint, model-id and framework
  tables in `scanners/ai_usage.py` are data, so a new provider is a table row. *Cost if
  wrong:* a provider missing from the tables is missed until it is added; extraction, told
  about each model call, can still name it.
- **The scan phase writes `inventory/ai-usage.json`, not the scanner.** No scanner wrote an
  artifact of its own before: scanners return findings, and the scan phase writes
  `scanner-findings.json`. The inventory is not a list of findings (a tool can use a model
  safely), so `ScanContext.inventory` carries it back and the scan phase writes it with its
  own inputs hash; it is one of the phase's outputs, so deleting it reruns the scan. A
  scanner failure leaves no file, which the documents show as "not checked" and which makes
  the scan rerun next time. *Cost if wrong:* a second scanner with an inventory needs the
  same two lines in the scan phase.
- **Low false positives over breadth.** Model ids count only in a file with a provider signal
  (an import, an endpoint or a client class), or on a `model` line when the id's pattern
  names its provider; call patterns shared with other APIs (`.messages.create(` is also
  Twilio's) count only beside that provider's import; a JavaScript-only package name
  (`ai`, `llamaindex`) imported in Python is the tool's own package, and so is
  django-haystack's `haystack.indexes`; a Django `model = "auth.User"`, a class name, or a
  bare `o1`/`o3` outside a `model` line of an AI file is not a model id. A loopback base URL
  (`http://localhost:8000`) is every web app's, so it names a local model server only beside
  another AI signal in the file (an SDK import or an OpenAI-compatible client), or when an
  OpenAI-style path (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`) is built
  from it; Anthropic's `/v1/messages` and Ollama's own paths at another port count only
  beside another AI signal (both are common app routes). Data flow is per file, by
  assignment statement: lines inside open brackets, after a backslash or inside a
  multi-line string continue a statement, so a multi-line `def` signature, a keyword
  argument or column-0 text in a docstring is not a statement, and an assignment reads its
  continuation lines. A value lives from the line it is bound until an unconditional
  reassignment from untainted values (a statement at the same or a lower indentation with
  no line between them indented less, so an `else:` or another branch does not end it) or
  the end of its Python function. Each live name is followed to the next assignment that
  reads or binds it, over an index of the file's assignments built once, so the cost
  follows the names reached rather than the file's length per prompt line (a whole-file
  pass per line took minutes on a 15,000-line handler file), and a call's argument text
  stops at 4,000 characters (a minified line after 30 calls took 30 seconds). An SDK pointed at a gateway's endpoint (the OpenAI client at
  `localhost:11434`) is recorded as the gateway, via the SDK. *Cost if wrong:* flows across
  files and through function parameters are missed, and a value reassigned in a branch
  still counts (known issues).
- **Severities: output to eval/exec, a shell or SQL text is high; request input in a prompt
  is one medium review finding; tools beside powerful actions are medium; unbounded calls
  are low.** The first is code execution with the tool's privileges for whoever controls the
  model's input; the second is a list to confirm, like the route review finding; the owner
  asked to keep excessive agency modest. A call counts as bounded when it sets a token limit
  or spreads options it may hold, or when its file mentions a timeout anywhere or a token
  limit outside any call (a client default). *Cost if wrong:* a call bounded only in another
  file is reported, and a file-wide timeout hides an unbounded call beside it.
- **API keys stay with the secrets scanner; excerpts redact every credential shape we can
  recognise.** The inventory holds no excerpts and checks each model id against the secrets
  rules (and drops any with `://`). A finding excerpt is cut to 1,000 characters (which
  bounds the cost of the patterns), then redacted by the secrets rules and these shapes: a
  trailing comment; URL userinfo and query values (Gemini's `?key=`); the value of any name
  that mentions a key, token, secret, password, pass (also a name ending in it, `DBPASS`,
  `smtppass`), passphrase, pin, signature, auth, session or cookie, in code (`"x-api-key": KEY || "..."`, `"Authorization": "Bearer " + "..."`) or
  inside a string (`PGPASSWORD=...`, `"dbname=x password=..."`); env-lookup defaults and a
  fallback after an env-style constant; `auth=(...)` tuples and Basic auth arguments; the
  first argument to an AI client constructor (`OpenAI("...")`); `-p`, `-u user:pass`,
  `--password` and `--passphrase` on a command line, in shell text or as list-form
  arguments (`["-p", "..."]`); and any token of 12 or more characters with letters and
  digits inside a string literal unless it is a model id or a host name. *Cost if wrong:*
  this is not a guarantee. A credential with none of these shapes still shows: a short or
  letters-only value with no secret-like name beside it (`{"X-Upstream": "..."}`, a
  password passed positionally to a function that is not an AI client, a bare word in
  shell text, `redis-cli -a ...`, SQL `IDENTIFIED BY '...'`). An excerpt can also lose a
  harmless long identifier, or the value beside a name like `bypass`.

## CycloneDX SBOM and dependency licences (UNVAR-93)

- **SBOM export now, licences only online (owner's choice, option A).** `export --format
  cyclonedx` builds the document from `dependencies.json` and its stored advisories, so it runs
  offline and adds no osv-scanner call at export time. Licences come only from deps.dev, which
  osv-scanner reaches online (`--licenses` with no allowlist, plus `--all-packages` so packages
  without advisories are listed); offline nothing is filled in and the findings document and
  the SBOM's metadata say "licences: not checked". *Cost if wrong:* an air-gapped engagement
  never gets licences; the consultant runs the inventory online where the site allows it.
- **CycloneDX 1.6 JSON, written by hand, not by a library.** The document needs a few dozen
  fields, and a dependency would ship in the image for one export. The suite validates it
  against the vendored 1.6 schema (with its SPDX and JSF schemas) using `jsonschema`, a new
  dev-only dependency. Licences are one SPDX expression when every licence is a recognised
  identifier, else each by name, so an unrecognised string never fails the schema's SPDX
  enumeration. *Cost if wrong:* a field a consumer expects is missing until added here.
- **Components are the declared dependencies, then what online resolution and advisories add.**
  A declared dependency carries its exact version when its constraint pins one (or online
  resolution found exactly one), else its constraint as a property, and its manifest. Packages
  osv-scanner resolved online that no manifest declares, and packages an advisory names that
  none does, are listed at their resolved version so every vulnerability's `affects` points at
  a component. Packages join records by ecosystem, normalised name and folder, since a
  lockfile resolves the manifest beside it. *Cost if wrong:* a manifest in one folder resolved
  by a lockfile in another shows the package twice.
- **Package URLs for osv-scanner's other ecosystems too.** Packages only osv-scanner reports
  (RubyGems, Packagist, NuGet, Pub, Hex, from lockfiles or advisories) get their purl type
  (`gem`, `composer`, `nuget`, `pub`, `hex`); a go.mod requirement, pseudo-versions and
  `+incompatible` included, is always an exact version. Any other ecosystem's component has
  no purl rather than a guessed one. *Cost if wrong:* a component a consumer cannot match by
  purl.
- **The allowlist is Unvarnish's own, applied by the scanner.** It never reaches osv-scanner,
  whose verdict (`license_violations`) is ignored, and osv-scanner keeps getting Unvarnish's
  empty `--config`, so a `PackageOverrides` licence override or ignore in the vetted
  repository's `osv-scanner.toml` has no effect (as for advisories, UNVAR-66's principle).
  Changing the allowlist reruns the scan, not the lookup. *Cost if wrong:* none known.
- **Medium for a licence that cannot be met without a copyleft one, low for any other licence
  outside the allowlist or none deps.dev can name**, one finding per manifest and licence, in
  the compliance category, band M. A copyleft licence can reach the tool's own source when it
  is distributed, which is the client's question; an unlisted permissive licence needs a
  review, not a rewrite. *Cost if wrong:* a weak-copyleft package used unmodified (LGPL, MPL)
  reads medium; the consultant accepts it in `baseline.accepted`.
- **No `licences` default in the configuration, and the online lookup joins the inventory's
  hash.** A new default would change every engagement's inventory hash; the online marker
  reruns only online inventories, once, so they pick licences up. The new note is scanner
  text, so the scan reruns once everywhere (SCANNER_TEXT_VERSION 2026-11-24.3). *Cost if
  wrong:* one osv-scanner call per online tool on upgrade.

## Batch mode for verify and prose (UNVAR-94)

- **Only verify and the render prose calls go in batches (owner's choice, option B).**
  Extract needs each unit's neighbours summarised in order (spec §6.6), and the module and
  tool rollups wait on each other, so batching them would serialise a run on hour-long
  batches. Verify's calls are independent of each other, and so are a tool's prose blocks.
  `rollup_modules` stays synchronous: it is structured output feeding `rollup_tool`, not the
  prose path. *Cost if wrong:* extract, the bulk of a run's tokens, still costs the
  synchronous price; option A (every phase) is the follow-up in known-issues.
- **A batch fills the response cache; the phase then runs as it always does.** Each phase
  works out the exact first request its ordinary path would send (`first_request` for
  structured calls, `first_prose_requests` for prose), sends them in one batch with the
  request's cache key as the custom id, and writes each usable reply into the response cache.
  The workers then find their first call answered there. Anything the batch could not answer
  (errored, expired, canceled, refused, empty, cut off, or a reply that fails validation)
  goes through the ordinary path: retried as a call, and recorded in `failures.json` if that
  fails too, never dropped. One code path produces the artifacts, so a batched run's are the
  same as a synchronous run's on the same replies. *Cost if wrong:* a request the batch
  missed costs the synchronous price; on a mostly failing batch the run pays twice for those.
- **The batch id is kept until its results are in the cache.** `analysis/batches/<phase>.json`
  holds the submitted batch ids and their requests' cache keys (no request content, no key).
  A run stopped while a batch is in progress collects the same batch on the next run and
  never sends its requests in a second batch. Each batch leaves the file as soon as its
  results are in the cache, so a stop between two batches of one phase never has the next
  run collect, and bill, the first one again; the file is deleted once all are in.
  A stored batch the API no longer returns (results are kept 29 days) is dropped and its
  requests go in a new batch. *Cost if wrong:* a stop in the instant between the API
  accepting a batch and the file being written pays for that batch twice.
- **The budget cap is checked once, before a batch is submitted, and the batch's usage counts
  after its replies are used.** A batch is one spend that cannot stop half way; counting it
  before the workers ran would throw away replies already paid for. Each batch's usage
  reaches the ledger as soon as it is collected, even when a later batch of the same phase
  fails, and the in-run budget counts it whether the phase ends normally or raises. *Cost if wrong:* a run
  can pass `budget.max_tokens` by one phase's batch; the next phase stops as usual.
- **Batch usage is a separate ledger entry, marked `batch`, priced at half.** `cost` shows
  such an entry as `<phase> (batch)` and prices it at `BATCH_RATE` (0.5); `run --dry-run`
  prices a batched phase's estimate at the same rate. Cache reads and writes inside a batch
  get the same discount, as Anthropic bills them. *Cost if wrong:* if the provider's
  discount changes, estimates and the ledger are off until `BATCH_RATE` follows it.
- **`batch: true` on an `openai_compatible` backend is a configuration error**, not ignored:
  a consultant who asked for half-price runs must not get full-price ones silently.
  `config check` prints one notice line per batch backend: the provider keeps batch results
  for 29 days and batches are not eligible for zero data retention. *Cost if wrong:* none
  known; a client with a zero-retention agreement leaves batch mode off.
- **Polling waits in one-second steps of an injected sleeper, every 30 seconds.** Ctrl-C stops
  the wait at once and leaves the batch to resume; tests never sleep. There is no local
  timeout: the API ends every batch within 24 hours, expiring what it did not process. A
  rate-limited status check (HTTP 429) counts as "still in progress", never as the batch's
  failure: dropping the batch would send its requests again and pay for them twice. A
  rate-limited results download is tried again a poll later (up to 10 times, then the run
  stops and the next run collects the batch). Any other non-fatal error reading a batch, new
  or stored, drops that batch and sends its uncollected requests as ordinary calls; the phase
  still ends normally.

## Empty header fields (UNVAR-85)

- **A missing client or firm is left out of the header, not shown as a dash.** The
  comparison keeps "Engagement" in its title when there is no client, because a title needs
  a noun. The template change reruns the render phase once on every engagement. *Cost if
  wrong:* a reader of a document without a client cannot tell whether the field was
  forgotten; `init` now says so at the start instead.

## Opengrep SAST scanner (UNVAR-89)

- **Bring your own rules; nothing bundled (owner's choice: bundle a rule set only if its
  licence allows redistribution, otherwise this first).** The opengrep/opengrep-rules
  repository's LICENSE (read 2026-11-23) is the semgrep-rules licence: LGPL 2.1 with the
  "Commons Clause" License Condition v1.0, licensor Semgrep, Inc. The clause withholds the
  right to "Sell", defined as providing to third parties, for a fee, "a product or service
  whose value derives, entirely or substantially, from the functionality of the Software",
  expressly including consulting and support fees. Unvarnish is a consultant's paid
  review tool, so shipping those rules in the image is at best unclear; the Dockerfile, site
  kit and CI are unchanged and the consultant supplies a rules directory. Latest Opengrep
  release seen: 2.0.0 (13 November 2026, GitHub releases page). *Cost if wrong:* if the
  clause does not reach this use, a scan without the consultant's own rules finds no
  code-level flaws that bundled rules would have; bundling is a later, separate change.
- **Local rules only.** `scanners.sast.rules` must be a local directory holding `.yml` or
  `.yaml` files; `auto`, registry names and URLs are refused before Opengrep starts, and its
  absolute path is what Opengrep sees. *Cost if wrong:* a consultant who wants a registry
  pack downloads it into a folder first.
- **Offline flags from Opengrep's source, not its docs.** Opengrep's `scan` command has no
  `--metrics` flag (passing one fails the run) and accepts `--disable-version-check` as an
  inert flag kept for Semgrep compatibility; both read from `Scan_CLI.ml` and
  `CLI_common.ml` on main. Unvarnish passes `--disable-version-check` and no `--metrics`.
  *Cost if wrong:* a release that rejects the flag turns the scan into a "not checked" note.
- **The vetted repository's ignore rules never apply.** Opengrep runs with `--no-git-ignore`,
  `--x-ignore-semgrepignore-files` and `--disable-nosem`, in an empty temp folder (the
  gitleaks lesson of UNVAR-66), and Unvarnish's census filters the results. Ignore files and
  `nosem` comments are reported as one low "Opengrep suppressions in the source" finding,
  low because they are disregarded (gitleaks' `.gitleaksignore` is medium because it still
  applies). *Cost if wrong:* results in gitignored files the census would also exclude are
  dropped anyway; a nosem comment that marks a confirmed false positive still costs a review.
- **One finding per rule.** Rule id goes in a `group:` tag with a `count:`, so the re-audit
  delta matches it by scanner and rule (UNVAR-49) and reports a changed count. Severity maps
  `ERROR` to high, `WARNING` to medium, `INFO` to low (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW` too);
  category follows the rule's `metadata.category`, security by default. Effort band M per
  rule, S for the suppression finding. *Cost if wrong:* a rule with hundreds of matches is
  one finding with a long count, which is the intent.
- **The scan's inputs include the rule files and whether `opengrep` is on PATH**, so editing
  rules or installing Opengrep rescans; the Opengrep version is not included. No scanner
  text version bump: the new scanner name already changes every scan's inputs hash.
  *Cost if wrong:* an Opengrep upgrade keeps an older scan until `--force`.

## Offline readiness check and bundled exploit data (UNVAR-101)

- **One `doctor` command, plus exploit data in the image and site kit (owner's choice,
  option A).** Each data set is located by the module a run reads it with (`analysis.eol`,
  `analysis.vulndata`, `analysis.advisories`, `analysis.treesitter`) and each tool by the same
  `which` and version checks `export` uses, so the check cannot disagree with a run about where
  a bundle lives or which pandoc is too old. *Cost if wrong:* none known.
- **Exit 1 only when something needed is absent, partial, unreadable or too old; stale data
  passes.** A run uses old data with a note, so stale is a warning in the table, not a failure;
  `docs/operations.md` ("Before you travel") tells the operator to refresh every stale row.
  Exit 2 is kept for an unreadable engagement, as elsewhere. *Cost if wrong:* a script that
  gates on the exit code ships a month-old kit; it can read `--json` and test `status`.
- **Outside an engagement, `doctor` judges against a new engagement's defaults** rather than
  refusing or passing everything: a laptop check before `init` is the common case, and the
  defaults are what `init` writes. An explicit `-e` that is not an engagement is an error (2).
  *Cost if wrong:* a machine meant only for HTML export fails on a missing weasyprint; `--json`
  shows that row alone failed.
- **The offline OSV databases are held to the exploit data's age limit**
  (`scanners.dependencies.max_data_age_days`, default 30) in `doctor` only: they are the same
  scanner's advisory data and have no limit of their own, and a run does not note their age.
  *Cost if wrong:* `doctor` calls a deliberately old database stale; raise the limit.
- **`--probe-backend` is a plain unauthenticated GET of each backend's models listing**
  (`<base_url>/models`, or Anthropic's `/v1/models`), counting any HTTP answer, a 401
  included, as reachable. It answers "can this machine reach the server" without a key,
  without tokens and without the cost ledger; `config check` remains the test of the key and
  the model. Without the flag nothing opens a socket (a test makes every connect raise).
  *Cost if wrong:* a proxy that answers for an unreachable host reads as reachable;
  `config check` still fails then.
- **The image writes `vulndata.gz` into `/opt/eol` and sets no `UNVARNISH_VULNDATA_DIR`**, so
  the folder a run reads by default holds both bundles and the existing `-v ...:/opt/eol`
  refresh covers both. The build step mirrors the end-of-life one: `EXPLOIT_DATA=fetch` (the
  default) fails the build when a feed fails, `skip` builds without it, anything else fails.
  CI's docker job prints both bundles' dates, runs `doctor --json` in the image, and builds
  once more with both skip arguments. *Cost if wrong:* about 3 MB per image and two more
  downloads per build; a CISA or FIRST outage fails the image build, as an endoflife.date
  outage already does (build with `EXPLOIT_DATA=skip` meanwhile).

## Leadership brief (UNVAR-99)

- **A separate `comparison/brief.md`, not a section of comparison.md (owner's choice, option
  A).** Leadership can be handed it without the engineering sections. It is rendered by its own
  engagement phase, `render_brief`, after `render_comparison`. *Cost if wrong:* one more file
  in `comparison/` and one more `--doc` value to know about.
- **Numbers from each tool's artifacts, not from comparison.json.** The brief needs the
  findings themselves (the ten most severe, the buckets), which comparison.json does not hold,
  so it reads `census.json`, `scanner-findings.json`, `findings.json`, `dependencies.json` and
  `delta.json` per tool and counts them with the same helpers as `findings.md` and the risk
  table (`merged_findings`, `risk_row`, `eol_counts`, `effort_counts`). It therefore renders
  even when compare's model calls failed or stopped for budget (`runs_after_stop`); a compare
  that fails outright still skips it. *Cost if wrong:* if the two documents' inputs drift (a
  tool rerun between compare and a later brief), the brief is the fresher one; both rerun on
  the next `compare`.
- **Action-plan buckets from severity and effort band only.** Critical: fix now, whatever
  the effort (a large job is a reason to start, not to wait). High: fix now at S or M, fix
  before scaling at L or XL. A high finding with no band is fix now: an unknown effort is not
  evidence of a large job, and the stricter bucket is the safer default. Medium: fix before
  scaling, whatever the effort. Low and info: accept (on record, or fix when the code is next
  changed). No setting changes the rule; a consultant moves a finding by changing its band or
  severity. *Cost if wrong:* a critical XL item sits in "fix now" beside quick fixes, and the
  fix-now engineer-days can be large; the per-bucket effort column shows that.
- **"Credential-like values" are the secrets scanner's findings**, split into working tree and
  git history only, matching the "Secrets" row of `findings.md`; browser-exposed credentials
  (client_exposure) are a separate row because one value can be counted by both scanners.
  *Cost if wrong:* a reader adds the two rows and over-counts; the rows are labelled apart.
- **The ten most severe findings in a fixed order:** severity, known exploited and EPSS,
  scanner before model (as `findings.md`), then the tools' order in `engagement.yaml`,
  path, line and title, so the same findings always give the same ten whatever order the
  artifacts list them in. *Cost if wrong:* at equal severity the first-listed tool fills
  the ten first; the per-tool row still shows every tool's counts.
- **A measure not checked for every tool is summed over the checked tools and says so**
  ("1 (1 of 2 tools checked)"), never filled in as zero. *Cost if wrong:* none known.
- **One new prose block, `portfolio_summary`, with no `PROSE_PROMPT_VERSION` bump.** The
  system prompt and the existing blocks are unchanged, so the existing documents' prose would
  come out the same; bumping would re-render every tool's prose. The block asks for
  severity counts only for all tools together, so the existing severity-count check holds
  against the totals. *Cost if wrong:* none for cached text; the brief's own hash covers the
  template.
