# Changelog

Unvarnish is built in slices (design spec §16). Each slice was planned, implemented test-first,
reviewed by a fresh-context reviewer on the whole branch, and fixed before merge. Decisions made
along the way are in [docs/decisions.md](docs/decisions.md); accepted minor gaps are in
[docs/known-issues.md](docs/known-issues.md); operating lessons are in
[docs/operations.md](docs/operations.md).

## [Unreleased] — 0.1.1

### A CycloneDX SBOM per tool, and licence checks online

- `unvarnish export --format cyclonedx` writes `exports/sbom-<tool>-<timestamp>.cdx.json`, a
  CycloneDX 1.6 SBOM of each tool's dependencies (package URL, version or constraint,
  manifest) and known advisories, without running osv-scanner. Online, package licences from
  deps.dev reach the SBOM, and `scanners.dependencies.licences` flags each licence outside
  that allowlist as a compliance finding; offline the documents say "licences: not checked".
  Scans rerun once to pick up the new note (UNVAR-93).

### `config check` without a model says what works

- With no model configured, `config check` prints one line saying `run` still runs the
  scanners and how to set `models.default`, instead of an empty table. The table's headers read
  "json schema" and "tool calling" and wrap in a narrow terminal rather than being cut to
  "json_sche…" at 80 columns (UNVAR-83).

### Known exploited dependency advisories

- `unvarnish vulndata refresh` downloads CISA's KEV catalog and FIRST's EPSS scores into an
  offline bundle; with it, an advisory CISA lists as exploited is critical and says "Known
  exploited (CISA KEV, added <date>)", and every advisory shows its EPSS score, which orders
  them, in `dependencies.json`, findings.md, CSV and SARIF (UNVAR-90).

### The site lives at unvarnish.tech

- The public site's canonical address, Open Graph and structured-data URLs, sitemap, robots
  file, `security.txt` and the package's Homepage now use `https://unvarnish.tech`.
  `unvarnish.com` and `www.unvarnish.com` redirect there (UNVAR-96).

### One commit, one file, one unit

- Phase lines, `status` cells, the run log and `ask`'s index line now say "1 commit",
  "1 file", "1 unit in 1 file", "1 doc" and so on instead of "1 commits"; the route-handler
  finding says "has ... near it" for a single handler. Scans rerun once to pick up the new
  text (UNVAR-81).

### A repeated value on one line is one piece of evidence

- The hardcoded-infrastructure scanner lists a value once per line, so an href and its link
  text no longer give two identical evidence rows that use up the evidence cap, and the
  "N locations" count is the number of distinct file lines. Finding ids do not change
  (UNVAR-82).

### Model-written text stays inside its paragraph

- A finding's summary, impact, remediation, effort note and verifier note can no longer start
  a heading, table, code fence, blockquote, list or rule in `findings.md` and its exports, and
  a prose block can no longer open a top-level or section heading. The words are kept, with a
  backslash before the marker (UNVAR-76).

### Unreachable model server is not a budget stop

- When a run stops because the model server cannot be reached, `status` now says the extract
  phase stopped because the backend was unreachable instead of "budget-stopped", "last run"
  shows the failure instead of "never", and the error names the server's base URL and
  suggests `unvarnish config check` (UNVAR-78).

### Architecture document without a module map

- When the tool model has no module map, `architecture.md` now says in one sentence that none
  was identified instead of printing a Mermaid block containing `None`, and the HTML, DOCX and
  PDF exports carry no blank module-map image (UNVAR-77).

### Attribute access is not a hostname

- The hardcoded-infrastructure scanner no longer reports code such as `if g.internal:`,
  `user.private and opts.local` or `net.lan;` as internal hostnames. In Python, JavaScript,
  TypeScript, Go and the other languages it lexes, a dotted name outside strings and comments
  that is used as an expression is code; hostnames in strings, comments, config files and
  shell scripts are still reported (UNVAR-75).

### unvarnish.com in the new Bonham Technologies design system

- The product site is rebuilt on the design system bonham.tech now uses: a light Daylight
  theme by default and a dark Night theme by the reader's system setting, Archivo and IBM Plex
  Mono, square shapes and hairlines, and one orange action button per view. Unvarnish's own
  identity inside it is no accent colour at all and a "stripped layers" motif under the hero,
  in the icon and in the link-preview image. Copy, links and the published NodeGoat exports
  are unchanged.
- Fonts are now self-hosted under `site/fonts/` and the site's CSP no longer allows Google
  Fonts, so the pages make no third-party request (UNVAR-74).

### Public repository

- The repository went public with a fresh history on 2026-11-18 (UNVAR-37), under the
  lowercase name `Bonham-Technologies/unvarnish`. The site's licence section and both footers
  now link it, and the package metadata, SECURITY.md, the issue template and the CI runner
  notes use the new name and present tense.
- `.gitleaksignore` is removed: its entries named commits of the old private history, so it
  suppressed nothing, and gitleaks finds nothing in the public history or tree (UNVAR-72).

### Anthropic backend and temperature

- A model request that sets a temperature no longer crashes the Anthropic backend: the SDK's
  `messages.create` takes no temperature, so the backend drops it with a debug log line. The
  OpenAI-compatible backend still sends it. Nothing sets one today (UNVAR-69).

### Export author

- HTML and PDF exports now carry the engagement's consultant (or "Unvarnish") as their author,
  the same value Word exports get: a `<meta name="author">` in the HTML and `/Author` in the
  PDF's document information. Both were missing. No byline is added to the body (UNVAR-60).

### gitleaks ignores the consultant's folder

- gitleaks now runs in an empty temp folder of Unvarnish's own. gitleaks 8.30.1 also reads
  `.gitleaksignore` from its working directory, so an ignore file in the folder Unvarnish was
  started from could hide a client's secret findings, tree or history, with no trace; the
  "Scanner suppression files in the source" finding only looks in the client's source. The
  scanned tree's own `.gitleaksignore` still applies and is still reported (UNVAR-66).

### CI test job time limit

- The CI `test` job stops after 45 minutes instead of GitHub's six-hour default, so a hung
  grammar download or pandoc call can no longer hold a runner and every pull request's
  `ci-status`. A normal run takes about 6 minutes; a slow apt mirror once took 32.
  `tests/test_repo_hygiene.py` checks that every job in every workflow sets a limit (UNVAR-65).

### Fork pull requests stay off the self-hosted runner

- CI uses the runner named by the `RUNS_ON` repository variable only for a pull request from a
  branch of this repo. A fork's pull request, a push and any other event run on the hosted
  `ubuntu-24.04`, so the workflow itself never routes outside code to a self-hosted machine.
  A fork's pull request can edit `ci.yml`, so the self-hosted runner must also be unavailable
  to the public repo (`docs/operations.md`, CI runners). Checkout no longer leaves its token
  in `.git/config` (`persist-credentials: false`). `tests/test_repo_hygiene.py` checks both for
  every workflow (UNVAR-70).

### HTML landmarks and row headers

- HTML exports put the report inside a `<main>` landmark, mark column headers with
  `scope="col"`, and make the first column of summary tables (the severity counts and the
  Measure and Layer tables) row headers, `<th scope="row">`, so a screen reader
  announces "high" or "Source lines" with each value. The bundled `report.css` styles those
  row headers like the data cells they replace, so the page looks the same. The filter runs
  for HTML only: Word and PDF output is unchanged. A custom `html_css` should copy the
  `tbody th` rule (UNVAR-64).

### Missing `--repo` path

- `unvarnish add --repo <path>` with a path that does not exist now says
  `error: <absolute path> does not exist` instead of "has no .git directory; use --files",
  which sent a user who had only mistyped the path toward the wrong fix. A path that is a file
  says it is not a folder. An existing folder without `.git` keeps its message (UNVAR-63).
  `add` prints its errors on one line, so a long path is not broken across lines.
- `add --files` and `add --link` say the same: a missing path is `<absolute path> does not
  exist` and a file is not a folder, where they said `<last segment> is not a directory`
  for both (UNVAR-71).

### Dry-run render estimate counts a tool's own blocks

- The dry-run estimate for the `render` phase counted every prose block, including the
  comparison document's two, so it showed "7 prose blocks" where a tool's render makes 5
  calls. It now counts the blocks the tool's own templates reference, read from the same
  templates the render phase uses, overrides included (UNVAR-62). The comparison's blocks
  belong to `compare`, which still has no dry-run estimate (see docs/decisions.md).

### Dry run with nothing to do

- `unvarnish run --dry-run` on an engagement where every phase is fresh prints "Nothing to
  run: every phase is fresh." instead of an empty table (UNVAR-61). With `--phase` it names
  that one phase, and when some tools are missing it says the sentence covers the others.

### Login guards count as authentication

- `client_exposure` no longer reports a route handler as having no authentication check when
  its line or the lines around it (`auth_window`) name a guard such as `isLoggedIn`,
  `ensureLoggedIn`, `is_logged_in`, `requireLogin` or `require_login` (`isAuthenticated` and
  `login_required` already matched).
  On OWASP NodeGoat this removes 15 false positives like
  `app.get("/profile", isLoggedIn, ...)`. A bare `login` is deliberately not a guard, so a
  route path such as `/account/login-history` still fires. The scan's text version is bumped,
  so an engagement scanned earlier rescans once (deterministic, no model calls) (UNVAR-67).

### Dependencies

- tree-sitter 0.26.1 (from 0.25.2), with typer 0.29.1, anthropic 2.8.0, openai 3.50.0 and ruff
  0.17.5 (Dependabot #121). The pin moves from `<0.26` to `!=0.26.0,<0.27`: 0.26.0 still
  segfaults freeing large parse trees and stays excluded, while 0.26.1 passes the full suite.

### Plural words in client documents

- The findings, comparison and scanner summaries no longer print "13 finding(s)" or
  "1 credential-like value(s)": counts take the right plural and the verb agrees ("1 finding
  is", "5 findings are"). A small shared helper, `unvarnish.util.plural`, backs the scanners
  and registers as the `plural`, `pluralize` and `is_are` Jinja filters. "1 distinct IP
  addresses" now reads "1 distinct IP address". Finding titles and ids are unchanged (ids hash
  the title, category and first evidence, not the summary), and a re-audit delta pairs findings
  by id, title, path and fingerprint and calls one "changed" only when it moved or was re-rated,
  so a delta against a baseline made before this upgrade shows no wording-only changes. The
  scan's inputs hash now carries a scanner text version, so an engagement scanned before this
  rescans once on its next plain run (deterministic, no model calls) and its documents lose the
  old wording; `run --phase render` alone keeps the summaries already in
  `scanner-findings.json` (UNVAR-57).
- Command-line and error messages drop "(s)" too: "1 file written under exports/",
  "3 recorded failures", "unknown tool: x", "no heartbeat for 1 minute". A source test now
  covers every file under `src/unvarnish/` except the model prompts, whose wording is part of
  their prompt version (UNVAR-68).

### End-of-life refresh

- `unvarnish eol refresh` checks the target folder is writable before it downloads anything, and
  a write failure prints one `error:` line naming the folder and suggesting `--dir`, exit 1,
  instead of a traceback after all 19 downloads. This was what a non-root container user
  got with the root-owned `/opt/eol` (UNVAR-56).

### Site launch fixes

- unvarnish.com went live on 2026-11-15 (BORG-96). bonham-ops `bin/seo-check` then failed two
  items: the site now serves `/.well-known/security.txt` (RFC 9116) with `Contact:
  mailto:support@bonham.tech` and an `Expires:` under a year out, and
  `demo/nodegoat-findings.html` names itself as canonical and has a description. The findings
  text is unchanged. `tests/test_site.py` checks both, and that every sitemap page is its own
  canonical.

### Licence and public-release hardening

- Unvarnish is licensed under Apache-2.0: `LICENSE` holds the standard text (it was a
  proprietary notice), `NOTICE` names the copyright holder, and the package metadata says
  `License-Expression: Apache-2.0` with both files in the wheel and the sdist. The Docker
  image copies them too. Contributions need a DCO `Signed-off-by` line (`git commit -s`);
  `CONTRIBUTING.md` explains it and `.github/dco.yml` configures the check. The README links
  the licence, contributing guide, code of conduct and security policy (UNVAR-36).
- CI runs with `permissions: contents: read`, and its actions are pinned to full commit SHAs
  (Dependabot's `github-actions` entry bumps the pins). CODEOWNERS covers `/.claude/` and
  `/site/`. The pull request template asks for a ticket key instead of linking the internal
  tracker (UNVAR-36).
- Credential-shaped test fixtures (Stripe, GitLab, Slack webhook, AWS, Anthropic, OpenAI,
  JWT and private-key headers) are built from fragments at runtime, so no tracked file holds a
  whole real-format token and GitHub secret scanning and push protection have nothing to act
  on once the repository is public. The values the tests see are unchanged.
  `tests/test_repo_hygiene.py` guards all of the above (UNVAR-36).
- The repository goes public as a fresh-history snapshot of this tree, so no tracked file
  outside the vendored `.claude/` policy links the internal Jira or Confluence site any more;
  `CLAUDE.md` names the Jira key and the Confluence tree as plain text, and
  `tests/test_repo_hygiene.py` fails on such a link (UNVAR-37).

### Export

- `unvarnish run --help` lists the phase names and `export --help` the formats and documents,
  all read from the pipeline and exporter definitions. `--phase`, `export --format` and
  `export --doc` complete their values in the shell (`unvarnish --install-completion`), and
  `--format HTML`, `--doc Findings` and `--phase Scan` are accepted: all three are
  lower-cased before validation (UNVAR-11).
- `unvarnish export --format sarif` and `--format csv` write each tool's findings as data, so
  client engineers stop retyping them into GitHub, Jira or Azure DevOps:
  `exports/findings-<tool>-<timestamp>.sarif` (SARIF 2.1.0, one run, one rule per source,
  category and title, `partialFingerprints.unvarnishFindingId`, repo-relative locations with
  line regions, levels from severity, GitHub's `security-severity` on security rules) and
  `.csv` (Summary, Description, Severity, Tool, Category, Source, Path, Lines, FindingId,
  Verification). Both hold the findings document's set (findings verification rejected are
  left out), pass through the secrets redactor, and need no pandoc. They are opt-in: `export`
  with no `--format`, or `--format all`, still writes docx, html and pdf only. A tool over
  GitHub's 25,000 results per run is split into part files. README and `docs/operations.md`
  show the `gh api` and `upload-sarif` uploads and the Jira CSV import (UNVAR-41).
- `export --format sarif` or `csv` with a `--doc` list that leaves out `findings` now exits 2
  before any work, with "sarif and csv come from the findings document; add `--doc findings` or
  drop `--doc`". It used to print an empty table and "Nothing to export: run `unvarnish run`
  first", which blamed a fully run tool. A mixed request such as `--format sarif --format docx
  --doc architecture` is refused whole, since part of it cannot be produced (UNVAR-58).

### Scanners

- New `client_exposure` scanner, offline and deterministic, for the ways AI-built web apps
  leak: a Supabase service-role key (decoded from the JWT, or an `sb_secret_` key) or a
  Firebase web config in browser-facing code (`src/`, `public/`, `dist/` by default); a
  `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` or `EXPO_PUBLIC_` variable named like a secret; SQL
  migrations that create a public table without enabling row level security (in a tool that
  uses Supabase or RLS), disable it, or add a `using (true)` policy, an insert policy without
  `with check` or an update policy with neither `using` nor `with check`; the public
  anon key in client code while tables are open; CORS that allows any origin with
  credentials; credentials in committed `.env` files and in `.mcp.json`,
  `.cursor/mcp.json` and `claude_desktop_config.json`; and API route handlers (Next.js,
  Express, FastAPI/Flask) with no authentication identifier nearby, as one medium review
  finding whose lines are handed to extraction so the model can confirm each. Values are
  redacted and fingerprinted. "By the numbers" and the comparison risk table gain a
  "Client-exposed credentials / open tables" row; client roots, extensions, public-by-design
  names and the search windows are set under `scanners.client_exposure` (UNVAR-39).
- New `end_of_life` scanner: a runtime, base image or framework past its end of life is a
  high finding, and one whose end of life falls within six months (`warn_months`) a medium
  one, each with its date and the date of the data. Versions come from `.python-version`,
  `requires-python`, `runtime.txt`, `package.json` engines, `.nvmrc`, `go.mod`,
  `*.csproj`/`*.fsproj`/`*.vbproj` TargetFramework, Dockerfile `FROM` tags (registry hosts
  are never repeated), `.ruby-version`, `composer.json` and the Django, React, Next.js, Vue,
  Angular and Spring Boot dependencies the inventory parses; a range such as `>=3.9` is
  judged by its lowest allowed version and the finding says so. Dates come offline from a
  bundled copy of endoflife.date (19 products), fetched on a connected machine with the new
  `unvarnish eol refresh` into `$UNVARNISH_EOL_DIR`, else `~/.local/share/unvarnish/eol`.
  Without a bundle the findings document says "not checked" and notes it under "Not
  analysed"; with one, "By the numbers" gains an "End-of-life runtimes and frameworks" row
  with the data date, and a refreshed bundle reruns the inventory and scan (UNVAR-43).
- The Docker image carries the end-of-life bundle: the build runs `unvarnish eol refresh`
  into `/opt/eol` and sets `UNVARNISH_EOL_DIR`, so a `--network none` run flags an
  end-of-life `FROM python:3.9-slim` with the data date. The build fails if any product
  cannot be downloaded; `--build-arg EOL_DATA=skip` builds without the data, and runs then
  report end of life as "not checked". `scripts/site-kit.sh` builds with the bundle and its
  image check prints the bundle date; the runbook says how to refresh it at a site without
  rebuilding the kit (UNVAR-44).
- An end-of-life bundle older than `scanners.end_of_life.max_data_age_days` (default 90)
  now says so: "Not analysed" gains a note naming the bundle's date, its age and how to
  refresh it, and the "End-of-life runtimes and frameworks" row adds "(N days old, older
  than the 90-day limit: refresh it)". The findings are made from the old data as before.
  An air-gapped site that never refreshed the data used to get no hint that runtimes ended
  since then could be missing. The new default is part of the scan's inputs hash, so the
  first run after upgrading reruns the scan and the documents of every tool once, and the
  comparison of a multi-tool engagement; the comparison's model calls are answered from the
  response cache, since its prompts do not include the scan's notes (UNVAR-59).

### Re-audit delta

- `unvarnish run --baseline <path>` compares this review with a previous one: a prior
  engagement folder, a tool folder, or one findings artifact (`scanner-findings.json` or
  `findings.json`), resolved per tool. Findings match by id, then by title and path within
  `baseline.line_drift` lines (default 50), then by secret fingerprint. Each tool gets
  `analysis/delta.json` (new, resolved, changed, persistent, risk accepted) and its
  `findings.md` opens with "Since the previous review (date, commit)": counts by severity,
  then the resolved, new and changed findings. Ids in `baseline.accepted` render as "Risk
  accepted", never as resolved, and the comparison's tools table gains a "Since the previous
  review" trend column. The baseline is snapshotted into `analysis/baseline.json`, so later
  runs keep comparing with it; a baseline of another findings schema version is refused
  (exit 2). No model calls: only `render` and `render_comparison` rerun. Without a baseline
  the documents are unchanged (UNVAR-40).
- A partly fixed grouped scanner finding no longer shows as one resolved plus a new finding of
  the same severity. Oversized files and functions, hardcoded values of one kind, TODO
  density and swallowed errors match the previous review's by scanner and rule, whatever
  their count, title ("Oversized file" or "files") or first path, and show as "changed" with
  "count 2 → 1" when the count moved; removing one of two hardcoded URLs is now credited
  instead of reading as persistent. The scanners tag these findings `group:<rule>` and
  `count:<n>`; baselines written before the tags still match, by scanner and title.
  `delta.json` entries gain optional `group`, `previous_count` and `count` fields and the
  `group` match. A change to the matching now re-renders a resumed run's delta on its own
  (UNVAR-49).

### Remediation effort

- Every finding can carry a remediation-effort band, S (up to half a day), M (up to two
  days), L (up to a week) or XL (weeks), with a one-line `effort_note`. Scanner findings get
  a fixed band per rule (rotate a credential S, split an oversized function M, add a test
  suite XL; the table is in `docs/decisions.md`), which `scanners.<name>.effort.<rule>`
  replaces. Extraction and both rollups ask the model for a band and a reason; the verifier
  may change it on the findings it checks. A finding without one shows "not estimated".
  `findings.md` gains an effort badge on every finding and a "Remediation outlook" table
  (findings by band and severity); the comparison risk table gains a "Cost to fix (effort
  bands)" row, which also reaches the consolidation prompt as a fact. Setting
  `report.effort_days` (for example `{S: 0.5, M: 2, L: 5, XL: 15}`) adds an engineer-day
  range labelled as an estimate to both documents; days are off until it is set, and the
  bands always show. Every total is counted from the findings JSON, never by a model. The
  extract, module rollup, tool rollup, verify and compare prompt versions are bumped, so
  those phases rerun once; ask and prose keep theirs. The band table is in the scan's inputs
  hash, so the scan reruns once too. Older artifacts load unchanged, with every finding "not
  estimated" until those phases rerun (UNVAR-42).

### Site

- `site/` holds unvarnish.com: a static writeup (what Unvarnish finds, who it is for, how it
  works, how to run it, licence) and a demo page with a real scanner-only run on OWASP
  NodeGoat and the findings document it wrote, in Markdown, HTML and PDF. `vercel.json` sets
  the security headers and CSP and skips deploys that don't touch `site/`;
  `tests/test_site.py` checks links, metadata, headers and the demo's numbers. Not deployed:
  the owner steps are in `site/README.md` (UNVAR-38).
- The site lists all ten scanners (it said eight, without `client_exposure` and
  `end_of_life`), mentions the SARIF and CSV findings exports and the re-audit delta
  (`run --baseline`), and the NodeGoat demo is re-recorded on 2026-11-14 with osv-scanner
  2.7.1 and an end-of-life bundle, so its report now shows the remediation outlook and the
  end-of-life and client-exposure rows: 164 findings, 34 critical. `tests/test_site.py`
  fails when the scanner table differs from `load_scanners()` (UNVAR-55).

### Development

- A `.gitleaksignore` lists the 17 gitleaks findings in the repository's history, all test
  fixtures for the secrets scanner (and one copy in a plan document) that the owner confirmed
  fake, so `gitleaks git .` on the repo reports 0 leaks and a real one can't hide among them
  (UNVAR-14).
- CI and the verify command install with `uv sync --locked --all-groups`, so a
  `pyproject.toml` change that skips `uv.lock` fails CI instead of re-resolving silently and
  testing dependencies no release installs (UNVAR-20).
- `uv run pytest -q` now measures branch coverage of `src/unvarnish` and fails below a floor
  of 94% (measured 94.2%), so CI blocks a change that quietly drops tests. Partial runs take
  `--no-cov`; `docs/operations.md` says how to raise the floor (UNVAR-10).

- Unvarnish now supports Python 3.13 only: CI installs 3.13, the image is built on
  `python:3.13-slim-trixie`, `requires-python` is `>=3.13`, and ruff targets `py313`; the
  README, CONTRIBUTING and the unvarnish.com install note say 3.13+.
  Every locked dependency already shipped cp313 wheels (amd64 and arm64), so no version
  moved; `tree-sitter` stays `<0.26` (0.25.2 resolved). Dependabot no longer proposes a new
  Python line on the image by itself, which is how a lone 3.13 image bump (#35) was opened
  (UNVAR-27).
- Dependabot no longer widens the `tree-sitter` cap to take 0.26.0, which segfaults and
  crashed CI in the weekly minor-and-patch group (#75, #82): the `uv` entry ignores that
  version. Later 0.26.x releases still arrive in the group and CI says whether the crash is
  gone; 0.26.1 (released 2026-11-09) is the first, so the next group PR may still carry it.
  A hygiene test keeps the ignore in place while `pyproject.toml` caps tree-sitter below 0.26
  (UNVAR-46).

### Performance

- The inventory walks each syntax tree once instead of three times: one tree-cursor pass
  counts functions, the deepest nesting and comment lines, and matches node kinds by integer
  id rather than building each node's type string. On a synthetic 375-file JavaScript tool
  (144,000 lines, 14 MB, 8.6 million nodes) the inventory phase went from about 18 s to 7 s,
  of which 3.7 s is now parsing; the walks alone went from 13 s to 3 s. On the ticket's
  600,000-line tool the walks were 201 s of a 205 s inventory. `metrics.json` is unchanged:
  a test compares the single walk with the three old walks across 18 languages and every
  Python file in `src/` (UNVAR-54).

### Fixes

- PDF exports are tagged (PDF/UA-1): weasyprint writes the structure tree and marks the file
  as tagged, so screen readers can follow headings, lists and tables instead of one flat run
  of text, and client accessibility policies that require tagged PDFs are met. Links stay
  clickable: weasyprint before 66.0 hid every link annotation in a tagged file, so the Docker
  image now installs weasyprint 70.0 from PyPI (pinned with hashes in `docker/weasyprint.txt`,
  in its own venv) instead of Debian's 62.3, and `unvarnish export` checks the installed
  version. With a weasyprint older than 66.0, or one whose version it can't read, PDFs are
  still exported, untagged, with a warning that names the version and how to upgrade
  (UNVAR-22).
- A typo in `engagement.yaml`, the user config or a `tools/<name>/tool.yaml` no longer prints
  a 70-line traceback. Every command prints one `error:` line per problem, naming the file and
  the dotted key with the value given (`error: engagement.yaml: pipeline.concurrency: Input
  should be a valid integer, ... (got 'zero')`), or the line and column of a YAML syntax
  error, and exits 2; a file that is not UTF-8 (UTF-16 from Notepad or PowerShell) or cannot
  be read is one such line too. The value is cut to 60 characters, and any API key or token
  the secrets scanner recognises is redacted from every error and unknown-setting line. An
  invalid `tool.yaml` stops `status`, `run`, `export` and `ask` before
  any work. `config check` also reports a built-in scanner option of the wrong type
  (`scanners.oversized_files.file_lines: expected a whole number (got 'lots')`), which loading
  accepts because scanner options are free-form and which made `run` record that scanner as
  failed on every run (UNVAR-50).
- The end-of-life check reads the other common ways a Python, Node or Ruby version is
  declared: Poetry's `[tool.poetry.dependencies] python`, the Pipfile's `[requires]`
  `python_version` or `python_full_version`, `python_requires` in `setup.cfg` and (as a
  literal only; it is never run) `setup.py`, `.tool-versions` (`python`, `nodejs`, `ruby`),
  the Gemfile's `ruby` (not when it names another `engine`), and an `.nvmrc`
  `lts/<codename>` such as `lts/fermium` (or `.tool-versions` `lts-fermium`), resolved
  through a table of Node.js LTS codenames, since endoflife.date carries none. A tool on
  Python 3.6 declared through Poetry or a Pipfile got no end-of-life finding and no note.
  Ranges such as Poetry's `^3.7` are judged by their lowest version, as `requires-python`
  is; `lts/*` and unknown codenames are still skipped. Existing engagements pick up the new
  declarations on the next fresh scan (`run --force` or a changed input), because the scan's
  inputs hash does not cover scanner code (UNVAR-52).
- Error and status messages no longer lose text in square brackets. Exception and user text
  went to Rich markup unescaped, so `unvarnish add "Bad Name"` printed
  `must match ^{0,63}$` instead of `^[a-z0-9][a-z0-9_-]{0,63}$`. Every interpolated value in
  the CLI's messages and table cells (export failure details, `config check` backend errors and
  model names, `scanners list` options, `cost` rows, log paths) is now escaped; the intentional
  colour markup is unchanged (UNVAR-53).
- Repeating `run --baseline .` (or the tool's own folder, or an artifact inside it) no longer
  wipes the re-audit comparison. The second run snapshotted the findings the first had just
  written, so the delta collapsed to "nothing changed" with no warning. A baseline taken
  from the tool's own folder now keeps the stored `analysis/baseline.json` and says so; delete
  that file to take a new one. A baseline in another folder still replaces it (UNVAR-48).
- Changing `report.detail_from` re-renders the documents. The render phase's inputs hash left it
  out, so `run` reported "render skipped fresh" and `findings.md` kept the old detail level.
  It is now a render input; no model phase reruns (UNVAR-51).
- On native Windows the CLI says it does not run there and to use the Docker image, and exits
  2, instead of failing with an ImportError for `fcntl`. The README and operations guide say
  native Windows is unsupported (UNVAR-35).
- Touching a source file without changing it (`touch`, `git checkout`, a re-clone) reruns
  only the inventory. Freshness hashed whole artifact files, whose `produced_at` changes on
  every write, so an inventory rerun with identical results made every later phase rerun and
  rewrite its artifacts and documents; with `cache/responses` cleared or missing, that
  re-spent the tool rollup, verification and prose. Freshness now hashes an artifact's data,
  schema version and recorded inputs hash, leaving out the write time and the inventory's
  file timestamps, and the census records a content digest of the tree so a same-size edit
  still reruns the scan, the split and the analysis of the edited code. Engagements from an earlier version rerun the inventory and
  every phase after it once after upgrading, answered from the unit, module and response
  caches (UNVAR-34).
- With a unit that fails on every run, switching the extract effort away and back no longer
  leaves the rollups, verification and documents on the other effort's extractions. The
  extract state records `units_digest`, a digest of each done unit's id and inputs hash
  (backend, model, effort, prompt version and source), and of the inputs hash recorded by any
  artifact a failed unit still has on disk, so any change to what the units were
  extracted with changes the state the rollups hash, even while the phase is incomplete and
  records no inputs hash of its own. An older state loads with an empty digest; where a unit
  is still failing, the first run after upgrading reruns the rollups once (UNVAR-47).
- The README's opening says what Unvarnish does today instead of "Slices 1 to 6 are in"
  next to a sentence saying slice 7 had shipped; a hygiene test keeps slice numbering out of
  it (UNVAR-25).
- Tree-sitter analysis no longer disappears silently when GitHub is unreachable. The language
  pack (1.x) downloads its grammars from GitHub releases on first use, so air-gapped runs, the
  Docker image under `--network none` and CI during a release-asset outage fell back to line
  counts without saying so: no function spans, no "Longest source function", no "Very large
  function" finding, coarser units. Now `unvarnish grammars fetch` downloads the 43 grammars
  the census can use, with retries and backoff, and `unvarnish grammars status` lists what is
  on disk without downloading. The Docker image fetches them at build time into
  `/opt/tree-sitter` (readable by any `--user`), so the site kit carries them and checks them;
  CI caches them and fetches before the tests. A grammar that still can't be loaded is logged
  once per language, named in the run table ("no tree-sitter grammar for python"), and noted
  under "Not analysed" in the findings document with the file count; once it is on disk, the
  next `unvarnish run` measures again (UNVAR-45).
- `unvarnish config check` now records the tokens its probes spend in the cost ledger, under
  tool `(engagement)` and phase `config-check`: the structured-output check and, with
  `--probe-context`, the long context probe (up to 30,000 tokens per model). They were sent
  but never counted, so `unvarnish cost` understated the spend (UNVAR-33).
- `cost.json` writes from separate processes no longer corrupt the ledger or drop entries: each
  write holds `.unvarnish/cost.lock`. `config check` is now one such writer and does not take
  the engagement lock, so it can run beside a `run` (UNVAR-33).
- Word exports now carry the document's title and the engagement's consultant (or
  "Unvarnish") in their Title and Author properties, which screen readers announce, Word's
  accessibility checker asks for, and document management systems index. Both were empty.
  The body is unchanged: no extra title line appears above the heading (UNVAR-21).
- Links in HTML and PDF exports are underlined, on screen and in print, in the bundled style
  and in `branding/bonham/report.css`. They differed from body text by colour alone on
  screen (WCAG 1.4.1) and not at all in print, where they turn to the text colour
  (UNVAR-23). A branded copy made from the old style keeps `text-decoration: none` until it
  is updated.
- The "Hardcoded URLs" finding no longer lists a project's own homepage, repository, issue
  tracker or funding links: `[project.urls]` and the Poetry equivalents in `pyproject.toml`,
  `homepage`/`repository`/`bugs`/`funding` in `package.json`, the `Cargo.toml` `[package]`
  and `setup.cfg` `[metadata]` URL keys, and Markdown and YAML files under
  `.github/ISSUE_TEMPLATE/`. Endpoints in code, private package indexes
  (`[[tool.uv.index]]`), and other sections of the same files are still reported (UNVAR-24).
- A unit or module whose model call failed is retried by the next plain `unvarnish run`, as
  `docs/operations.md` already promised. `extract` and `rollup_modules` wrote their full
  inputs hash even when items failed, so the rerun skipped every phase as fresh and only
  `--force` retried them. They now stay stale while they have failures, the way a
  budget-stopped run does, and while `failures.json` holds entries for them, so an existing
  engagement heals too; done units and modules are kept by their own hashes, so the
  rerun calls the model only for the failed items, and a success clears the entry in
  `failures.json` and refreshes the later phases. The run table says "N failed; rerun to
  retry" (UNVAR-29).
- `ask` can no longer hang on a slow regex. `grep_source` runs the model's pattern with the
  `regex` package and stops after `ask.grep_timeout_s` (default 5 s) in total, returning
  "pattern too slow; simplify it" with the matches found so far. The pattern comes from the
  model, which text in the analysed code can steer (UNVAR-9). A pattern whose repeat counts
  would expand past 20,000 nodes at compile time (`regex` writes each minimum out, so
  `a{4294967294}` would exhaust memory) is refused with "pattern too large; use smaller
  repeat counts".
- `unvarnish add --repo <local path>` no longer copies untracked dependency and build
  directories such as `.venv`, `node_modules`, `__pycache__` and `dist`, which the inventory
  excluded anyway: adding this repository's own checkout copied 9,500 files, 9,072 of them
  `.venv`. "Files analysed / total" no longer counts them, and "Not analysed" names them.
  Tracked ones (a committed `vendor/`) and other gitignored files (`.env`) are still copied
  and scanned; URL clones are unchanged (UNVAR-8).
- HTML, PDF and Word exports declare their language (`lang="en"`, or `report.lang` from the
  engagement config), so screen readers stop guessing it (WCAG 2.1 SC 3.1.1). Diagram images
  get a sentence as alt text, such as "Module map: how the files depend on each other",
  instead of the internal name `modules`; Word exports carry the same text (UNVAR-7).
- The secrets scanner no longer reports tool caches as leaks. A linked checkout's
  `.pytest_cache/v/cache/nodeids` gave 20 critical "GitHub token" findings from test
  parameters while "Not analysed" listed the same files as excluded: pytest's own
  `.gitignore` in the cache made the census record them as gitignored. The working-tree pass
  now skips every path under a tool cache (`.pytest_cache`, `__pycache__`, `.mypy_cache`,
  `.ruff_cache`, `.gradle`, `.parcel-cache`, `.angular`), whatever its exclusion reason. Build
  output such as `dist/` or `.next/` is still scanned, because a key baked into a shipped
  bundle is a live leak, and so are other gitignored text files, such as a `.env`. A secret
  found in one that git does not track is noted "gitignored: present in the ingested copy, not
  in the repository"; a file committed before it was ignored gets no such note, and in a copy
  without git the note says only that the file matches a `.gitignore` rule. "Not analysed"
  says the secrets scanner still read gitignored files, except tool caches, vendored
  directories and files over 5 MB (UNVAR-18).
- The Docker image pins its base image and the gitleaks, osv-scanner and uv images by digest
  (`tag@sha256:...`), so a rebuild or site kit cannot pull different binaries under a moved
  tag. The tool images are now named stages, because Dependabot reads only `FROM` lines and
  never bumped the `COPY --from` images; it now bumps tag and digest for all four.
  `docs/operations.md` says how to refresh the pins (UNVAR-19).
- A tool whose `tools/<name>/tool.yaml` is gone (for example its folder was deleted to drop
  it) no longer crashes `status` and `run` with a traceback. `status` shows a row saying
  "missing: tool.yaml not found; remove it from engagement.yaml or add it again" and exits 0.
  `run` reports each missing tool in one line, still runs the others, names the missing ones in
  its summary and exits 2 because a named tool could not run; `export` and `ask` report the
  same line and exit 2 when a tool they would cover is missing (`run <tool>`, `export <tool>`
  and `ask --tool <tool>` on a present tool are not blocked by another, missing one) (UNVAR-17).
- `unvarnish run <tool> --phase <name>` on a tool whose earlier phases have not run reports
  which one to run first ("needs inventory; run `unvarnish run demo` or `--phase inventory`
  first") instead of a bare `FileNotFoundError`. The phase is still recorded as failed, so the
  run exits non-zero (UNVAR-5).
- Adding a tool no longer runs the vetted repository's git hooks, `core.fsmonitor` command,
  `core.sshCommand` or `ext::` transports, and its `core.worktree` can no longer make
  `add --repo <path> --branch` write files outside the tool's folder. Every git child,
  Unvarnish's own and gitleaks', runs with `core.hooksPath` set to an empty directory,
  `core.fsmonitor=false` and `protocol.ext.allow=never`; the checkout passes `--work-tree`;
  `core.sshCommand` comes from the operator's global and system config only. The override
  is per subprocess, so the operator's own hooks are untouched (UNVAR-15).
- A local repository's own filter and diff drivers no longer run on the consultant's machine.
  A `filter.<name>.smudge`, `.clean` or `.process` command named by the repo's config used to
  run during the checkout of `add --repo <path> --branch`, and a `diff.<name>.textconv`
  command during gitleaks' history scan (`--repo` and `--link`). Before each git call,
  Unvarnish reads the driver names from the repo's own config files and every file they
  include, whatever the include's condition, and disarms them for that call and for
  gitleaks: filter commands are emptied (`required=false`), textconv becomes `cat`. Files in
  such a repo are analysed as committed, without the filter's conversion. Git never recurses
  into submodules (whose own config can name drivers), never checks signatures, and a repo
  whose config can't be read in time is refused rather than run with its drivers armed (UNVAR-26).
- Adding a linked worktree or a submodule checkout with `add --repo <path>` no longer works on
  the client's real git directory. Its `.git` file was copied as the pointer it is, so
  `--branch` moved the HEAD and index of the client's own worktree; the copy now gets a real
  `.git` (the shared directory plus the worktree's HEAD and index), and a copied
  `core.worktree` is removed (UNVAR-26).
- Two `run`, `compare` or `ask` commands can no longer work one engagement at once. Before,
  a scheduled run and a manual one (or two `docker run` containers on one mount) each
  enforced `budget.max_tokens` on its own, so together they could spend twice the cap on the
  same units, and they rewrote `cost.json` over each other, so `unvarnish cost` lost entries.
  These commands now hold `.unvarnish/run.lock` in the engagement; a second one exits 2 naming
  the holder's PID, host and start time. A lock left by a process that died is taken over
  with a warning: at once on the same machine or Docker host (also after the machine
  restarted), and after `pipeline.lock_stale_minutes` (default 10) without a heartbeat when
  the holder was on another machine. `status`, `cost`, `export` and `run --dry-run` don't take it (UNVAR-6).
- Ctrl-C stops `unvarnish run`. Before, the interrupt reached only the main thread, and every
  phase of every tool kept running and spending (46 model calls after Ctrl-C in the repro).
  Now no new model call starts, the calls in flight finish and are recorded, the run prints
  "interrupted; rerun `unvarnish run` to resume" and exits 130, and the interrupted phases
  stay stale so the next run resumes them (UNVAR-16).
- A phase that crashes writes an ERROR line naming the tool and phase, with the full
  traceback (secrets redacted), to the run log; before, the log stayed empty. The console keeps
  its one-line summary unless `--verbose` (UNVAR-4).
- HTML, PDF, and Word exports show raw HTML in model-written or scanned text as text: a
  quoted `<script>` or `<img onerror=…>` is inert, and `List<String>` keeps its `<String>`
  (UNVAR-2). Stray diagram markers are dropped before export.
- Exports no longer follow images or script links in model-written or scanned text. A
  Markdown image shows its alt text instead of being read from disk or fetched, so a finding
  cannot embed a file from the consultant's machine; only the rendered diagrams embed. Links
  other than `http`, `https`, `mailto` and in-document anchors (`javascript:`, `data:`,
  `file:` and the rest) show as text (UNVAR-12).
- The secret scanner no longer reports vendor-documented sample keys (AWS's
  `AKIAIOSFODNN7EXAMPLE`, any value containing `EXAMPLE`) or private-key blocks whose body is
  a placeholder such as `MIIE...`, in the tree or in history (UNVAR-3).
- `run --dry-run` after a source edit lists every phase the edit reaches, not only
  inventory, so the token estimate shows before the spend. A phase is planned when it is
  stale or a phase whose artifacts it reads is planned; each phase declares those in
  `depends_on`, and a test checks them against what its inputs hash reads (`git` reads the
  repository's history, so a working-tree edit leaves it fresh). The extract estimate counts
  the units whose source, model or prompt changed ("1 of 16 units new or changed"), from a
  split of the current source computed in memory when split would rerun; before, it counted
  units with no artifact, and printed "run split first" until split had run. A dry run on a
  fresh engagement still lists nothing (UNVAR-30).
- A file committed despite a `.gitignore` rule (`git add -f config.json`) is analysed again:
  the census read only the `.gitignore` patterns, so every scanner, the split and the model
  phases skipped committed, shipped code. Git never ignores a tracked file, and now neither
  does the census for a `--repo` or `--link` tool with its own `.git`. The census lists such
  files in `tracked_despite_gitignore`, and the findings document names them under "Not
  analysed". A tracked file under `build/` or `node_modules/` is still excluded as build
  output or vendored code, and `--files` piles keep the `.gitignore` rules as written
  (UNVAR-28).
- An unexpected error in an `extract` worker (a module file deleted after split, a full disk
  while writing a unit) no longer leaves `extract` fresh with units undone. The exception
  failed the phase, yet extract-state was written with its full inputs hash, so the phase
  counted as fresh at "0/2 units" and a plain rerun skipped it; only `--force` retried it.
  The error is now recorded in `failures.json` for that module, the other modules are still
  extracted, the run table says "1 failed; rerun to retry", and the next plain `run` retries
  it. Extract-state never records a fresh hash while units are left undone (UNVAR-32).
- A tool whose source directory is gone, a `--link` folder moved or deleted after `add` or a
  copied `tools/<name>/source` removed by hand, is no longer analysed as an empty tool. The
  inventory said "ok, 0 files", and render overwrote the tool's documents with "Files
  analysed / total | 0 / 0". Inventory now fails with "source directory <path> does not
  exist (linked tool; re-add or restore it)", every later phase is skipped, so nothing under
  `docs/` is rewritten, and `status` shows the same reason on the inventory row. A single
  phase that reads the source (`run --phase scan --force`, and git, split, extract or
  verify) fails the same way instead of rewriting its artifact from nothing, while
  `--phase render` still renders from the saved analysis; `ask`'s source search reports
  the missing folder instead of finding no matches (UNVAR-31).

### On-prem simulation through OpenRouter

Found by running plan and headless-artist against `qwen/qwen3-coder-30b-a3b-instruct` on
OpenRouter, capped at a 32k window to stand in for a single-GPU on-prem server.

- `max_tokens` is fitted to the context window on OpenAI-compatible servers; a 32k server was
  sent a 32k output budget and refused every request with a 400.
- Unquoted keys and trailing commas are repaired locally before a retry call; a provider that
  ignored the schema had failed 35 of 103 units with `qwen-2.5-coder-32b`.
- `backends.<name>.extra_body` is sent with every request (OpenRouter provider routing, vLLM
  guided decoding).
- `config check` probes the live server, not the response cache; a cached probe passed while
  every real request would have been refused.
- The executive summary no longer invents a purpose when the tool rollup failed.
- An evidence excerpt that is not in the cited file moves to the evidence note, so the report
  never prints a model's description as if it were the code (68 of 110 on headless-artist with
  qwen3, 20 of 86 with Sonnet).
- A redacted excerpt (`sk-p…[redacted 38 chars]`) counts as verbatim, the redaction marker
  standing in like an elision; every hardcoded-secret quote had been demoted to a note.
- A credential finding whose cited value is a placeholder (`Bearer REPLACE_ME`) is rejected
  without a model call; qwen3 had confirmed one as critical.
- The placeholder check reads values conservatively: an apostrophe in a comment, a ternary's
  first branch, a backslash, a backtick template, an unquoted `.env` value, or a truncated
  excerpt can no longer hide a real credential behind a `REPLACE_ME` beside it, and only a
  claim that the credential is in the source is judged by its literals.
- The verify phase's inputs hash carries a logic version, so a verify artifact from before
  grounding and placeholder rejection is rerun instead of being taken as fresh.

### Branding, parallel runs, and the known-issues burn-down

- A neutral, print-ready export style (HTML, PDF, and Word): Inter with offline fallbacks,
  ruled tables with repeating headers, a running title, "Confidential", and page numbers.
  `branding/bonham/` is an editable copy with a guide; `scripts/build-reference-docx.py`
  rebuilds the Word style. The image installs Inter and Liberation fonts.
- Tools in an engagement run in parallel (`pipeline.parallel_tools`, default 4);
  `pipeline.concurrency` now caps model calls across all of them.
- Every entry in known-issues was fixed or decided (66 fixes). Highlights: nested
  `.gitignore` files, rename-aware churn, per-key fingerprints, linear hostname search,
  severity breakdown of vulnerabilities, unknown-setting warnings, a 1M context for Anthropic,
  module rollups trimmed to the context window, truncated prose retried, model text redacted
  before storage, `config check --probe-context`, `max_completion_tokens` support, comparison
  crashes recorded and failed proposals retried, ask-mode fixes, unique export names, and a
  warning when the Docker engagement folder is not mounted.

### Comparison validation and site kit

- Consultant constraints (`consolidation:` in engagement.yaml: target platform, approved
  stack, must-keep and retire lists, notes) shape the consolidation proposal; comparison.md
  lists them and every conflict with what the tools do (spec §17).
- Air-gapped site kit: `scripts/site-kit.sh` builds an image with dated offline advisory
  databases for eight ecosystems, saved with checksums, a runbook, and an on-prem example.
  Reports state the database date. uv is pinned in the image.
- Verification reads windows around matching lines in large cited files, so tool-level claims
  on big files are checked instead of left unverified.
- Prose that misstates severity counts is retried once with the facts.
- Dry-run estimates price cached system prompts and skip derived module rollups.
- Packages with no registry source no longer make an ecosystem look unchecked.
- The comparison groups stores and systems that tools name differently, and leaves in-process
  state out of the integration map. On ESCAPESUITE's four tools it now shows the one IndexedDB
  database three tools share, which appeared before as seven unrelated stores.
- A refused model request is retried once, then sent to `models.refusal_fallback` if set.
  Opus refused the capability normalisation for ESCAPESUITE's tools ("cyber") once; without it
  nothing grouped across tools.
- The comparison's tools table shows one sentence of each tool's purpose.

### Release-candidate validation

Found by running the finished pipeline on ESCAPESUITE and air-gapped against a local
`qwen2.5:14b` served by Ollama.

- A request that times out fails that unit and the run continues; before, one slow unit on
  on-prem hardware aborted extraction with exit 2 after four ten-minute attempts.
  `backends.<name>.timeout_s` sets the limit (OpenAI-compatible default 30 minutes); timeouts
  are not retried; dropped connections and server errors are retried with backoff.
- Committed build output is excluded: `dist-*` variants, Playwright reports, test results,
  `storybook-static`, `htmlcov`, and framework caches. On ESCAPESUITE that removed 115 units
  and about a million extract tokens.
- Ignore files, licences, `robots.txt`, `sitemap.xml`, and editor or version pins are not sent
  to the model.
- Oversized files and functions are one finding per severity, locations listed longest first,
  instead of one finding each (ESCAPESUITE's findings.md had 63 identical sections). Long test
  blocks are no longer reported as oversized functions.
- gitleaks findings have short titles ("Generic API key (gitleaks)"); its description sentence
  moves to the summary.
- Extractions drop "None" and "N/A" placeholder entries, and the extract prompt rules out
  reporting strengths as findings.
- `config check` passes any schema-valid probe reply, and also probes the default model used by
  phases without an override.
- The token budget counts cache reads at a tenth, as they are billed; ESCAPESUITE hit a
  16-million cap with 7.3 million of it cache reads.
- Shell and REPL history files (`.Rhistory`, `.bash_history`) are not sent to the model.
- findings.md stays readable at scale: low and info findings are one table row each
  (`report.detail_from`, default `medium`), with full detail in `findings.json` and `ask`.
  ESCAPESUITE's findings.md went from 35,276 lines to 5,045.
- A file with one unit is rolled up from that unit without a model call
  (`pipeline.rollup_single_unit_modules: true` restores the call). On ESCAPESUITE this skips
  912 of 1,048 Opus calls (about $13) and 1,009 restated low findings.
- Tool-level findings that cite whole files are verified against those files when they are
  small, instead of being left unverified.
- Reworded duplicate findings and entry points from different tool-rollup chunks are merged.
- "By the numbers" ranks source files, not tests, for largest file and longest function.
- `export --format` can be repeated.
- `budget.prices` accepts one price per model id and optional cache read and write rates, so
  `cost` and dry-run estimates are right when phases use different models.

### Slice 7: remaining scanners and hardening

- `dependencies` scanner: advisories from `osv-scanner` (offline by default, run during
  inventory, "not checked (reason)" when unavailable) and unpinned dependencies without a
  lockfile.
- `hardcoded_infra` scanner: URLs, internal hostnames, IPs, absolute paths, and emails, with
  credentials masked; a "Hardcoded infrastructure" row in findings.md and a "Hardcoded in
  source" table in architecture.md.
- `vendored_bulk` (dependency or build directories, large binaries) and `generated_bulk` (bulk
  commits, noting AI co-author trailers) scanners.
- The secrets scanner adds gitleaks results its own rules missed when gitleaks is installed,
  always with `--redact`.
- Hardening: git never prompts for credentials on unattended runs; every model prompt treats
  its input as data, never instructions; files over 5 MB are listed as not analysed; all text
  I/O is UTF-8.
- Docker image bundles gitleaks 8.30.1 and osv-scanner 2.7.0, with optional offline advisory
  database seeding (`--build-arg OSV_ECOSYSTEMS="PyPI npm"`).
- Final-review fixes:
  - Hardcoded URLs never carry credentials, query strings, webhook paths, or token-like path
    segments, in values, excerpts, summaries, or the architecture table. Unpinned-dependency
    notes are scrubbed the same way.
  - Offline osv-scanner runs use `--offline`, which also stops transitive resolution through
    deps.dev. An ecosystem without an offline database is reported as "not checked" beside the
    count instead of looking clean. "No package sources" counts as checked.
  - A vetted repo can no longer switch off the scanners: osv-scanner gets an empty `--config`,
    gitleaks gets a config that extends its default rules and `--ignore-gitleaks-allow`. A new
    "Scanner suppression files in the source" finding lists `.gitleaksignore` and similar files.
  - Fewer `hardcoded_infra` false positives: imports and namespaces, attribute calls, package
    versions, image names, netmasks, user agents, templated URLs, schema and documentation
    URLs, ignore files, container paths, and URL paths in web code.
  - git keeps the user's `GIT_SSH`, `core.sshCommand`, and `GIT_ASKPASS` helper and only adds
    `BatchMode`.
  - Evidence bullets in findings.md and rows of the comparison risk table each render on their
    own line (the risk table had rendered as one line since slice 4).
  - Pinning understands Poetry bare versions, npm `=`, aliases, git SHAs, `workspace:` and
    `file:`, Cargo and Poetry path, workspace, and git tables, and BOM-managed Maven versions.
    `pom.xml` is parsed one dependency at a time.
  - The image build fails if an OSV database download fails.

### Slice 6: export and distribution (PR #9)

- `unvarnish export [--format docx|html|pdf|all] [--template PATH] [--doc ...] [TOOL ...]`
  writes `exports/<doc>-<tool>-<timestamp>.<ext>` with pandoc: DOCX with a reference document,
  self-contained HTML with embedded CSS and inlined SVG, PDF through weasyprint.
- Diagrams rendered by Graphviz from the same model as the Mermaid in the Markdown; render
  phases save `docs/diagrams.json` and mark each Mermaid fence.
- Toolchain pre-flight (missing tools, pandoc older than 2.19, missing branding files, wrong
  template type) exits 2 before anything is written; dropped PDF images fail loudly.
- Dockerfile (`python:3.12-slim-trixie`, git, pandoc, Graphviz, weasyprint; non-root friendly),
  PyPI metadata, CI installs the toolchain and runs `uv build`.
- Every command refuses an engagement written by a newer `schema_version`.

### Slice 5: ask mode (PR #8)

- `unvarnish ask ["QUESTION"] [--tool NAME]`: one question or an interactive session.
- Pure-Python BM25 index over units, modules, tool models, capabilities, and findings, built
  lazily under `cache/index/` and rebuilt when the analysis changes.
- Five read-only tools (search, unit, module, tool model, findings, source grep) with exclusions,
  caps, and secret redaction; bounded loop with a structured action schema; citations validated
  against real ids and paths; uncited answers marked unverified; context-window guard.
- Sessions saved to `ask-sessions/<timestamp>.md`.

### Live smoke fixes (PR #7)

- Strict schemas no longer strip a field *named* `title` (every candidate finding was failing).
- Structured calls fall back to JSON-in-prompt when the API rejects a schema as too large.

### Slice 4: cross-tool comparison (PRs #5, #6)

- `unvarnish compare [--force]`: capability matrix (one normalisation call), integration and
  data map and risk table (pure joins), consolidation proposal for two or more tools (one call),
  rendered to `comparison/comparison.md`.

### Slice 3: rollups, verification, full documents (PRs #3, #4)

- `rollup_modules`, `rollup_tool` (directory chunking for large tools), and `verify`
  (deduplication and evidence-only verification of high and critical model findings).
- `architecture.md`, `findings.md`, `requirements.md` with model-written prose blocks, tone
  setting, Mermaid diagrams, and template overrides.

### Slice 2: model layer and extraction (PR #2)

- Anthropic and OpenAI-compatible backends, content-addressed response cache, structured output
  with retry and repair, per-run token budget, cost ledger, run logs.
- `split` (structural, HTML streams, windows) and `extract` phases; `config check`, `cost`,
  `cache clear`, `run --dry-run`.

### Slice 1: deterministic core (PR #1)

- CLI, engagement workspace, ingest (repo, files, link), inventory, git history statistics, and
  the `secrets`, `oversized_files`, `hygiene`, `bus_factor` scanners.
- `findings.md` rendered from scanner findings alone.
