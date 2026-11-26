# Operations

Practical notes for running Unvarnish on an engagement, from the live runs so far.

## Before the first engagement on a machine

1. `unvarnish config check` probes every configured backend with the real extraction schema.
   It also reports unknown keys and built-in scanner options of the wrong type; any command
   names an invalid value in `engagement.yaml` or a `tool.yaml` by file and dotted key and
   exits 2.
2. Run `scripts/smoke.sh` with a real key once per machine and model. It ingests two small tools,
   runs every phase, compares, asks one question, and exports HTML. Two bugs that the offline
   suite could not see were found this way (see `docs/decisions.md`, live smoke test).
3. For document exports, `pandoc` 2.19 or later, Graphviz `dot`, and `weasyprint` (PDF only)
   must be on PATH, or use the Docker image (SARIF and CSV exports need none of them).
   `apt install pandoc` on Ubuntu 22.04 or Debian 12 is too old; `unvarnish export` says so
   and exits 2. For tagged (PDF/UA-1) PDFs, weasyprint must be 66.0 or later (tested with
   70.0, the image's): `pip install 'weasyprint>=66'` or `brew install weasyprint`. Debian's
   (62.3) and Ubuntu 24.04's (61) packages are older, and their tagged PDFs hide every link, so with them `export`
   writes the PDFs untagged and prints a warning that says so.
4. git 2.31 or later (the Docker image has 2.47). gitleaks' own git calls rely on
   `GIT_CONFIG_COUNT` to keep a vetted repo's hooks and its filter and textconv drivers from
   running, and older git ignores it.
5. A local repo's own filter drivers never run, so a repo encrypted with git-crypt, or one
   whose LFS filter is set in its own `.git/config` (`git lfs install --local`), is analysed
   as stored in git: ciphertext or LFS pointer files. Decrypt or `git lfs pull` into a plain
   folder and add that with `--files` when those files matter. LFS set up in the operator's
   global config still works for clones and `--branch` checkouts.

## Before you travel

Run this on a connected machine before leaving for a site, ideally the day before, with the
engagement folder you will take (or the image you will carry):

1. `unvarnish doctor -e <engagement>` (in the image:
   `docker run --rm --network none -v "$E:/engagement" unvarnish doctor`). It reads only local
   files and `<tool> --version`, never the network, and prints one row each for the tree-sitter
   grammars, the end-of-life bundle, the exploit data bundle, the offline OSV databases, pandoc,
   Graphviz, weasyprint, git, gitleaks and osv-scanner: present, stale, partial, absent,
   unreadable or too old, each data set's date and age against its `max_data_age_days`
   (end-of-life 90 days; exploit data and OSV databases 30, from
   `scanners.dependencies.max_data_age_days`), and the exact command that refreshes or
   installs it. It exits 1 when anything the engagement needs is missing; stale data is shown
   but does not fail it, since a run still uses it with a note. Outside an engagement it
   checks against a new engagement's defaults (`unvarnish init`), so a laptop with no
   weasyprint fails on PDF export even if you only want HTML. `--json` prints the same as JSON.
2. Run every refresh command the table shows for an absent or stale row, then `doctor` again
   until it says "Ready". For the image, rebuild the site kit (`scripts/site-kit.sh`, which runs
   `doctor` in its image check) rather than patching data into it.
3. If the site's model server is reachable from where you are now, `unvarnish doctor -e
   <engagement> --probe-backend` sends one unauthenticated request to each backend the
   engagement's models name (no key, no tokens: any HTTP answer, a 401 included, counts as
   reachable; user info or a query in a `base_url` is dropped, never sent). `unvarnish config check` then tests the key and the model itself.
4. Pack the kit, the engagement folder and this runbook (`docs/site-kit.md`).

## Keys

- Keys come only from the environment variable named in `api_key_env` or the OS keychain
  (`api_key_keychain`). Unvarnish never writes them to the engagement, the cache, or logs.
- Pass keys to Docker with `-e ANTHROPIC_API_KEY`; never bake them into an image.
- Rotate any key that was pasted into a chat, a ticket, or a shared terminal.

## Cost and time

| Run | Size | Result |
|---|---|---|
| Live smoke, Opus 5.5 at low effort | two small tools (14 units) | all phases ok, about 213,000 tokens |
| Scale rehearsal, fake backend | ESCAPESUITE: 1,034 files, 1,487 units | full pipeline in about 60 s, 2,534 model requests, tool rollup in 7 chunks |
| ESCAPESUITE on Anthropic (extract Sonnet 5.5, rest Opus 5.5, low effort) | 1,402 units, 1,048 modules | about 40 minutes; about $48 with a model call per module, about $35 with one-unit modules derived |
| ESCAPESUITE as four tools plus compare (craft, artist, plan, headless-artist) | 1,124 units | about 25 minutes; $22 |
| OpenRouter as on-prem stand-in, `qwen3-coder-30b-a3b`, 32k window | plan and headless-artist (148 units) | every unit ok; about 14 minutes and 920,000 tokens, about $0.08 |
| Air-gapped, `qwen2.5:14b` on Ollama, 8-core Intel CPU | 45 units, 977 source lines | extract 3.5 hours (4 to 13 minutes a unit); tool rollup 31 minutes; prose about 10 minutes |

Prices are per model, so mixed-model runs cost correctly:

    budget:
      prices:
        claude-opus-5-5: { input_per_mtok: 4, output_per_mtok: 20, cache_read_per_mtok: 0.2 }
        claude-sonnet-5-5: { input_per_mtok: 2, output_per_mtok: 10, cache_read_per_mtok: 0.2 }

Use `unvarnish run --dry-run` for a per-phase token estimate before spending, and set
`budget.max_tokens` for unattended runs; a capped run exits 3 and resumes on the next `run`.
The dry run lists each stale phase and every phase downstream of it, so it may list a phase
the real run then skips because its inputs came out unchanged. Freshness follows content, not
timestamps (UNVAR-34): after a `git checkout`, a re-clone or a `touch` that leaves the files'
content as it was, the dry run lists every phase from the inventory on, while the real run
reruns only the inventory and reports the rest as fresh. The extract estimate prices
only the units whose source changed; the module rollup estimate prices every module that
needs a call, an upper bound after a small edit.
The cap is per run, and cache reads count at a tenth because they are billed at about a tenth
of the input price. ESCAPESUITE (1,402 units) used about 7 million cache-read tokens.

Ctrl-C stops `unvarnish run` and its spending. No new model call starts, including calls
already queued for a slot; the calls in flight finish and are recorded, so a run stops within
about one request's time (on a CPU server, one unit can take minutes). The run then prints
"interrupted; rerun `unvarnish run` to resume" and exits 130. Interrupted phases stay stale,
and the next `run` picks up where this one stopped. A second Ctrl-C while it drains does not
skip the wait.

A unit or module whose model call fails (a timeout, malformed JSON after the repair call, a
refusal that survives the fallback), or whose source file or artifact cannot be read or
written, is recorded in `analysis/failures.json` and the run goes
on; the run table says "N failed; rerun to retry". `extract` and `rollup_modules` then stay
stale, so the next plain `unvarnish run` retries only the failed items: done units and modules
are kept by their own hashes, and a success clears the failure and refreshes the later phases.
A unit that fails every time is re-attempted on every run; `unvarnish status` shows it as
"15/16 units (1 failed)", never as fresh. The later phases rerun after such a retry, but their
requests are unchanged, so the response cache answers them without a model call. Staleness
follows `failures.json`, so an engagement whose failures were recorded by an earlier version is
retried the same way.

The scale rehearsal is repeatable without spending tokens:

    UNVARNISH_SCALE_REPO=/path/to/repo uv run pytest --no-cov tests/test_scale.py -s

### Batch mode (Anthropic)

`batch: true` on an Anthropic backend sends the verify phase and the render prose calls
through the Message Batches API, at half the synchronous price:

    backends:
      anthropic:
        type: anthropic
        api_key_env: ANTHROPIC_API_KEY
        batch: true

Extract and the rollups stay synchronous. A batched phase submits one batch per tool and
phase, checks it every 30 seconds and goes on once it ends, usually within the hour (at most
24 hours). The replies land in the response cache, so the phase then runs as usual; anything
the batch could not answer (errored, expired, refused, unparseable) is sent as an ordinary call
and, if that fails too, recorded in `failures.json`. Ctrl-C while a batch is in progress
leaves its id in `tools/<tool>/analysis/batches/<phase>.json`; the next `run` collects that
batch instead of sending a new one. `cost` lists batch spending as `<phase> (batch)` priced
at the batch rate, and `run --dry-run` prices a batched phase at the same rate.

The provider keeps batch results for 29 days, and batches are not eligible for zero data
retention; `config check` says so for each batch backend. Leave batch mode off for a client
with a zero-retention agreement. `batch: true` on an `openai_compatible` backend is a
configuration error.

## Docker

- Native Windows is unsupported: the engagement lock needs `fcntl`, so the CLI stops at
  start-up with "does not run natively on Windows" and exit code 2. Windows users run the
  image (UNVAR-35).
- The image pins `python:3.13-slim-trixie` because older Debian ships a pandoc too old for
  self-contained HTML.
- On Linux hosts run with `--user "$(id -u):$(id -g)"` so files in the mounted engagement stay
  yours; the image marks every directory as a git `safe.directory` and sets `HOME=/tmp`.
- `docker save unvarnish | gzip > unvarnish.tar.gz` moves the image to an air-gapped site.
- Tools added with `--link` are invisible inside the container; use `--repo` or `--files`.
- CI's `docker` job builds the image and runs it on `tests/data/docker-smoke/` with no
  network, on every push to `main` and on pull requests that change the image's inputs
  (UNVAR-80). A Dependabot bump of a pinned image therefore shows a build failure on its pull
  request; its "Does this change touch the image?" step lists the changed files it looked at.

## Tree-sitter grammars

- Function lengths, nesting, the "Very large function" finding and structural units come from
  tree-sitter. The language pack ships no grammars: it downloads them from GitHub releases
  (`github.com/xberg-io/tree-sitter-language-pack`) the first time a language is parsed, into
  `~/.cache/tree-sitter-language-pack/<version>/libs`, or under
  `$TREE_SITTER_LANGUAGE_PACK_CACHE_DIR` when that is set.
- On a laptop install (`uv tool install`, `uv sync`), run `unvarnish grammars fetch` once while
  online. It downloads every grammar Unvarnish can use, in up to four attempts;
  `--dir <path>` puts them elsewhere (then export `TREE_SITTER_LANGUAGE_PACK_CACHE_DIR=<path>`
  for runs). Rerun it after upgrading Unvarnish, since a new pack version has its own cache.
- `unvarnish grammars status` lists what is on disk without touching the network and exits 1
  when any grammar is missing.
- The Docker image fetches them at build time into `/opt/tree-sitter`, so `--network none`
  and the site kit need nothing more; `scripts/site-kit.sh` checks them in its image check.
- CI caches `~/.cache/tree-sitter-language-pack` and runs `unvarnish grammars fetch` before the
  tests, so a GitHub outage fails that step, by name, instead of fifteen tree-sitter tests.
- A run that can't load a grammar still finishes: the log warns once per language, the run
  table says "no tree-sitter grammar for <language>", and the findings document notes it under
  "Not analysed". After `grammars fetch`, a plain `unvarnish run` measures those files again.

## Dependency advisories

- `osv-scanner` runs during `inventory` when it is on PATH, offline by default. Offline means
  `--offline`: no osv.dev queries and no transitive resolution through deps.dev. Without a
  local database the report says "not checked" with the reason; nothing fails.
- When some ecosystems have a database and others do not, the count shows the gap, for example
  "9 (npm not checked: no offline database)". Seed the missing ecosystem and rerun.
- A seeding build fails if any database download fails, so a successful image has every
  ecosystem it was asked for.
- Unvarnish passes osv-scanner an empty `--config`, so an `osv-scanner.toml` in the client's
  repo cannot hide advisories.
- Installing osv-scanner after a run does not refresh the "not installed" note on its own:
  rerun `unvarnish run --phase inventory --force`.
- Seed the Docker image for the ecosystems you expect:
  `docker build --build-arg OSV_ECOSYSTEMS="PyPI npm Go Maven crates.io" -t unvarnish .`
  On a laptop, `osv-scanner scan source --offline-vulnerabilities --download-offline-databases <dir>`
  fills its cache once while online.
- After refreshing the database, rerun `unvarnish run --phase inventory --force` and
  `unvarnish run`.
- Set `scanners.dependencies.offline: false` to query osv.dev directly where the site allows it.
  Online, osv-scanner also reads each package's licences from deps.dev (`--licenses`, no
  allowlist), and the inventory stores them in `dependencies.json` (UNVAR-93).

## Dependency licences and the SBOM

- Licences are checked only online. Offline (the default) the findings document says
  "licences: not checked (offline mode)" under "Not analysed", and the SBOM lists no licence:
  none is ever guessed. Switching to `offline: false` reruns the inventory once.
- Set the client's accepted licences as SPDX identifiers, matched without regard to case:

      scanners:
        dependencies:
          offline: false
          licences: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]

  An expression is accepted when any `OR` branch and every `AND` part is on the list
  (`MIT OR GPL-3.0` passes with MIT); `X WITH exception` passes when X or the whole of it is
  listed. Each manifest and licence outside the list is one compliance finding: medium when the
  licence cannot be met without a copyleft one (GPL, AGPL, LGPL, MPL, EPL, EUPL, CDDL, OSL,
  SSPL, CC-BY-SA...), low otherwise, and low for a package deps.dev names no licence for. It
  covers every package osv-scanner resolved, transitive ones from a lockfile included; a
  declared dependency it resolved no version for (a range without a lockfile) is named in a
  note, since its licence was not checked. Without the option nothing is flagged and a note
  says so; changing it reruns the scan only, not the inventory's osv-scanner lookup.
- The allowlist never reaches osv-scanner, and osv-scanner always gets Unvarnish's own empty
  `--config`, so an `osv-scanner.toml` in the vetted repository cannot override or ignore a
  package's licence, just as it cannot hide advisories.
- `unvarnish export --format cyclonedx [tool...]` writes `exports/sbom-<tool>-<timestamp>.cdx.json`
  (CycloneDX 1.6, JSON) from `inventory/dependencies.json`, with no osv-scanner call: declared
  dependencies (package URL, exact version or the constraint as `unvarnish:constraint`, the
  manifest as `unvarnish:manifest`, dev dependencies with scope `optional`), online also the
  packages osv-scanner resolved, and each package an advisory names. Advisories are
  `vulnerabilities` with their aliases as references, the severity Unvarnish rated, the KEV and
  EPSS data as properties, and `affects` pointing at the component. The metadata says whether
  licences and advisories were checked. A tool not yet inventoried is skipped. Rerun `export`
  after `run`: the file is a snapshot.

## Exploit data (CISA KEV and EPSS)

- The inventory marks each dependency advisory from one file, `vulndata.gz`, and never touches
  the network during a run. It looks in `$UNVARNISH_VULNDATA_DIR` when that is set, else in
  the end-of-life data folder (`$UNVARNISH_EOL_DIR`, else `$XDG_DATA_HOME/unvarnish/eol`, else
  `~/.local/share/unvarnish/eol`), so one folder or mount holds both bundles (UNVAR-90).
- On a connected laptop, run `unvarnish vulndata refresh` before each engagement. It downloads
  CISA's Known Exploited Vulnerabilities catalog
  (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) and
  FIRST's EPSS scores (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, which
  redirects to the day's dated file; the older host was `epss.cyentia.com`), four attempts
  each with backoff (`--attempts`), checks every line, and writes the bundle atomically with
  today's date; `--dir <path>` writes it elsewhere, and `--kev-url`/`--epss-url` read a
  mirror or a moved feed. If either feed fails it exits 1 naming it and writes nothing, so the
  previous bundle stays as it was. It checks the folder is writable before downloading.
- Then rerun the engagement: the bundle date is in the inventory's inputs hash, so a plain
  `unvarnish run` reruns the inventory, the scan and render; the per-tool model phases stay
  fresh, but in an engagement with more than one tool `compare` reruns and calls the model.
  The hash holds the bundle's date only, so a second refresh on the same day reruns nothing.
- With a bundle, an advisory whose id or aliases include a CVE in the KEV catalog is critical
  and its line in the finding says "Known exploited (CISA KEV, added <date>)"; every advisory
  shows its EPSS score and percentile (its CVEs' highest; "no EPSS score" without a CVE
  alias). EPSS never changes a severity: it orders advisories within a finding and findings
  within a severity, known exploited first. `dependencies.json` carries `kev`,
  `kev_date_added`, `epss` and `epss_percentile` per advisory, SARIF results carry them as an
  `exploits` property, and the CSV's Description repeats the finding's text. "By the numbers"
  gains a "Known exploited" row with the count and the data date.
- Without a bundle nothing else changes: "Not analysed" says "exploit data: not checked" and
  how to get one. A bundle fetched more than `scanners.dependencies.max_data_age_days` days
  (default 30: EPSS moves daily) before the scan is still used, with a note and "(N days old,
  older than the 30-day limit: refresh it)" on the row.
- A refreshed bundle that newly lists an advisory re-rates its finding: a re-audit
  (`--baseline`) shows it under "Changed" as "re-rated from high", not as resolved and new,
  since severity is not part of a finding's id.
- The bundle is gzip: the first line is a JSON header (`format: 1`, `fetched`, the sources,
  the KEV catalog version, the EPSS model version and score date, `attribution` and `kev`, CVE
  to date added); each other line is `CVE-YYYY-NNNN,epss,percentile`. A run streams the
  scores and keeps only the CVEs its advisories name.
- The Docker image holds a bundle in `/opt/eol/vulndata.gz`, beside the end-of-life bundle,
  fetched when the image was built (UNVAR-101): `docker build` needs both feeds for that step
  and fails, naming the feed, if either still fails after the retries. Build without it with
  `docker build --build-arg EXPLOIT_DATA=skip -t unvarnish .`; runs then report exploit data
  as "not checked". Any other `EXPLOIT_DATA` value fails the build. `scripts/site-kit.sh`
  prints the bundle's date in its image check.
- To give an existing image newer data, refresh both bundles into one folder and mount it over
  `/opt/eol`, as for end-of-life data below: a mount over `/opt/eol` hides both of the image's
  bundles, so it must hold both (`unvarnish doctor` in that container shows which it sees).

## End-of-life data

- The `end_of_life` scanner reads end-of-life dates from one file, `endoflife.json`, and never
  touches the network during a run. It looks in `$UNVARNISH_EOL_DIR` when that is set, else
  `$XDG_DATA_HOME/unvarnish/eol`, else `~/.local/share/unvarnish/eol`.
- On a connected laptop, run `unvarnish eol refresh` before each engagement. It downloads 19
  products from endoflife.date's API v1 (`https://endoflife.date/api/v1/products/<slug>`),
  four attempts each with backoff (`--attempts`), and writes the bundle with today's date;
  `--dir <path>` writes it elsewhere (then export `UNVARNISH_EOL_DIR=<path>` for runs). If any
  product fails, it exits 1 naming it and leaves the previous bundle as it was. It checks the
  folder is writable first; if not, it exits 1 with one error line suggesting `--dir`, and
  downloads nothing.
- Then rerun the engagement: the bundle date is in the inventory's inputs hash, so a plain
  `unvarnish run` reruns the inventory, the scan and render with the new dates; the split and
  the model phases stay fresh, since the census they read is unchanged (UNVAR-34).
- The findings document's "End-of-life runtimes and frameworks" row shows the counts and the
  data date. Without a bundle it reads "not checked (no end-of-life data bundle)" and "Not
  analysed" says how to get one; nothing fails.
- A bundle fetched more than `scanners.end_of_life.max_data_age_days` days (default 90)
  before the scan is still used, but "Not analysed" gains a note naming its date and age,
  and the row adds "(N days old, older than the 90-day limit: refresh it)". Refresh it as
  above; for a deliberately old bundle, raise the limit in the engagement file (UNVAR-59).
- The bundle is plain JSON (`format: 1`): `fetched` (the date), `source`, `attribution`
  (endoflife.date, MIT licence) and `products`, keyed by endoflife.date slug, each a `label`
  and its `cycles` (`cycle`, `codename`, `eol_from`, `is_eol`, `is_maintained`, `latest`),
  newest first. To use it elsewhere, copy the file into a folder and set `UNVARNISH_EOL_DIR`
  to that folder.
- The Docker image already has a bundle, in `/opt/eol` (`UNVARNISH_EOL_DIR=/opt/eol`),
  fetched when the image was built: `docker build` needs endoflife.date for that step and
  fails, naming the product, if any download still fails after the retries. Build without
  the data with `docker build --build-arg EOL_DATA=skip -t unvarnish .`; runs then report end
  of life as "not checked". Any other `EOL_DATA` value fails the build.
- To give an existing image newer data, write a bundle with the image itself and mount it
  over `/opt/eol` (create the folder first, or Docker creates it owned by root and the
  refresh cannot write to it):
  `mkdir -p eol && docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/eol:/eol" unvarnish eol refresh --dir /eol`,
  and the same with `vulndata refresh --dir /eol` (the mount hides the image's exploit data
  too), then add `-v "$PWD/eol:/opt/eol:ro"` to each run. The site kit runbook
  (`docs/site-kit.md`, section 6) has the same steps for an air-gapped site.
- Docker's layer cache can keep an older bundle when nothing before that step changed;
  `scripts/site-kit.sh` prints every bundle's date and runs `unvarnish doctor`, and
  `docker build --no-cache` fetches anew.

## gitleaks

- Used automatically when `gitleaks` is on PATH (it is in the image). It always runs with
  `--redact`; only what the built-in rules missed is added.
- Disable with `scanners.secrets.use_gitleaks: false`.
- gitleaks runs with Unvarnish's own config (the default rules) and `--ignore-gitleaks-allow`, so
  a `.gitleaks.toml` allowlist or `gitleaks:allow` comment in the client's repo has no effect.
  A `.gitleaksignore` file in the scanned tree still does; gitleaks 8.30.1 always reads it from
  the scanned directory. gitleaks would also read one from its working directory, so Unvarnish
  runs it in an empty temp folder of its own: a `.gitleaksignore` in the folder you start
  Unvarnish from has no effect (UNVAR-66).
  Look for the "Scanner suppression files in the source" finding and review its entries.
- This repository has no `.gitleaksignore` (UNVAR-72): its public history starts at one
  snapshot commit and holds no credential-shaped fixture whole. Check the repo with
  `gitleaks git . --redact` and `gitleaks dir . --redact`; both should say "no leaks found" (a
  shallow clone scans only what it has, so fetch full history first). Run `gitleaks dir` on a
  clean checkout: it ignores `.gitignore`, and after a test run the bytecode in `__pycache__`
  holds fixtures whole, because Python joins string fragments when it compiles them. A new
  finding means a new leak or a whole-token fixture: fragment the fixture as UNVAR-36 did. A
  confirmed false positive or a revoked leak can still be listed in a new `.gitleaksignore` by
  its fingerprint in this history; `tests/test_repo_hygiene.py` rejects only the old archive's
  commits.

## SAST (Opengrep)

- `sast` is optional and nothing is bundled: install `opengrep` yourself and point
  `scanners.sast.rules` at a local directory of Opengrep (Semgrep-format) rule files
  (`.yml`, `.yaml`). A relative path is relative to the engagement folder. Without either,
  the run still succeeds and "Not analysed" says `sast: not checked (...)` with the reason.
- Only a local directory is accepted: `auto`, registry names (`p/...`, `r/...`, `s/...`),
  URLs and `git+` repositories are refused, so the scan never fetches rules. Opengrep runs
  with `--disable-version-check`, in an empty temp folder of its own, and without any
  `SEMGREP_*` or `OPENGREP_*` variable (`SEMGREP_RULES` would add rules). Opengrep has no
  metrics to switch off.
- The vetted repository cannot hide results: Opengrep runs with `--no-git-ignore`,
  `--x-ignore-semgrepignore-files` and `--disable-nosem`, and Unvarnish's own census decides
  which files count (excluded, vendored and binary files are dropped). A `.semgrepignore` or
  `.opengrepignore` file (a name clients pass with `--semgrepignore-filename`) and every
  `nosem`, `nosemgrep` or `noopengrep` comment are listed in the "Opengrep suppressions in
  the source" finding, whether or not Opengrep ran.
- One finding per rule, with up to `max_evidence` places (default 25); the summary gives the
  full count. A follow-up review matches it to the baseline by scanner and rule.
- Changing a rule file, or installing or removing `opengrep`, reruns the scan; a new Opengrep
  version alone does not (`run --phase scan --force`).
- Where to get rules, and why none ship with Unvarnish: `docs/decisions.md`, "Opengrep SAST
  scanner (UNVAR-89)". The flags above were checked against Opengrep's source, not a binary:
  if a release drops `--x-ignore-semgrepignore-files` (marked internal), the note says
  `sast: not checked (opengrep failed: ...)`.

## Client exposure

- `client_exposure` treats `src/`, `public/` and `dist/` as browser-facing. For a monorepo or a
  client tree under another name, set `scanners.client_exposure.client_roots`, for
  example `client_roots: ["apps/web/", "frontend/"]`; the list replaces the default.
- A public-by-design key reported as "Secret-named variable exposed to the browser" (an
  analytics write key) goes in `public_names`; the list replaces the default, so copy it
  from `unvarnish scanners list` first.
- Tables reported without row level security may have RLS set in the Supabase dashboard
  rather than in migrations: ask the client for `select relname, relrowsecurity from
  pg_class` before calling them open.
- The route review finding is a list to confirm, not a verdict. With a model configured,
  extraction is told about each listed handler and reports the ones it confirms.

## Hidden text

- `hidden_text` findings show each hidden character as a `[U+XXXX]` escape; a run longer than
  eight ends in `[+N more]`. To see the raw bytes, open the cited line with
  `sed -n '<line>p' <file> | od -c` or an editor that shows invisible characters (VS Code's
  `editor.renderControlCharacters` and `editor.unicodeHighlight.invisibleCharacters`).
- A rule-file finding is high whatever the characters are, because the file steers every
  generation the assistant makes: read the file's history (`git log -p -- <file>`) and review
  code generated after the characters arrived.
- Model prompts carry the same escapes (at the one structured-call function every model phase
  uses), so the model sees what a reviewer would and cites the same line numbers. A unit with
  hidden characters gets a new cache key, so a later extract run asks about it again.
- Runs of variation selectors or private-use characters shorter than
  `scanners.hidden_text.long_run` (32) are not reported in source: icon fonts and variation
  sequences make short runs normal. Lower it to search for smaller payloads.
- The MCP finding is a review item: pin `npx`/`uvx` servers to an exact version
  (`pkg@1.2.3`, `pkg==1.2.3`); a server given by `url` is not reported.

## AI usage

- `ai_usage` lists the AI services in architecture.md ("AI services used") and
  `inventory/ai-usage.json`; the comparison's risk table names the providers per tool, hosted
  or local. A provider it does not know is a row to add to the tables in
  `src/unvarnish/scanners/ai_usage.py`.
- The prompt-injection and excessive-agency findings are lists to confirm, like the route
  finding. With a model configured, extraction is told about each model call and tool
  definition and reports the ones it confirms.
- Test code and vendored directories are skipped; set `scanners.ai_usage.include_tests: true`
  to include tests.

## Private repositories over SSH

- git never prompts during a run. Unvarnish appends `-o BatchMode=yes` to your
  `GIT_SSH_COMMAND` or `core.sshCommand`, keeps a `GIT_ASKPASS` token helper you set, and leaves
  `GIT_SSH` alone. Load keys into an agent, or use a key without a passphrase, before an
  unattended run.

## Air-gapped site kit

Build with `scripts/site-kit.sh` on a connected machine; it writes `dist/site-kit-<version>/`
with the image tarball, checksums, `RUNBOOK.md` (from `docs/site-kit.md`), and an on-prem
engagement example. Rebuild before each engagement so the advisory databases are current; the
report states their date. Lockfile entries without a registry source are never matched by
osv-scanner (they are local packages), so test fixtures need real `resolved` URLs.

### Refreshing the image pins

The `Dockerfile` pins its base image and the gitleaks, osv-scanner and uv images as
`tag@sha256:<digest>` (the multi-arch index digest), so a rebuild pulls the same binaries.
Dependabot's docker entry bumps tag and digest together, but it reads only `FROM` lines, so
each tool image is a named stage (`FROM <image> AS gitleaks`) and `COPY --from` names the
stage, never an image. Before building a site kit, confirm the pins are current by merging
any open Dependabot docker PR. To refresh one by hand, fetch the index digest for its tag and
replace the digest in the `Dockerfile`:

```bash
docker buildx imagetools inspect python:3.13-slim-trixie   # the "Digest:" line
```

Keep the tag and change only what follows `@sha256:`. `tests/test_distribution.py` fails if
any `FROM` loses its digest or a `COPY --from` names an image instead of a stage.

## Refusals

Safety classifiers occasionally refuse benign review material. Every request is retried once;
set a fallback model for a second refusal:

    models:
      refusal_fallback: { backend: anthropic, model: claude-sonnet-5-5, effort: low }

Refusals that remain are recorded in failures.json and the run continues.

## Constraining the consolidation proposal

Add a `consolidation:` section to engagement.yaml (see the README), then run
`unvarnish compare`; the constraints change the comparison's inputs, so the proposal is redone.

## Remediation effort and engineer-days

Every finding shows an effort band (S up to half a day, M up to two days, L up to a week, XL
weeks), and `findings.md` has a "Remediation outlook" table counting them by severity. To add
an engineer-day range to `findings.md` and the comparison's risk table, set the ceiling of
each band, in engineer-days, in `engagement.yaml`:

```yaml
report:
  effort_days: { S: 0.5, M: 2, L: 5, XL: 15 }
```

All four bands are required and must not shrink from S to XL. The range is an estimate (the
documents say so): the low end counts each finding at the band below's figure, the high end
at its own. Setting or changing it reruns `render`, `compare`, `render_comparison` and
`render_brief`; only the consolidation call is repeated. Remove it to drop the day figures; the bands stay.

To change a scanner rule's band, name the rule (shown in each finding's effort note, for
example `scanner rule hygiene.no_tests`) under the scanner:

```yaml
scanners:
  hygiene:
    effort: { no_tests: L }
```

The scan reruns. A model finding without a band shows "not estimated"; after upgrading, the
model phases rerun once to collect bands.

## Leadership brief

`unvarnish compare` also writes `comparison/brief.md` (the `render_brief` phase), a short
document for leadership that can be handed over without the engineering sections:

- portfolio totals: tools reviewed, files analysed, findings by severity, credential-like
  values from the secrets scanner (working tree and git history only), credentials exposed to
  browsers, end-of-life runtimes and frameworks, known-exploited (CISA KEV) dependency
  advisories, and the effort to fix;
- one row per tool: severity counts, effort to fix (engineer-days once `report.effort_days`
  is set, bands otherwise), and the trend since the previous review when a tool has a delta;
- the ten most severe findings across all tools, with tool and location, in a fixed order:
  severity, then known exploited and EPSS, scanner findings before model findings, then
  the tools' order in `engagement.yaml`, path, line and title;
- an action plan in three buckets.

Every number is counted from each tool's own artifacts (`census.json`,
`scanner-findings.json`, `findings.json`, `dependencies.json`, `delta.json`) with the same
rules as its `findings.md`, so a total is the sum of the per-tool documents. A measure that
was not checked for every tool says how many tools it covers ("1 (1 of 2 tools checked)").
The one model call is the summary paragraph; with no model configured, air-gapped or not, it
is the usual "No model-written text for this section" sentence and the rest still renders. A
one-tool engagement gets a brief that says the comparison sections were skipped. A budget
stop in `compare` does not stop the brief. Export it with `unvarnish export --doc brief`
(`exports/brief-engagement-<timestamp>.docx`, `.html`, `.pdf`).

The action-plan buckets are decided by each finding's severity and effort band alone:

| Severity | S | M | L | XL | Not estimated |
|---|---|---|---|---|---|
| critical | Fix now | Fix now | Fix now | Fix now | Fix now |
| high | Fix now | Fix now | Fix before scaling | Fix before scaling | Fix now |
| medium | Fix before scaling | Fix before scaling | Fix before scaling | Fix before scaling | Fix before scaling |
| low, info | Accept | Accept | Accept | Accept | Accept |

To change a finding's bucket, change its band (`scanners.<name>.effort` for a scanner rule,
see above) or its severity; the brief has no settings of its own. Template overrides work as
for the other documents (`brief.md.j2`).

## Follow-up reviews (re-audit delta)

1. Keep the previous engagement folder (or at least each tool's `inventory/` and `analysis/`
   with `tool.yaml`). Start the follow-up in a new engagement with the same tool names.
2. `unvarnish run --baseline ../acme-2026-10` (an engagement folder; a tool folder or one
   `scanner-findings.json`/`findings.json` also works, matched by its `tool` field). The
   baseline is read before anything runs: one with another findings schema version, or with
   none of the selected tools, stops the run with exit 2. A tool missing from it gets a
   warning and no comparison. `--dry-run --baseline` checks the baseline and writes nothing.
   In Docker, mount the previous engagement too: `-v "$PWD/acme-2026-10:/baseline:ro"` and
   `--baseline /baseline`.
3. Each tool's `findings.md` opens with "Since the previous review (date, commit)" and
   `analysis/delta.json` holds every finding's status. `unvarnish compare` adds a trend column.
   Export as usual; the section is part of `findings.md`.
4. The baseline is copied to `tools/<name>/analysis/baseline.json`, so later plain runs keep
   comparing. Pass `--baseline` again to replace it; delete that file to drop the section.
   A baseline in the engagement's own folder (`--baseline .`, or the tool's folder) is the
   exception: once a readable snapshot exists it is kept, so rerunning the same command to
   resume after a budget stop or Ctrl-C still compares with the results before the first run,
   and the run prints "keeping the stored baseline". To take a new snapshot from the folder, delete
   `tools/<name>/analysis/baseline.json` and run with `--baseline .` again.
5. Risks the client accepted: list their finding ids (shown in `findings.md` and the delta
   tables) under `baseline.accepted` in `engagement.yaml` and run again; only `render`
   reruns. A finding that moved further than 50 lines shows as resolved plus new: raise
   `baseline.line_drift`.

Compare like with like: a scanner-only baseline against a model-analysed run compares scanner
findings only, and the section says so. Model findings vary between runs, so a reworded one
shows as resolved plus new; check those pairs before quoting the counts. A grouped scanner
finding (oversized files, hardcoded URLs and the like) matches whatever its count: partly
fixing one shows as "changed" with "count 2 → 1", not as resolved plus new.

## Parallel tools

Tools run in parallel, `pipeline.parallel_tools` at a time (default 4). `pipeline.concurrency`
caps model requests across all of them, so set it to what the model server can take: 8 or more
for Anthropic, 1 for a single-GPU or CPU server.

## Stale engagement lock

`run`, `compare` and `ask` hold `.unvarnish/run.lock` in the engagement while they work, so two
of them never spend on the same engagement at once; `status`, `cost`, `export` and
`run --dry-run` don't need it. A second command exits 2 with "another unvarnish command is
working on this engagement: PID … on host … (unvarnish run, started …)". The host is the
machine's name, or the container ID inside Docker.

- **The holder is still running.** Wait for it, or stop it (Ctrl-C finishes the calls in
  flight and records them). A run suspended with Ctrl-Z still holds the lock: `fg` it or kill
  it. An interactive `ask` session holds the lock until you type `exit`.
- **The holder died on this machine, or in another container on the same Docker host.**
  Nothing to do: the next command sees the lock is free, prints "took over a stale engagement
  lock … its process has exited" and carries on.
- **The machine restarted while a run held the lock.** Also nothing to do when the run was
  on the machine itself: its name is unchanged and its last heartbeat predates the reboot, so
  the next command takes over at once ("the machine has restarted since its last
  heartbeat"). Inside Docker each container gets a new host name, so a container started
  after a reboot waits out `pipeline.lock_stale_minutes` unless the containers share a fixed
  name: give scheduled runs `docker run --hostname unvarnish …`.
- **The holder was on another machine** (an engagement on a network share), **or on the macOS
  host while the new run is in Docker Desktop's VM** (or the reverse). The lock can't be
  checked across kernels, so the holder refreshes the file's timestamp every 30 seconds, and
  the lock counts as stale once that heartbeat is older than `pipeline.lock_stale_minutes`
  (default 10). To take over sooner, make sure the process named is gone (`ps -p <PID>` on
  that host, `docker ps` for a container), then empty the file: `: > .unvarnish/run.lock`.

Never empty or delete the lock file while the process it names is alive: the next run would
start beside it.

## On-prem and local models

- **Check the context length for real:** `unvarnish config check --probe-context` sends a long
  prompt with a code word at the start and reports a server that silently truncates.

- **Set the server's context length.** Ollama defaults to a 4,096-token context on machines
  without a GPU and silently truncates longer prompts. Start it with
  `OLLAMA_CONTEXT_LENGTH=32768` (or the model's window) and set the same number as
  `capabilities.context_window` in `engagement.yaml`. vLLM and similar servers have their own
  `--max-model-len`.
- **Expect hours on CPU.** `qwen2.5:14b` on an 8-core Intel CPU processed about 12 prompt tokens
  and 2 output tokens a second: 4 to 7 minutes per unit. A GPU server is roughly two orders of
  magnitude faster. Run `unvarnish run --dry-run` for the unit count before starting.
- **Timeouts.** Each request may take up to `backends.<name>.timeout_s` (default 1800 seconds
  for OpenAI-compatible servers). A unit that exceeds it is recorded as failed and the run
  continues; raise the limit and rerun `unvarnish run` (no `--force`) to retry only the failed
  units. The tool rollup writes the longest
  answer of any call: on a CPU-only server it needed more than 30 minutes for a 45-unit tool,
  so set `timeout_s: 7200` there.
- **Keep one request at a time on a single-GPU or CPU server**: `pipeline.concurrency: 1`
  and `OLLAMA_NUM_PARALLEL=1`. Parallel requests only share the same hardware.
- **Structured output must be enforced by the server.** A server that ignores `json_schema`
  lets the model write unquoted keys and trailing commas; Unvarnish repairs those locally, but
  other slips cost a retry call each. On vLLM, pass guided decoding through
  `backends.<name>.extra_body`; on OpenRouter, require a provider that honours the schema:

      backends:
        onprem:
          extra_body: { provider: { require_parameters: true } }

  If no provider for the model supports structured output, OpenRouter answers 404 "No
  endpoints found"; pick another model. `config check` probes the live server (never the
  response cache), so it catches this before a run starts.
- **`max_tokens` is fitted to the window.** On OpenAI-compatible servers each request asks for
  no more output than the context window has room for after the prompt (at least 1,024
  tokens), so a 32k server is not sent a 32k output budget and refused with a 400.
- **Simulating an on-prem server with OpenRouter.** Without a GPU, an OpenAI-compatible backend
  pointed at `https://openrouter.ai/api/v1` with an open-weights coder model and
  `capabilities.context_window: 32768` behaves like a single-GPU server, minus the speed. Keep
  the key in the keychain and export it as `OPENROUTER_API_KEY` for the run only.
- **Testing an air gap with Docker:** put Unvarnish on an `--internal` network whose only other
  member relays to the model server. `docker network create --internal airgap`, then a relay
  container on both that network and the default bridge, then
  `docker run --network airgap ... unvarnish run`.

## Verify

The full check, as CI runs it:

    uv sync --locked --all-groups && uv run ruff check . && uv run pytest -q && uv build

`--locked` installs exactly what `uv.lock` pins and fails with "The lockfile at `uv.lock` needs
to be updated" when `pyproject.toml` changed without it, so CI tests what the Dockerfile
(`--frozen`) and the site kit ship. After editing dependencies, run `uv lock` with the
Dockerfile's uv version and commit both files.

CI's `test` job stops after 45 minutes (a normal run takes about 6). A run cancelled at the
limit fails `ci-status`; rerun it once, and if it times out again look for a hung download
in the grammar fetch or apt step (UNVAR-65).

## CI runners

`ci.yml` reads the repository variable `RUNS_ON` (a JSON runner label or list) for the
`ci-status` job, but only on a pull request from a branch of this repo; everything else,
fork pull requests included, runs on the hosted `ubuntu-24.04` (UNVAR-70). The repository is
public (UNVAR-37, 2026-11-18), so `RUNS_ON` stays unset or names a hosted label, and any
self-hosted runner group stays closed to public repositories. Checkout runs with `persist-credentials: false`; a step
that ever needs to push passes its own token.

## Coverage floor

`uv run pytest -q` measures branch coverage of `src/unvarnish` and fails below
`[tool.coverage.report] fail_under` in `pyproject.toml`; CI runs the same command, so the
floor gates every merge. The terminal report lists the missing lines of each file that is not
fully covered. A partial run (one test file, `-k`) covers far less than the floor, so add
`--no-cov` to it.

To raise the floor after adding tests: run `uv run pytest -q`, read the `TOTAL` line, set
`fail_under` to that percentage rounded down to a whole number, and update the date and
figure in the comment above it. Never lower it to get a change through; add the tests
instead (`tests/test_distribution.py` fails if `fail_under` drops below 95, the floor since
UNVAR-87).

## Findings into GitHub and Jira

`unvarnish export --format sarif` and `--format csv` write one file per tool under
`exports/` (`findings-<tool>-<timestamp>.sarif` / `.csv`), from the tool's
`inventory/scanner-findings.json` and `analysis/findings.json`. They hold what the findings
document lists: scanner findings and model findings that verification did not reject,
redacted. Neither needs pandoc; a tool that has not been scanned is skipped. Rerun `export`
after a rerun of `run`: the files are snapshots, like the other exports.

SARIF and CSV come only from the findings document, so `--doc` must include `findings` (or be
left out) when either is requested; otherwise `export` exits 2 before doing any work, including
for the docx, html and pdf parts of a mixed `--format` list.

**GitHub code scanning.** Each SARIF file is one run for one tool, so upload it to that tool's
repository. Code scanning must be enabled there (GitHub Advanced Security for a private
repository), and the token needs `security_events` (a fine-grained token: "Code scanning
alerts", read and write). Use the commit Unvarnish analysed, `commit` in
`tools/<tool>/tool.yaml`, and the branch it came from:

    gzip -c exports/findings-expense-bot-<timestamp>.sarif | base64 | tr -d '\n' |
      gh api -X POST repos/ACME/expense-bot/code-scanning/sarifs \
        -f commit_sha=<commit from tool.yaml> -f ref=refs/heads/main -F sarif=@-
    gh api repos/ACME/expense-bot/code-scanning/sarifs/<id from the response>  # processing status

The encoded file goes in on standard input (`-F sarif=@-`): passed as one command-line
argument, as in `-f sarif="$(...)"`, anything over 128 KB fails on Linux with "Argument list
too long".

From a workflow in the tool's repository, commit the file (or fetch it as an artifact) and use
`github/codeql-action/upload-sarif` with `sarif_file:` set to it. The run's
`automationDetails.id` is `unvarnish/<tool>/`, which GitHub uses as the upload's category, so
a new upload replaces the previous Unvarnish alerts for that tool and leaves CodeQL's alone.
Alerts match across uploads by `partialFingerprints.unvarnishFindingId`, the finding id in
the documents. Paths are relative to the tool's root, and GitHub resolves them from the
repository root, so the alerts of a tool added from a subdirectory of a repository don't line
up with its files (see `docs/known-issues.md`). A tool with more than 25,000 findings
(GitHub's limit per run) is split into `-part1`, `-part2`, ... files with categories
`unvarnish/<tool>-part1/`, ...; upload each.

Levels: critical and high are `error`, medium `warning`, low and info `note`. Security rules
also carry `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0), so GitHub ranks
them Critical, High, Medium and Low as the documents do. Each result's `properties` carry
Unvarnish's severity, category, source, verification and confidence.

**Jira.** The CSV has the columns `Summary`, `Description` (summary, impact and remediation,
plus any further evidence), `Severity`, `Tool`, `Category`, `Source`, `Path`, `Lines`,
`FindingId` and `Verification`, UTF-8 with multi-line cells quoted. Import it with Jira's CSV
importer (Import issues from CSV, or System > External System Import > CSV as an
administrator): map `Summary` and `Description` to the fields of the same name, `Severity` to
Priority (critical to Highest, high to High, and so on, in the importer's value mapping),
`Tool`, `Category` and `Source` to labels or components, and `FindingId` to a text custom
field or a label, so a later import can be checked against findings already filed. A cell
that would start with `=`, `+`, `-` or `@` is prefixed with `'` so a spreadsheet does not
evaluate it.

## Known traps

- **A phase failed overnight.** `unvarnish status` gives the one-line reason; the full,
  redacted traceback is in the run's log, `logs/run-<timestamp>.log` in the engagement, on the
  ERROR line naming the tool and phase. Add `--verbose` to see it on the console too.
- **A linked tool's folder moved or was deleted.** `run` fails its inventory with "source
  directory <path> does not exist (linked tool; re-add or restore it)" and leaves its
  documents as they were; `status` shows the reason. Restore the folder at that path and
  run again, or add the tool again from its new place: `add` refuses a tool that already
  exists, so move `tools/<tool>` aside first. A copied tool whose `tools/<tool>/source` is gone fails the same way ("copied
  source; re-add the tool").
- **Pandoc 3.1.x and PDF diagrams.** Pandoc 3.1 writes its PDF intermediate into the current
  directory, and weasyprint resolves images against it. Unvarnish runs pandoc in its own work
  directory and fails the conversion if weasyprint reports a missing image, so a PDF never ships
  without its diagrams.
- **Large schemas and the Anthropic API.** The tool-rollup schema is too large for the API's
  grammar compiler; the call falls back to JSON-in-prompt automatically and logs a warning.
- **Small context windows.** On-prem endpoints with 32k windows can fail module rollups for very
  large files (recorded, not fatal); ask mode trims its own conversation to fit.

## Reports

Engagement reports are kept outside the repository, for example
`~/Projects/unvarnish-reports/<tool>-<date>/`. The repository holds no client material.
