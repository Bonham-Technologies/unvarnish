# alpha: Findings

**Client:** Acme · **Prepared by:** Bonham Technologies · **Generated:** 2026-11-08 12:00 UTC\
**Source:** repo `expense-bot` at `7cbb0dce7e55`

> Produced by Unvarnish's deterministic scanners and model-assisted analysis (stub/stub-model).
> Every finding is traceable to a file and line. Model findings rated high or critical were checked by an
> independent verification pass that saw only the claim and the cited lines; each shows its status.

## Executive summary

PROSE Write the executive summary for leadersh

## Summary

20 findings: 11 high, 7 medium, 2 low.
Scanner findings: 12. Model findings: 8 (5 confirmed, 0 downgraded, 1 unverified; 1 rejected on verification and excluded).

**11 findings are critical or high severity and need action before this tool is relied on further.**

## By the numbers

| Measure | Value |
|---|---|
| Files analysed / total | 7 / 8 |
| Source lines | 3,032 |
| Largest source file | `app.py` (3,008 lines) |
| Longest source function | `process_everything` in `app.py` (3,002 lines) |
| Languages (source lines) | python 3,008; html 24 |
| Frameworks | Flask |
| Automated tests | **none** |
| Secrets (current / history only) | 0 / 2 |
| Client-exposed credentials / open tables | 0 / 0 |
| Dependencies declared | 2 |
| Dependency vulnerabilities | not checked (disabled by UNVARNISH_DISABLE_OSV) |
| End-of-life runtimes and frameworks | not checked (no end-of-life data bundle) |
| Model findings (after verification) | 8 (1 rejected) |
| Commits · authors · active days | 4 · 2 · 4 |
| History span | 2026-01-05 to 2026-02-01 |
| Top author share · bus factor | 100% · 1 |
| Commits over 2,000 lines | 1 |
| AI tooling indicators | CLAUDE.md; Co-Authored-By Claude ×1 |

### Largest source files

| File | Lines | Longest function |
|---|---:|---|
| `app.py` | 3,008 | `process_everything` (3,002) |
| `static/index.html` | 24 | `render` (7) |

## Remediation outlook

Findings by remediation effort: S up to half a day, M up to two days, L up to a week, XL weeks. Scanner findings carry a fixed band per rule; model findings carry the model's band, adjusted by the verifier where it checked the finding. The bands are an input to the consultant's judgment, not a quote.

| Severity | S | M | L | XL | Not estimated | Total |
|---|---:|---:|---:|---:|---:|---:|
| high | 0 | 2 | 3 | 0 | 6 | 11 |
| medium | 1 | 2 | 1 | 1 | 2 | 7 |
| low | 2 | 0 | 0 | 0 | 0 | 2 |
| **Total** | 3 | 4 | 4 | 1 | 8 | 20 |

## Findings

### High (11)

#### Single-author concentration

`process` · source: scanner (bus_factor) · effort: L · id `3e2387278298a39f`

Alice authored 100% of all changed lines across 4 commits; 2 authors in total (threshold 90%).

**Impact.** Knowledge of how this tool works lives with one person. If they leave or are unavailable, nobody can safely change or operate it.

**Remediation.** Pair a second maintainer with the author now and document the design before handover.

**Effort.** L: pair a second maintainer and document the design (scanner rule bus_factor.single_author)

**Evidence.**
- `.` (4 commits; shares by changed lines: Alice 100%, Bob 0%)

#### AWS access key ID in git history

`security` · source: scanner (secrets) · effort: M · id `4d24901ffcd2c45f`

AWS access key ID found in app.py. The value is redacted here and identified by fingerprint.

**Impact.** Anyone who can read this code or its history holds a working credential. Rotation is required regardless of whether the file is still present.

**Remediation.** Rotate the credential now. Move it to a secret manager or environment variable. Purge it from git history (git filter-repo) before the repository moves anywhere.

**Effort.** M: rotate the credential, then rewrite history every clone must take (scanner rule secrets.credential_history)

**Evidence.**
- `app.py` — `AWS_ACCESS_KEY_ID = "AKIA…[redacted 20 chars]"` (fingerprint a55913dfca88; added in commit 0f27c8756471; removed from the working tree but recoverable by anyone with repository access)

#### Database connection string with embedded password in git history

`security` · source: scanner (secrets) · effort: M · id `1f79f6b50a6c6ecf`

Database connection string with embedded password found in app.py. The value is redacted here and identified by fingerprint.

**Impact.** Anyone who can read this code or its history holds a working credential. Rotation is required regardless of whether the file is still present.

**Remediation.** Rotate the credential now. Move it to a secret manager or environment variable. Purge it from git history (git filter-repo) before the repository moves anywhere.

**Effort.** M: rotate the credential, then rewrite history every clone must take (scanner rule secrets.credential_history)

**Evidence.**
- `app.py` — `DB_URL = "postgres://admin:…[redacted 7 chars]@db.internal:5432/expenses"` (fingerprint f52fbd32b2b3; added in commit 0f27c8756471; removed from the working tree but recoverable by anyone with repository access)

#### Oversized file

`maintainability` · source: scanner (oversized_files) · effort: L · id `baa260a096cc92e4`

app.py is 3,008 lines (threshold 1,500).

**Impact.** Files this large are not readable in one sitting, hide duplicated logic, and make ownership and review impractical.

**Remediation.** Split by responsibility into modules of a few hundred lines each.

**Effort.** L: split each file by responsibility (scanner rule oversized_files.file)

**Evidence.**
- `app.py:1-3008` (3,008 lines)

#### Very large function

`maintainability` · source: scanner (oversized_files) · effort: L · id `e1809cafbfc34103`

process_everything in app.py is 3,002 lines (threshold 150).

**Impact.** A function this long cannot be unit tested or reasoned about; defects hide in it.

**Remediation.** Extract cohesive steps into named functions with their own tests.

**Effort.** L: restructure a function far beyond any reviewable size (scanner rule oversized_files.very_large_function)

**Evidence.**
- `app.py:7-3008` (process_everything: 3,002 lines)

#### Hardcoded credential

`security` · source: model · verification: confirmed · effort: not estimated · id `d0f49f3bfae0edd7`

s

**Impact.** i

**Remediation.** r

**Verifier.** checked the lines

**Evidence.**
- `CLAUDE.md:1` (x)

#### No auth anywhere

`security` · source: model · **unverified** · effort: not estimated · id `c339be6eeffe9937`

s

**Impact.** i

**Remediation.** r

**Verifier.** tool-level finding: not independently verifiable from cited lines; review manually

**Evidence.**
- `app.py` (cited by tool-level analysis)

#### Hardcoded credential

`security` · source: model · verification: confirmed · effort: not estimated · id `1d0a6c38797e2d2d`

s

**Impact.** i

**Remediation.** r

**Verifier.** checked the lines

**Evidence.**
- `app.py:1` — `x`
- `app.py:785` — `x`
- `app.py:1526` — `x`
- `app.py:2253` — `x`
- `app.py:2980` — `x`

#### Hardcoded credential

`security` · source: model · verification: confirmed · effort: not estimated · id `ca09bd6a3e965d35`

s

**Impact.** i

**Remediation.** r

**Verifier.** checked the lines

**Evidence.**
- `requirements.txt:1` (x)

#### Hardcoded credential

`security` · source: model · verification: confirmed · effort: not estimated · id `2455a1c1e88f0967`

s

**Impact.** i

**Remediation.** r

**Verifier.** checked the lines

**Evidence.**
- `static/app.min.js:1` (x)

#### Hardcoded credential

`security` · source: model · verification: confirmed · effort: not estimated · id `da21c6daae4f4607`

s

**Impact.** i

**Remediation.** r

**Verifier.** checked the lines

**Evidence.**
- `static/index.html:1` — `x`
- `static/index.html:4` — `x`
- `static/index.html:7` — `x`
- `static/index.html:12` — `x`
- `static/index.html:19` — `x`
- `static/index.html:21` — `x`
- `static/index.html:22` — `x`

### Medium (7)

#### Bulk commits

`process` · source: scanner (generated_bulk) · effort: L · id `370fde4611244f0f`

1 commit changed more than 2,000 lines (3,009 lines, 99% of all changed lines). The history carries AI co-author trailers (Claude ×1), consistent with generated code committed in bulk.

**Impact.** Changes this large are rarely reviewed line by line; they are typical of generated code pasted in wholesale, so defects and copied secrets slip through.

**Remediation.** Review the largest of these commits for code nobody owns, and require smaller, reviewed changes from now on.

**Effort.** L: review the largest unreviewed commits (scanner rule generated_bulk.bulk_commits)

**Evidence.**
- `.` (17e1b9d35944 2026-01-06 Alice: +3,006 -3 in 2 files: generate processing)

#### No automated tests

`process` · source: scanner (hygiene) · effort: XL · id `06d773d833a22e45`

The tool has no test files of any kind.

**Impact.** Every change is verified by hand or not at all; regressions reach users.

**Remediation.** Add a test runner and cover the main paths before any further change.

**Effort.** XL: add a test suite and cover the main paths (scanner rule hygiene.no_tests)

**Evidence.**
- `.` (repository root)

#### No continuous integration configuration

`process` · source: scanner (hygiene) · effort: M · id `7af36647292303a7`

No CI pipeline definition was found.

**Impact.** Nothing runs tests, linting, or builds automatically; quality depends on individual discipline.

**Remediation.** Add a pipeline that runs tests and linting on every push.

**Effort.** M: add a pipeline that runs tests and linting (scanner rule hygiene.no_ci)

**Evidence.**
- `.` (repository root)

#### Dependency or build directories in the source

`maintainability` · source: scanner (vendored_bulk) · effort: M · id `52364e4135515550`

1 directory of third-party or build output (1 file, 0.0 MB) is part of the source: node_modules.

**Impact.** Third-party code is versioned alongside the tool's own: it bloats every clone, hides local edits to dependencies, and never receives security updates.

**Remediation.** Remove these directories from the source, list them in .gitignore, and restore them from the package manager's manifest and lockfile at build time.

**Effort.** M: restore dependencies from the manifest at build time (scanner rule vendored_bulk.vendored_directories)

**Evidence.**
- `node_modules` (1 file, 0.0 MB)

#### Unpinned dependencies without a lockfile

`dependency` · source: scanner (dependencies) · effort: S · id `dac29a1902864564`

1 dependency across 1 manifest accepts a range of versions and no lockfile records which version was actually installed.

**Impact.** Each install can resolve to a different release, including a broken or compromised one; builds are not reproducible and an audit cannot say what code actually runs.

**Remediation.** Commit the package manager's lockfile, or pin exact versions in the manifest, and update them deliberately.

**Effort.** S: commit a lockfile or pin versions (scanner rule dependencies.unpinned)

**Evidence.**
- `requirements.txt` (unpinned: requests >=2.31)

#### Mixed responsibilities

`maintainability` · source: model · verification: not_required · effort: not estimated · id `d1917cc66c5d9a6c`

s

**Impact.** i

**Remediation.** r

**Evidence.**
- `app.py:1` — `x`

#### Mixed responsibilities

`maintainability` · source: model · verification: not_required · effort: not estimated · id `70b2f1ab183cbd4b`

s

**Impact.** i

**Remediation.** r

**Evidence.**
- `static/index.html:1` — `x`

### Low (2)

One row per finding. Impact, remediation, and excerpts for each are in
`analysis/findings.json`, and `unvarnish ask` can explain any of them.

| Finding | Category | Source | Effort | Location |
|---|---|---|---|---|
| No license file | compliance | scanner | S | `.` |
| No linter or formatter configuration | maintainability | scanner | S | `.` |

## Not analysed

Excluded from analysis but counted in totals:

- **vendored:node_modules**: 1 file — e.g. `node_modules/leftpad/index.js`

Scanner notes:

- gitleaks: disabled by UNVARNISH_DISABLE_GITLEAKS
- dependencies: exploit data: not checked (no exploit data bundle); advisories are not marked as known exploited (CISA KEV) or ordered by exploit likelihood (EPSS) (run `unvarnish vulndata refresh` while online, or set UNVARNISH_VULNDATA_DIR to a folder holding vulndata.gz, then rerun)
- dependencies: licences: not checked (offline mode); osv-scanner reads package licences from deps.dev, so no licence is listed in the SBOM export and none is checked against an allowlist (set scanners.dependencies.offline: false, then rerun)
- end_of_life: no end-of-life data bundle; runtime and framework versions were not checked against end-of-life dates (run `unvarnish eol refresh` while online, or set UNVARNISH_EOL_DIR to a folder holding endoflife.json, then rerun)
- sast: not checked (no rules directory configured; set scanners.sast.rules to a local Opengrep rules directory)

1 model finding was rejected on verification and is excluded above; it remains in `analysis/findings.json` for inspection.

