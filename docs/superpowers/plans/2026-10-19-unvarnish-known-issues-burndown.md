# Known-Issues Burn-Down Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Each fix is
> test-first: write the named test, watch it fail, fix, watch it pass, run the area's tests.

**Goal:** Address every entry in `docs/known-issues.md`: fix it, or decide it is correct and
record the decision in `docs/decisions.md` with its reason and cost if wrong.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md`

## Global Constraints

- Line length 100; ruff E, F, I, UP, B; UTF-8 for all text I/O; every fix has a test that
  failed first, in `tests/test_backlog_<area>.py`.
- Behaviour visible in documents changes only where the item says so.
- One commit per area; the full suite passes before each commit.

## Triage

Legend: **F** fix · **D** decide (no code change; reason goes to decisions.md) · **X** already
fixed on main or this branch (move to "Fixed by later slices").

### Task 1: Ingest and git history (`tests/test_backlog_git.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 1 | `git log` failure reported as "no commits" | F | GitStats gets `error`; git phase records the failure and the note says why |
| 2 | Renames in `--numstat` not parsed | F | parse `a/{old => new}` and `old => new` to the new path |
| 3 | `--all`, merges, shallow, submodules, worktree `.git` file | D | all refs matter for secrets; merge diffs repeat parents; full history needed for bus factor; submodules are separate tools; worktrees: use `--repo` URL |
| 4 | Only the root `.gitignore` honoured | F | Excluder loads every `.gitignore` and applies it below its directory |
| 5 | `--link` invisible in Docker | D | documented in the runbook and operations |
| 6 | git subprocesses decode with the locale | F | `encoding="utf-8"` on every git call |

### Task 2: Scanners (`tests/test_backlog_scanners.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 7 | `hygiene` uses `splitlines()` | F | split on `\n` only |
| 8 | All private keys share one fingerprint | F | fingerprint header plus the first body line |
| 9 | "Removed from the working tree" wrong for skipped files | F | say "removed" only when the path is absent from the census |
| 10 | No prefilter before history regexes | F | per-rule literal prefilter on each line |
| 11 | AI-tooling pattern matches Devin/Cline; misses email-only Anthropic trailers | F | bot names need a bot-like email; match `noreply@anthropic.com` |
| 12 | Extension map case-sensitive; `.ipynb` unmapped; `bin` over-excludes | F | case-insensitive suffix lookup; `.ipynb` maps to `jupyter`; drop `bin` from build dirs |
| 13 | History findings identified by title suffix | F | `history` tag |
| 14 | gitleaks note only in the log | F | scanner notes rendered under "Not analysed" |
| 15 | Disable switches treat `0` as disable | F | only `1/true/yes/on` disable |
| 16 | Inventory freshness ignores osv-scanner and dependency options | F | both in the inventory inputs hash |
| 17 | Hostname pattern backtracks quadratically | F | find TLD occurrences, walk back over host characters (linear) |
| 18 | gitleaks repeats one history secret at different lines | F | history results deduplicated by rule, path, and commit |
| 19 | "Files too large" paragraph wording | F | one listing, accurate about what is skipped, mentions the line cut-off |
| 20 | `generated_bulk` counts deletions | F | added lines only |
| 21 | Vulnerabilities not by severity | F | "9 (2 high, 7 medium)" |
| 22 | Test files under `build/` treated as build output | F | not when a test directory contains the build directory |
| 23 | Doc links in comments reported as hardcoded URLs | F | skip URLs on comment-only lines |
| 24 | Token redaction hides commit SHAs and file names | F | keep hex SHAs and names with an extension |
| 25 | No abandoned-package check | D | needs registry lookups; the product is offline-first |

### Task 3: Configuration (`tests/test_backlog_config.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 26 | Unknown keys silently ignored | F | `config check` and every load warn with the dotted key |
| 27 | `report.templates_dir` resolves against the cwd | F | against the engagement root |
| 28 | `status`/`cost` crash on a corrupt artifact | F | shown as unreadable |
| 29 | Freshness re-reads whole artifacts | F | read only the `meta` object from the file's tail |
| 48 | Anthropic default `context_window` 200,000 | F | 1,000,000 for `anthropic` backends unless set |

### Task 4: Model layer and analysis (`tests/test_backlog_model.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 30 | Dry-run counts stale units; "≤ USD" label | F | count against the current index; label "≈ USD" |
| 31 | HTML windows not flagged in the prompt | F | unit message says "window N of M" for windowed units |
| 32 | `max_completion_tokens` for newer OpenAI/Azure | F | capability `max_tokens_param`; switch automatically on the 400 that names it |
| 33 | `render` skipped after a budget stop | F | render always runs; documents show what is complete |
| 34 | Verify dedupe merges distinct problems; missing confidence becomes 0.0 | F | key includes overlapping lines; merged count kept; `None` stays `None` |
| 35 | `verify`/estimate read stale artifacts | F | read only ids in the current index |
| 36 | Store/system module lists unfiltered | F | filtered against known paths |
| 37 | Two chunks can share a prefix label | F | labels made unique |
| 38 | Prose tag accepts only double quotes | F | single quotes too |
| 39 | Truncated prose accepted | F | `max_tokens` stop retried once with twice the limit, else recorded |
| 40 | Module rollup prompts not trimmed to the window | F | units trimmed to fit, with an omitted count |
| 41 | Model lists uncapped in documents | F | caps with "(+N more)" |
| 42 | `call_structured` records a fatal config error per item | F | re-raised |
| 43 | Empty module map renders an empty Mermaid | F | diagram omitted with a sentence |
| 44 | "Used by" matching is substring-based | F | whole-name matching |
| 45 | Prose fallback persists until `--force` | F | render stays stale while any fallback text is present |
| 46 | Model summaries not redacted | F | summaries, descriptions, purposes redacted at write time |
| 47 | `config check` cannot see a server context limit | F | `config check --probe-context` sends a long prompt with a marker at the start |
| 49 | Small models misstate counts / report intended content | X / D | counts retried (fixed); judgement quality is the model's, documented |
| 50 | Tool-level findings on files over 600 lines unverified | X | windows (this branch) |

### Task 5: Comparison (`tests/test_backlog_compare.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 51 | "Serves" column unescaped | F | `cell` filter |
| 52 | `recommended_tool` not validated | F | unknown names marked "(not a reviewed tool)" |
| 53 | Unmapped footnote wording without normalisation | F | says normalisation did not run |
| 54 | A crash in `compare` leaves `failures.json` empty | F | the crash is recorded |
| 55 | A failed consolidation is fresh | F | stays stale so `compare` retries |
| 56 | Exit-2 detection matches message text | F | a typed error |
| 57 | No caps on normalisation input or matrix rows | F | caps with a note |

### Task 6: Ask mode (`tests/test_backlog_ask.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 58 | Call with no tool spends the forced-answer turn | F | treated as an invalid call, turn not spent |
| 59 | Unknown-tool branch unreachable | F | removed |
| 60 | Empty line ends a session; Ctrl-C prints nothing | F | `exit`/`quit` end it; Ctrl-C prints the saved line |
| 61 | Schema sent twice on non-native backends | F | once |
| 62 | BM25 rebuilt per query | F | built once per session |
| 63 | `grep_source` on unbounded lines | F | lines cut at 2,000 characters |
| 64 | Question unredacted; second-resolution names; log named `run-` | F | redacted; millisecond names; `ask-<ts>.log` |
| 65 | No tests for truncation or `get_module` by path | F | tests added |

### Task 7: Export and Docker (`tests/test_backlog_export.py`)

| # | Item | Res | Approach |
|---|---|---|---|
| 66 | Second export in one second overwrites | F | suffix `-2`, `-3` |
| 67 | Export table truncates paths | F | paths fold instead of truncating |
| 68 | `--template` treats any non-`.docx` as CSS | F | only `.css`; anything else is an error |
| 69 | Exporting one tool exports the comparison | F | only when no tools are named or `--doc comparison` |
| 70 | Dependencies reinstall on every source change; `VOLUME` hides a missing `-v` | F | dependency layer before source; no `VOLUME`; warn when `/engagement` is not a mount |
| 71 | `uv:latest` | X | pinned in this branch's parent |
| 72 | Windows paths in osv output | F | backslashes normalised before relativising |

### Task 8: Record

Rewrite `docs/known-issues.md` with what remains (the **D** items move to decisions.md), list
every fix in CHANGELOG, run the full suite, push, open the PR.
