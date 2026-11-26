# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Unvarnish is a command-line tool a consultant runs to vet internally built ("vibe-coded")
tools at a client: for each tool it writes architecture, findings, and requirements
documents, and across tools a comparison with a consolidation proposal. It runs unattended,
online (Anthropic) or air-gapped (any OpenAI-compatible model server), on code in any
language. Design spec: `docs/superpowers/specs/2026-10-15-unvarnish-design.md`.

Architecture: an engagement folder holds the tools and every artifact. A phase pipeline runs
per tool (`inventory`, `git`, `scan`, `split`, `extract`, `rollup_modules`, `rollup_tool`,
`verify`, `render`), each phase writing a JSON artifact with an inputs hash so reruns skip
fresh work and resume after a stop. Deterministic scanners (secrets, gitleaks, osv-scanner
advisories, hardcoded infrastructure, hygiene, oversized files, bus factor, bulk commits) run
first; model phases extract each code unit with structured output, roll units up to files and
the tool, and verify high findings against the cited lines. Engagement phases (`compare`,
`render_comparison`, `render_brief`) build the cross-tool comparison and the leadership
brief. `ask` answers questions over the analysis with cited sources; `export` converts
Markdown to DOCX, HTML, and PDF.

## Layout

- `src/unvarnish/`: the package. `cli.py` (Typer commands), `phases/` (the pipeline),
  `scanners/`, `analysis/` (census, split, metrics, dependencies, advisories, comparison),
  `model/` (backends, structured output, caching, budget, prompts), `render/` (Jinja2
  templates and context builders), `export/` (pandoc pipeline and bundled style), `ask/`
  (index, tools, loop), `schemas/` (Pydantic artifact models), `util/`.
- `tests/`: pytest suite; `tests/fake_llm.py` and `tests/stub_backend.py` stand in for models.
- `docs/`: `decisions.md`, `known-issues.md`, `operations.md`, `site-kit.md`, and
  `superpowers/` (spec and implementation plans).
- `scripts/`: `smoke.sh` (live end-to-end run), `site-kit.sh` (air-gapped image bundle),
  `build-reference-docx.py` (Word export style).
- `branding/bonham/`: editable export style. `examples/`: on-prem engagement config.
- `site/`: unvarnish.tech (unvarnish.com redirects to it), static HTML deployed by its own Vercel project; see `site/README.md`.
- `Dockerfile`: the distributable image (scanners, pandoc, fonts, optional offline advisories);
  `docker/weasyprint.txt` pins its PDF engine with hashes.

## Commands

Verify: `uv sync --locked --all-groups && uv run ruff check . && uv run pytest -q && uv build`

```bash
uv sync --locked --all-groups             # install exactly what uv.lock pins
uv run unvarnish --help                   # run the CLI
uv run ruff check .                       # lint (CI runs exactly this)
uv run pytest -q                          # test with the coverage floor (about 4 minutes)
uv run pytest -q --no-cov tests/test_x.py # a partial run: skip coverage, it is below the floor
uv build                                  # build the wheel
docker build -t unvarnish .               # build the image
scripts/site-kit.sh                       # build the air-gapped site kit into dist/
```

## Conventions

- Python 3.13, ruff (line length 100; rules E, F, I, UP, B), UTF-8 for every text read and
  write, Pydantic v2 models for every artifact.
- Test-first: every fix and feature starts with a test that fails.
- Branch from `main` for each piece of work; never stack on another feature branch. Open a
  pull request; `ci-status` must pass; squash-merge only.
- Commit messages: conventional prefixes (`feat:`, `fix:`, `docs:`, `chore:`), a body that
  says why.
- Each change updates the record: `CHANGELOG.md`, `docs/decisions.md` (rulings with their
  cost if wrong), `docs/known-issues.md`, `docs/operations.md`.
- Never write API keys to disk, logs, artifacts, or output; they come from environment
  variables or the keychain.

## Record

- Jira key: UNVAR. Ticket keys go in as plain text, never as links.
- Confluence tree: OPS > Projects > Unvarnish (Charter & Scope, Architecture, Decision Log,
  Runbooks, Brainstorms, Session Log).
- Worktrees: none; work happens on branches of this checkout. Reports from real runs live
  outside the repo in `~/Projects/unvarnish-reports/<engagement>/`.
- Follow-ups: `docs/known-issues.md` (accepted gaps), `docs/decisions.md` (rulings).
