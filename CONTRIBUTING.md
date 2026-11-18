# Contributing to Unvarnish

Thanks for helping! This guide covers setup and what a pull request needs.

## Setup

Unvarnish is a Python 3.13 project managed with [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-groups          # create .venv with the package and dev tools
uv run unvarnish --help       # the CLI
```

Exports need pandoc (3.1 or newer), Graphviz, and WeasyPrint on PATH (`brew install pandoc
graphviz weasyprint`, or the Debian packages of the same names). Tagged PDFs need WeasyPrint 66
or later (`pip install 'weasyprint>=66'`); with the Debian package the tagged-PDF test skips
and PDFs export untagged. The Docker image bundles
them: `docker build -t unvarnish .`. Live model tests need an `ANTHROPIC_API_KEY`;
`scripts/smoke.sh` runs one end to end. The unit suite never calls a model.

## Before you open a PR

```bash
uv run ruff check .
uv run pytest -q
```

- Keep PRs focused; follow the existing code style.
- Add or update tests for behaviour changes; every fix starts with a failing test.
- Record decisions in `docs/decisions.md`, accepted gaps in `docs/known-issues.md`, and
  user-visible changes in `CHANGELOG.md`.
- Conventional-commit style titles (`feat:`, `fix:`, `chore:`) are appreciated.
- `main` is protected: open a pull request, wait for the `ci-status` check to
  pass, and squash-merge.

## Sign your commits (DCO)

Unvarnish is licensed under Apache-2.0 ([LICENSE](LICENSE)), and contributions come in under
the same licence. Instead of a contributor licence agreement we use the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO): a short statement
that you wrote the change, or otherwise have the right to submit it under the project's
licence. You agree to it by adding a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds the line for you, using your `user.name` and `user.email`. Use your real
name. A check on each pull request refuses commits without the line; to fix one, run
`git commit --amend -s` (or `git rebase --signoff main` for several) and push again.
