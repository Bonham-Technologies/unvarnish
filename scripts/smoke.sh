#!/usr/bin/env bash
# Live smoke test against a real backend. Needs ANTHROPIC_API_KEY (or edit the backend below).
set -euo pipefail
E=$(mktemp -d)/smoke
uv run unvarnish init "$E" --client Smoke >/dev/null
cat >> "$E/engagement.yaml" <<YAML
backends:
  anthropic: { type: anthropic, api_key_env: ANTHROPIC_API_KEY }
models:
  default: { backend: anthropic, model: claude-opus-5-5, effort: low }
budget:
  max_tokens: 200000
YAML
uv run unvarnish add scanners --files "$(dirname "$0")/../src/unvarnish/scanners" -e "$E"
uv run unvarnish add render --files "$(dirname "$0")/../src/unvarnish/render" -e "$E"
uv run unvarnish config check -e "$E"
uv run unvarnish run --dry-run -e "$E"
uv run unvarnish run -e "$E" || echo "run exited $? (recorded failures are expected to be visible below)"
uv run unvarnish compare -e "$E" || echo "compare exited $?"
uv run unvarnish ask "What does the scanners tool do, and what is its most serious finding?" -e "$E" || echo "ask exited $?"
uv run unvarnish export --format html -e "$E" || echo "export exited $?"
uv run unvarnish status -e "$E"
uv run unvarnish cost -e "$E"
echo "engagement at $E"
