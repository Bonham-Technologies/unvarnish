"""Running Opengrep for the `sast` scanner (UNVAR-89): local rules only, never the network."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from unvarnish.scanners.gitleaks import _relative
from unvarnish.util.gitcmd import GitError, git_env

RULE_SUFFIXES = (".yml", ".yaml")
# Checked against Opengrep's own CLI source (Scan_CLI.ml and CLI_common.ml on main, November
# 2026), not against a binary. Opengrep has no metrics and no `--metrics` flag: passing one
# fails the run. `--disable-version-check` is accepted and inert (Opengrep never checks), and
# is kept so a semgrep-compatible build stays offline too. The other three stop the vetted
# repository's own files from hiding results: `.gitignore`, `.semgrepignore` and inline
# `nosem`/`nosemgrep` comments. Unvarnish's census decides which files count instead.
OPENGREP_FLAGS = ["--json", "--disable-version-check", "--no-git-ignore",
                  "--x-ignore-semgrepignore-files", "--disable-nosem"]
# Exit codes 0 and 1 carry results; anything else is a fatal error (a bad rule, a crash).
OK_CODES = (0, 1)
NO_RULES = ("no rules directory configured; set scanners.sast.rules to a local Opengrep "
            "rules directory")


def is_registry_value(value: str) -> bool:
    """A value Opengrep would fetch over the network: `auto`, a registry pack (`p/...`),
    rule (`r/...`) or snippet (`s/...`), a URL, or a remote git repository (`git+...`)."""
    v = value.strip()
    return (v.lower() == "auto" or v.startswith(("p/", "r/", "s/", "git+"))
            or "://" in v)


def resolve_rules(value: object, base: Path | None) -> tuple[Path | None, str | None]:
    """(the rules directory, None), or (None, why it cannot be used). A relative path is
    relative to `base` (the engagement folder)."""
    if not isinstance(value, (str, os.PathLike)) or not str(value).strip():
        return None, NO_RULES
    text = str(value).strip()
    if is_registry_value(text):
        return None, (f"scanners.sast.rules is not a local rules directory: {text!r}; "
                      "registry names and URLs are never fetched")
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    path = path.resolve()
    if not path.is_dir():
        return None, f"rules directory not found: {path}"
    if not rule_files(path):
        return None, f"no rule files (.yml, .yaml) in {path}"
    return path, None


def rule_files(rules: Path) -> list[Path]:
    return sorted(p for p in rules.rglob("*") if p.is_file() and p.suffix in RULE_SUFFIXES)


def rules_digest(value: object, base: Path | None) -> str:
    """What the scan's freshness depends on beyond the options: the rule files' contents and
    whether opengrep is on PATH. Empty when no usable rules are configured."""
    rules, note = resolve_rules(value, base)
    if rules is None:
        return ""
    h = hashlib.sha256()
    for p in rule_files(rules):
        h.update(p.relative_to(rules).as_posix().encode("utf-8") + b"\0")
        try:
            h.update(p.read_bytes() + b"\0")
        except OSError:  # Opengrep reports it when it runs; the hash must not fail the phase
            h.update(b"\0unreadable\0")
    h.update(str(shutil.which("opengrep") is not None).encode("utf-8"))
    return h.hexdigest()[:16]


def opengrep_command(root: Path, rules: Path) -> list[str]:
    return ["opengrep", "scan", "--config", str(rules), *OPENGREP_FLAGS, str(root)]


def _env(root: Path) -> dict[str, str]:
    """git's hardened environment (Opengrep may call git in the vetted repository), without
    any SEMGREP_*/OPENGREP_* variable: SEMGREP_RULES alone would add registry rules."""
    return {k: v for k, v in git_env(root).items()
            if not k.upper().startswith(("SEMGREP", "OPENGREP"))}


def _first_error(data: object, stderr: bytes | None) -> str:
    errors = data.get("errors") if isinstance(data, dict) else None
    if isinstance(errors, list):
        for e in errors:
            msg = e.get("message") if isinstance(e, dict) else None
            if msg:
                return str(msg).strip().splitlines()[0]
    lines = (stderr or b"").decode("utf-8", "replace").strip().splitlines()
    return (lines or ["?"])[-1]


def run_opengrep(root: Path, rules: object, *, base: Path | None = None,
                 which: Callable[[str], str | None] = shutil.which,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 ) -> tuple[list[dict], list[str], str | None]:
    """(results, error messages Opengrep reported, note). A note means Opengrep did not run
    or failed, and nothing else is returned. Never raises."""
    rules_dir, note = resolve_rules(rules, base)
    if rules_dir is None:
        return [], [], note
    if which("opengrep") is None:
        return [], [], "opengrep not installed"
    try:
        env = _env(root)
    except GitError as exc:
        return [], [], f"opengrep not run: {exc}"[:300]
    root = root.resolve()  # Opengrep runs in its own folder, so a relative root would break
    with tempfile.TemporaryDirectory(prefix="unvarnish-opengrep-") as tmp:
        try:
            # An empty working directory: no ignore file of the consultant's folder applies.
            proc = run(opengrep_command(root, rules_dir), capture_output=True, timeout=1800,
                       env=env, cwd=tmp)
        except (OSError, subprocess.SubprocessError) as exc:
            return [], [], f"opengrep failed: {exc}"[:300]
    try:
        data = json.loads(proc.stdout or b"{}")
    except ValueError as exc:
        data = None
        if proc.returncode in OK_CODES:
            return [], [], f"opengrep output unreadable: {exc}"[:300]
    if proc.returncode not in OK_CODES:
        return [], [], f"opengrep failed: {_first_error(data, proc.stderr)}"[:300]
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        return [], [], "opengrep output unreadable: no results list"
    results = [r for r in data.get("results", []) if isinstance(r, dict)]
    for r in results:
        r["path"] = _relative(str(r.get("path", "")), root)
    raw_errors = data.get("errors")
    errors = [str(e.get("message") or e.get("type") or "error").strip()
              for e in (raw_errors if isinstance(raw_errors, list) else [])
              if isinstance(e, dict)]
    return results, errors, None
