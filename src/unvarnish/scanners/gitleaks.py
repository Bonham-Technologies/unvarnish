from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from unvarnish.util.env import env_flag
from unvarnish.util.gitcmd import GitError, git_env

DISABLE_ENV = "UNVARNISH_DISABLE_GITLEAKS"
GITLEAKS_FLAGS = ["--report-format", "json", "--report-path", "-", "--no-banner", "--redact",
                  "--exit-code", "0", "--ignore-gitleaks-allow"]
# Passed with --config so a .gitleaks.toml in the vetted repo cannot replace or allowlist the
# default rules. (gitleaks still reads the repo's .gitleaksignore; the secrets scanner
# reports that file instead.)
GITLEAKS_CONFIG = 'title = "unvarnish"\n\n[extend]\nuseDefault = true\n'


def gitleaks_commands(root: Path, history: bool, config: Path | None = None) -> list[list[str]]:
    flags = [*GITLEAKS_FLAGS, *(["--config", str(config)] if config is not None else [])]
    cmds = [["gitleaks", "dir", str(root), *flags]]
    if history:
        cmds.append(["gitleaks", "git", str(root), *flags])
    return cmds


def _relative(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        return p.as_posix()
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return ""


def run_gitleaks(root: Path, *, history: bool,
                 which: Callable[[str], str | None] = shutil.which,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 ) -> tuple[list[dict], list[dict], str | None]:
    """(tree results, history results, note). Never raises; never sees a raw secret."""
    if env_flag(DISABLE_ENV):
        return [], [], f"disabled by {DISABLE_ENV}"
    if which("gitleaks") is None:
        return [], [], "gitleaks not installed"
    try:
        # gitleaks' own `git log -p` keeps textconv on: disarm the repo's drivers for it
        env = git_env(root)
    except GitError as exc:
        return [], [], f"gitleaks not run: {exc}"[:300]
    reports: list[list[dict]] = []
    with tempfile.TemporaryDirectory(prefix="unvarnish-gitleaks-") as tmp:
        config = Path(tmp) / "gitleaks.toml"
        config.write_text(GITLEAKS_CONFIG, encoding="utf-8")
        procs = []
        for cmd in gitleaks_commands(root, history, config):
            try:
                procs.append(run(cmd, capture_output=True, timeout=1800, env=env))
            except (OSError, subprocess.SubprocessError) as exc:
                return [], [], f"gitleaks failed: {exc}"[:300]
    for proc in procs:
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            return [], [], f"gitleaks failed: {(err or ['?'])[-1]}"[:300]
        try:
            data = json.loads(proc.stdout or b"[]")
        except ValueError as exc:
            return [], [], f"gitleaks output unreadable: {exc}"[:300]
        if not isinstance(data, list):
            return [], [], "gitleaks output unreadable: not a list"
        for entry in data:
            entry["File"] = _relative(str(entry.get("File", "")), root)
        reports.append(data)
    return reports[0], (reports[1] if history else []), None
