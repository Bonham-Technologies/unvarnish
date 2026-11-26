"""`unvarnish doctor`: whether this machine (or image) has the offline data and the tools a
run needs, how old the data is, and the exact command that fetches or installs each one
(UNVAR-101). It reads files and runs `<tool> --version`; it never touches the network unless
asked to probe the model backends.

Each data set is located by the module that reads it during a run, so the check and the run
can never disagree about where a bundle lives."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from pathlib import Path

from unvarnish import __version__
from unvarnish.analysis import advisories, eol, treesitter, vulndata
from unvarnish.config import EngagementConfig
from unvarnish.export import tools as export_tools
from unvarnish.model.base import display_url
from unvarnish.scanners import gitleaks
from unvarnish.scanners.dependencies import DEFAULT_EXPLOIT_DATA_AGE_DAYS
from unvarnish.scanners.end_of_life import max_data_age_days
from unvarnish.schemas.doctor import USABLE, BackendCheck, DoctorCheck, Status
from unvarnish.util.env import env_flag

VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
# gitleaks' git calls rely on GIT_CONFIG_COUNT, which git before 2.31 ignores (gitcmd).
MIN_GIT = (2, 31)
PROBE_TIMEOUT = 10.0
ANTHROPIC_URL = "https://api.anthropic.com"
SITE_KIT = "on a connected machine, rebuild the image: scripts/site-kit.sh"
INSTALL = {
    "git": f"install git {'.'.join(map(str, MIN_GIT))} or later  |  "
           "https://git-scm.com/downloads",
    "gitleaks": "brew install gitleaks  |  https://github.com/gitleaks/gitleaks/releases",
    "osv-scanner": "brew install osv-scanner  |  https://github.com/google/osv-scanner/releases",
}


def _dotted(version: Sequence[int]) -> str:
    return ".".join(str(x) for x in version)


def tool_version(command: Sequence[str]) -> str | None:
    """The first dotted version number a tool prints (stdout or stderr), or None."""
    try:
        done = subprocess.run(list(command), capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    m = VERSION_RE.search((done.stdout + done.stderr).decode("utf-8", errors="replace"))
    return m.group(0) if m else None


def _age(fetched: str, today: date, limit: int) -> tuple[Status, int]:
    age = (today - date.fromisoformat(fetched)).days
    return ("stale" if age > limit else "present"), age


def _check(**fields) -> DoctorCheck:
    usable = fields["status"] in USABLE
    return DoctorCheck(ready=usable or not fields["needed"], **fields)


# --- data sets ------------------------------------------------------------------------------

def _grammars(docker: bool) -> DoctorCheck:
    where, missing, total = treesitter.grammar_status()
    status: Status = ("present" if not missing else "absent" if len(missing) == total
                      else "partial")
    detail = f"{total - len(missing)} of {total} in {where}"
    if missing and status == "partial":
        detail += f"; missing: {', '.join(missing)}"
    return _check(name="tree-sitter grammars", kind="data", status=status, detail=detail,
                  needed=True, needed_for="code structure (run)",
                  refresh=SITE_KIT if docker else "unvarnish grammars fetch")


def _bundle(name: str, path: Path, load, no_bundle: str, *, limit: int, today: date,
            needed: bool, needed_for: str, refresh: str) -> DoctorCheck:
    bundle, why = load(path)
    if bundle is None:
        status: Status = "absent" if why == no_bundle else "unreadable"
        detail = f"no {path.name} in {path.parent}" if status == "absent" else f"{why}: {path}"
        return _check(name=name, kind="data", status=status, detail=detail,
                      max_age_days=limit, needed=needed, needed_for=needed_for,
                      refresh=refresh)
    fetched = bundle.fetched.isoformat()
    status, age = _age(fetched, today, limit)
    return _check(name=name, kind="data", status=status, detail=f"in {path.parent}",
                  date=fetched, age_days=age, max_age_days=limit, needed=needed,
                  needed_for=needed_for, refresh=refresh)


def _osv_databases(config: EngagementConfig, today: date, docker: bool,
                   osv_used: bool) -> DoctorCheck:
    root = advisories.local_db_dir()
    files = advisories.local_db_files(root)
    offline = config.scanners.get("dependencies", {}).get("offline", True) is not False
    limit = _exploit_limit(config)
    needed = osv_used and offline
    needed_for = ("offline advisories" if osv_used and offline else
                  "nothing: offline is false, osv.dev is queried" if osv_used else
                  f"nothing: osv-scanner disabled by {advisories.DISABLE_ENV}")
    refresh = (f"{SITE_KIT} (OSV_ECOSYSTEMS)" if docker else
               "osv-scanner scan source --offline-vulnerabilities "
               "--download-offline-databases <a folder with the tool's lockfiles>")
    if not files:
        return _check(name="OSV databases", kind="data", status="absent",
                      detail=f"no <ecosystem>/all.zip under {root}", max_age_days=limit,
                      needed=needed, needed_for=needed_for, refresh=refresh)
    fetched = advisories.database_date(root) or datetime.fromtimestamp(
        max(f.stat().st_mtime for f in files), UTC).date().isoformat()
    status, age = _age(fetched, today, limit)
    ecosystems = advisories.local_db_ecosystems(root)
    return _check(name="OSV databases", kind="data", status=status,
                  detail=f"{', '.join(ecosystems)} in {root}", date=fetched, age_days=age,
                  max_age_days=limit, needed=needed, needed_for=needed_for, refresh=refresh)


def _exploit_limit(config: EngagementConfig) -> int:
    return max_data_age_days(config.scanners.get("dependencies", {}).get("max_data_age_days"),
                             DEFAULT_EXPLOIT_DATA_AGE_DAYS)


# --- tools ----------------------------------------------------------------------------------

def _tool(name: str, binary: str, *, needed: bool, needed_for: str, install: str,
          version: Callable[[], str | None], minimum: tuple[int, ...] | None = None,
          which: Callable[[str], str | None] = shutil.which) -> DoctorCheck:
    path = which(binary)
    if path is None:
        return _check(name=name, kind="tool", status="absent", detail=f"{binary} not on PATH",
                      needed=needed, needed_for=needed_for, refresh=install)
    found = version()
    status: Status = "present"
    detail = path
    if found is None:
        detail += " (version unknown)"
    elif minimum is not None and tuple(int(x) for x in found.split(".")) < minimum:
        status = "too old"
        detail += f": {found} is older than {_dotted(minimum)}"
    return _check(name=name, kind="tool", status=status, detail=detail, version=found,
                  needed=needed, needed_for=needed_for, refresh=install)


def _weasyprint() -> DoctorCheck:
    version = export_tools.installed_weasyprint_version()
    check = _tool("weasyprint", "weasyprint", needed=True, needed_for="export (pdf)",
                  install=export_tools.INSTALL_HINTS["weasyprint"],
                  version=lambda: _dotted(version) if version else None)
    # Export still works with an older one: it writes the PDFs untagged (UNVAR-22).
    if (check.status == "present" and version is not None
            and export_tools.untagged_pdf_reason(version)):
        check.note = (f"{_dotted(version)} is older than "
                      f"{_dotted(export_tools.MIN_WEASYPRINT_TAGGED)}, so PDFs are exported "
                      "untagged")
    return check


def run_checks(config: EngagementConfig, *, today: date | None = None) -> list[DoctorCheck]:
    """Every data set and tool, in a fixed order, judged against `config`."""
    today = today or datetime.now(UTC).date()
    docker = env_flag("UNVARNISH_IN_DOCKER")
    osv_used = not env_flag(advisories.DISABLE_ENV)
    gitleaks_used = (not env_flag(gitleaks.DISABLE_ENV)
                     and config.scanners.get("secrets", {}).get("use_gitleaks", True)
                     is not False)
    eol_limit = max_data_age_days(config.scanners.get("end_of_life", {})
                                  .get("max_data_age_days"))
    pandoc = export_tools.installed_pandoc_version
    return [
        _grammars(docker),
        _bundle("end-of-life data", eol.bundle_path(), eol.load_bundle,
                "no end-of-life data bundle", limit=eol_limit, today=today, needed=True,
                needed_for="end_of_life scanner",
                refresh=("unvarnish eol refresh --dir <a mounted folder>, mounted over "
                         "/opt/eol (docs/site-kit.md)" if docker else "unvarnish eol refresh")),
        _bundle("exploit data", vulndata.bundle_path(), vulndata.load_bundle,
                vulndata.NO_BUNDLE, limit=_exploit_limit(config), today=today,
                needed=osv_used,
                needed_for=("dependencies scanner (KEV, EPSS)" if osv_used else
                            f"nothing: osv-scanner disabled by {advisories.DISABLE_ENV}"),
                refresh=("unvarnish vulndata refresh --dir <the same mounted folder> "
                         "(docs/site-kit.md)" if docker else "unvarnish vulndata refresh")),
        _osv_databases(config, today, docker, osv_used),
        _tool("pandoc", "pandoc", needed=True, needed_for="export (docx, html, pdf)",
              install=export_tools.INSTALL_HINTS["pandoc"], minimum=export_tools.MIN_PANDOC,
              version=lambda: _dotted(v) if (v := pandoc()) else None),
        _tool("Graphviz (dot)", "dot", needed=True, needed_for="export (docx, html, pdf)",
              install=export_tools.INSTALL_HINTS["dot"],
              version=lambda: tool_version(["dot", "-V"])),
        _weasyprint(),
        _tool("git", "git", needed=True, needed_for="git history, --repo", minimum=MIN_GIT,
              install=INSTALL["git"], version=lambda: tool_version(["git", "--version"])),
        _tool("gitleaks", "gitleaks", needed=gitleaks_used,
              needed_for=("secrets scanner" if gitleaks_used else
                          "nothing: disabled (use_gitleaks or "
                          f"{gitleaks.DISABLE_ENV})"),
              install=INSTALL["gitleaks"], version=lambda: tool_version(["gitleaks", "version"])),
        _tool("osv-scanner", "osv-scanner", needed=osv_used,
              needed_for=("dependency advisories" if osv_used else
                          f"nothing: disabled by {advisories.DISABLE_ENV}"),
              install=INSTALL["osv-scanner"],
              version=lambda: tool_version(["osv-scanner", "--version"])),
    ]


# --- backends (only with --probe-backend) ---------------------------------------------------

def used_backends(config: EngagementConfig) -> list[str]:
    """The backends the engagement's models name, in first-use order, each once."""
    refs = [config.models.default, *config.models.phases.values(),
            config.models.refusal_fallback]
    return list(dict.fromkeys(r.backend for r in refs if r is not None))


def backend_url(config: EngagementConfig, name: str) -> str | None:
    """The models listing of a backend: any HTTP answer from it shows the server is there."""
    cfg = config.backends.get(name)
    if cfg is None:
        return None
    if cfg.type == "anthropic":
        base = cfg.base_url or os.environ.get("ANTHROPIC_BASE_URL") or ANTHROPIC_URL
        return base.rstrip("/") + "/v1/models"
    return cfg.base_url.rstrip("/") + "/models" if cfg.base_url else None


def probe_backends(config: EngagementConfig, timeout: float = PROBE_TIMEOUT
                   ) -> list[BackendCheck]:
    """One unauthenticated GET per backend in use. No key is sent and no tokens are spent, so
    an answer of 401 counts as reachable; `config check` tests the key and the model."""
    out = []
    for name in used_backends(config):
        url = backend_url(config, name)
        if url is None:
            out.append(BackendCheck(backend=name, url="", reachable=False,
                                    detail="no such backend, or no base_url"))
            continue
        shown = display_url(url)
        req = urllib.request.Request(url, headers={"User-Agent": f"unvarnish/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                detail = f"HTTP {resp.status}"
            reachable = True
        except urllib.error.HTTPError as exc:
            reachable, detail = True, f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            reachable, detail = False, f"{type(exc).__name__}: {reason}"[:200]
        out.append(BackendCheck(backend=name, url=shown, reachable=reachable, detail=detail))
    return out
