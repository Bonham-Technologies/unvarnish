from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path, PureWindowsPath
from typing import NamedTuple

from unvarnish.util.env import env_flag

OSV_DEFAULT_ARGS = ["scan", "source", "--format", "json", "--recursive"]
DISABLE_ENV = "UNVARNISH_DISABLE_OSV"
# osv-scanner's offline databases: <folder>/<subfolder>/<ecosystem>/all.zip. The image sets
# the folder and seeds osv-scalibr/; osv-scanner's own downloads may use either subfolder.
LOCAL_DB_ENV = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
LOCAL_DB_SUBDIRS = ("osv-scalibr", "osv-scanner")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
TEXT_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                 "MEDIUM": "medium", "LOW": "low"}
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
NO_SOURCES_EXIT = 128  # "No package sources found": nothing to check, not a failure
PROGRESS_PREFIXES = ("Scanning ", "Starting filesystem walk", "Scanned ", "End status:",
                     "Loaded ", "Filtered ")
LOADED_RE = re.compile(r"^Loaded (\S+) local db", re.M)
COULD_NOT_LOAD_RE = re.compile(r"could not load db for (\S+) ecosystem: (.*)$", re.M)


def _offline(options: dict) -> bool:
    return options.get("offline", True) is not False


def osv_command(root: Path, options: dict, osv: str = "osv-scanner", *,
                config: Path | None = None) -> list[str]:
    """--offline disables every network feature, including deps.dev transitive resolution.
    --config replaces any osv-scanner.toml in the vetted repo, so it cannot hide advisories.
    --all-packages lists unaffected packages too, so unchecked ecosystems can be named.
    Online, --licenses (with no allowlist) adds deps.dev's licences to every package; the
    allowlist is Unvarnish's own (scanners.dependencies.licences) and never reaches
    osv-scanner, whose verdict a repo's config could change (UNVAR-93)."""
    args = list(options.get("osv_args") or OSV_DEFAULT_ARGS)
    if _offline(options):
        args += ["--offline", "--all-packages"]
    else:
        args += ["--licenses", "--all-packages"]
    if config is not None:
        args += ["--config", str(config)]
    return [osv, *args, str(root)]


def _cause(stderr: str) -> str:
    """The first stderr line that is not progress output."""
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    meaningful = [ln for ln in lines if not ln.startswith(PROGRESS_PREFIXES)]
    return (meaningful or lines or ["?"])[0]


def local_db_dir() -> Path:
    """Where osv-scanner keeps its offline databases: $OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
    when set (the image sets it), else the user cache folder, osv-scanner's own default."""
    configured = os.environ.get(LOCAL_DB_ENV)
    if configured:
        return Path(configured)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return Path(xdg) if xdg else Path.home() / ".cache"


def local_db_files(root: Path | None = None) -> list[Path]:
    """Every ecosystem database (`all.zip`) under the folder, sorted."""
    root = root or local_db_dir()
    return sorted(f for sub in LOCAL_DB_SUBDIRS for f in (root / sub).glob("*/all.zip")
                  if f.is_file())


def local_db_ecosystems(root: Path | None = None) -> list[str]:
    """The ecosystems that have an offline database, sorted, each once."""
    return sorted({f.parent.name for f in local_db_files(root)})


def database_date(root: Path | None = None) -> str | None:
    """The date the site kit recorded in DATE beside the databases (YYYY-MM-DD), or None."""
    try:
        date = ((root or local_db_dir()) / "DATE").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not DATE_RE.fullmatch(date):
        return None
    try:  # the pattern lets 2026-02-30 through
        datetime.date.fromisoformat(date)
    except ValueError:
        return None
    return date


def database_date_note() -> str | None:
    """The date the image's offline database was downloaded, when the site kit recorded it."""
    if not os.environ.get(LOCAL_DB_ENV):
        return None
    date = database_date()
    return f"offline database dated {date}" if date else None


def unchecked_note(report: dict, stderr: str) -> str | None:
    """Ecosystems osv-scanner found packages for but had no offline database for."""
    # Packages osv-scanner marks as local (no registry source) are never matched, whatever
    # databases are loaded; they do not make an ecosystem "not checked".
    scanned = {(p.get("package") or {}).get("ecosystem") for r in report.get("results") or []
               for p in r.get("packages") or []
               if "source=LOCAL" not in str((p.get("package") or {}).get("purl") or "")
               } - {None, ""}
    loaded = set(LOADED_RE.findall(stderr))
    reasons = {eco: reason.strip() for eco, reason in COULD_NOT_LOAD_RE.findall(stderr)}
    missing = sorted((scanned - loaded) | set(reasons))
    if not missing:
        return None
    parts = []
    for eco in missing:
        why = reasons.get(eco, "no offline database")
        parts.append(f"{eco} not checked: {why}")
    return "; ".join(parts)[:300]


def severity_from_osv(max_severity: str | None, texts: Sequence[str]) -> str:
    """CVSS score when osv-scanner gives one, else the advisory's own label, else medium."""
    try:
        score = float(max_severity) if max_severity else None
    except ValueError:
        score = None
    if score is not None:
        return ("critical" if score >= 9 else "high" if score >= 7 else
                "medium" if score >= 4 else "low")
    mapped = [TEXT_SEVERITY[t.upper()] for t in texts if t and t.upper() in TEXT_SEVERITY]
    return min(mapped, key=RANK.__getitem__) if mapped else "medium"


def _relative(path: str, root: Path) -> str:
    if not path:
        return "."
    if re.match(r"^[A-Za-z]:[\\/]", path) or "\\" in path:  # osv-scanner on Windows
        win, win_root = PureWindowsPath(path), PureWindowsPath(str(root))
        try:
            return win.relative_to(win_root).as_posix()
        except ValueError:
            return win.name
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(path).name


def parse_osv(report: dict, root: Path) -> list[dict]:
    out: list[dict] = []
    for result in report.get("results") or []:
        manifest = _relative((result.get("source") or {}).get("path", ""), root)
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            groups = pkg.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = [i for i in g.get("ids") or [] if i]
                if not ids:
                    continue
                ids += [a for a in g.get("aliases") or [] if a not in ids]
                # Each vulnerability's own aliases too: a report without `groups` lists a
                # GHSA advisory's CVE only there, and the exploit data joins on CVEs (UNVAR-90).
                for i in list(ids):
                    ids += [a for a in (vulns.get(i) or {}).get("aliases") or []
                            if a and a not in ids]
                first = vulns.get(ids[0], {})
                texts = [((vulns.get(i) or {}).get("database_specific") or {}).get("severity", "")
                         for i in ids]
                out.append({
                    "id": ids[0], "ids": ids, "package": info.get("name", "?"),
                    "version": info.get("version", "?"),
                    "ecosystem": info.get("ecosystem", "?"), "manifest": manifest,
                    "summary": first.get("summary") or (first.get("details") or "")[:200],
                    "severity": severity_from_osv(g.get("max_severity"), texts),
                })
    return out


def parse_licences(report: dict, root: Path) -> list[dict]:
    """Every package in an online report with the licences deps.dev gave it (none: [])."""
    out: list[dict] = []
    for result in report.get("results") or []:
        manifest = _relative((result.get("source") or {}).get("path", ""), root)
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            out.append({"ecosystem": info.get("ecosystem", "?"), "name": info.get("name", "?"),
                        "version": info.get("version", "?"), "manifest": manifest,
                        "licences": [str(x) for x in pkg.get("licenses") or [] if x]})
    return out


class Lookup(NamedTuple):
    checked: bool
    advisories: list[dict]
    note: str | None  # why advisories were not checked, or what was not
    packages: list[dict] | None = None  # parse_licences, online only; None when not checked


def lookup_advisories(root: Path, options: dict, *,
                      which: Callable[[str], str | None] = shutil.which,
                      run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                      ) -> tuple[bool, list[dict], str | None]:
    """(checked, advisories, note). Never raises: a missing or failing tool becomes a note."""
    return lookup_dependencies(root, options, which=which, run=run)[:3]


def lookup_dependencies(root: Path, options: dict, *,
                        which: Callable[[str], str | None] = shutil.which,
                        run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                        ) -> Lookup:
    """One osv-scanner run: advisories, and online the packages with their licences."""
    if options.get("enabled", True) is False:
        return Lookup(False, [], "disabled in engagement.yaml")
    if env_flag(DISABLE_ENV):
        return Lookup(False, [], f"disabled by {DISABLE_ENV}")
    if which("osv-scanner") is None:
        return Lookup(False, [], "osv-scanner not installed")
    with tempfile.TemporaryDirectory(prefix="unvarnish-osv-") as tmp:
        config = Path(tmp) / "osv-scanner.toml"
        config.write_text("", encoding="utf-8")
        try:
            proc = run(osv_command(root, options, config=config), capture_output=True,
                       timeout=900)
        except (OSError, subprocess.SubprocessError) as exc:
            return Lookup(False, [], f"osv-scanner failed: {exc}"[:300])
    stderr = (proc.stderr or b"").decode("utf-8", "replace")
    if proc.returncode == NO_SOURCES_EXIT:
        return Lookup(True, [], None, None if _offline(options) else [])
    if proc.returncode not in (0, 1):  # 1 means "vulnerabilities found"
        err = stderr or (proc.stdout or b"").decode("utf-8", "replace")
        return Lookup(False, [], f"osv-scanner failed: {_cause(err)}"[:300])
    try:
        report = json.loads(proc.stdout or b"{}")
        advisories = parse_osv(report, root)
        packages = None if _offline(options) else parse_licences(report, root)
    except (ValueError, AttributeError) as exc:
        return Lookup(False, [], f"osv-scanner output unreadable: {exc}"[:300])
    if not _offline(options):
        return Lookup(True, advisories, None, packages)
    notes = [n for n in (unchecked_note(report, stderr), database_date_note()) if n]
    return Lookup(True, advisories, ("; ".join(notes) or None))
