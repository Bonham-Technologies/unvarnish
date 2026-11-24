from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, date, datetime
from pathlib import PurePosixPath

from unvarnish.analysis import vulndata
from unvarnish.analysis.licences import copyleft, expression, satisfied
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.end_of_life import age_phrase, max_data_age_days
from unvarnish.scanners.hardcoded_infra import scrub_text
from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
    AdvisoryExploit,
    Category,
    Evidence,
    Finding,
    Severity,
    Source,
)
from unvarnish.schemas.inventory import DependencyRecord
from unvarnish.util.plural import plural

LOCKFILE_NAMES: dict[str, set[str]] = {
    "pypi": {"poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"},
    "npm": {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"},
    "cargo": {"Cargo.lock"},
    "go": {"go.sum"},
}
EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][\w.]+)?$")
LOCAL_PREFIXES = ("path:", "file:", "link:", "portal:", "workspace")
GIT_PREFIXES = ("git:", "git+", "git://", "github:", "gitlab:", "bitbucket:")
GIT_PINNED_RE = re.compile(r"#(?:rev=)?[0-9a-fA-F]{7,40}$")
MAX_LISTED = 10
MAX_UNPINNED = 20
NAME = "dependencies"
# EPSS moves daily and the KEV catalog grows weekly, so exploit data ages faster than
# end-of-life dates (UNVAR-90); `max_data_age_days` overrides it.
DEFAULT_EXPLOIT_DATA_AGE_DAYS = 30
# The old-data note starts "<NAME>: exploit data dated <date> is <age_phrase>"; the findings
# document's "Known exploited" row reads the phrase back (exploit_data_age_warning).
EXPLOIT_AGE_NOTE_RE = re.compile(rf"^{NAME}: exploit data dated \d{{4}}-\d{{2}}-\d{{2}} is "
                                 r"(\d+ days? old, older than the \d+-day limit)")


def is_pinned(rec: DependencyRecord) -> bool:
    c = (rec.constraint or "").strip()
    if rec.ecosystem == "go":
        return True  # go.mod requires an exact version for every module
    if rec.ecosystem == "maven" and not c:
        return True  # version managed by a BOM or parent POM
    if not c:
        return False
    if c.startswith(LOCAL_PREFIXES):
        return True  # local path or workspace member: not resolved from a registry
    if c.startswith(GIT_PREFIXES):
        return bool(GIT_PINNED_RE.search(c))  # pinned only to a commit
    if rec.ecosystem == "pypi":
        if EXACT_VERSION.match(c):
            return True  # Poetry: a bare version is exact
        return c.startswith(("==", "===")) and "*" not in c and "," not in c
    if rec.ecosystem == "npm":
        if c.startswith("npm:"):
            c = c.rsplit("@", 1)[-1]  # alias: npm:other@1.2.3
        return bool(EXACT_VERSION.match(c.removeprefix("=")))
    if rec.ecosystem == "cargo":
        return c.startswith("=")  # a bare Cargo version means ^version
    if rec.ecosystem == "maven":
        return not any(t in c for t in ("[", "(", "LATEST", "RELEASE"))
    return True


def _severity(value: str | None) -> Severity:
    try:
        return Severity(value or "medium")
    except ValueError:
        return Severity.medium


def _percent(value: float) -> str:
    """0.94358 -> "94.36", 0.5 -> "50"; never "100" for a value below 1."""
    shown = round(value * 100, 2)
    if shown >= 100 and value < 1:
        shown = 99.99
    return f"{shown:g}"


def exploit_text(a: dict) -> str:
    """" [Known exploited (CISA KEV, added 2021-12-10); EPSS 94.36%, percentile 99.97]" for
    an advisory the exploit data bundle marked; "" for one it did not (no bundle)."""
    if "kev" not in a:
        return ""
    parts = []
    if a.get("kev"):
        parts.append(f"Known exploited (CISA KEV, added {a.get('kev_date_added') or '?'})")
    if a.get("epss") is not None:
        parts.append(f"EPSS {_percent(a['epss'])}%, percentile "
                     f"{_percent(a.get('epss_percentile') or 0.0)}")
    else:
        parts.append("no EPSS score")
    return " [" + "; ".join(parts) + "]"


def exploit_rank(a: dict) -> tuple[int, float]:
    """Known exploited first, then the likeliest to be exploited (EPSS)."""
    return (0 if a.get("kev") else 1, -(a.get("epss") or 0.0))


def _exploits(advs: list[dict]) -> list[AdvisoryExploit] | None:
    if not any("kev" in a for a in advs):
        return None
    return [AdvisoryExploit(advisory=a.get("id", "?"), cves=vulndata.advisory_cves(a),
                            kev=bool(a.get("kev")), kev_date_added=a.get("kev_date_added"),
                            epss=a.get("epss"), epss_percentile=a.get("epss_percentile"))
            for a in advs]


def exploit_data_age_warning(notes: list[str]) -> str | None:
    """"45 days old, older than the 30-day limit" from the scan's old-exploit-data note, for
    the findings document's row; None when the data was within the limit."""
    for note in notes:
        if m := EXPLOIT_AGE_NOTE_RE.match(note):
            return m.group(1)
    return None


class DependenciesScanner:
    name = NAME
    category = Category.dependency

    def __init__(self, today: date | None = None) -> None:
        self._today = today
        self.notes: list[str] = []

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.notes = self._exploit_notes(ctx)
        return self._advisories(ctx) + self._unpinned(ctx) + self._licences(ctx)

    def _licences(self, ctx: ScanContext) -> list[Finding]:
        """Packages whose deps.dev licence is outside `scanners.dependencies.licences`, one
        finding per manifest and licence; online only, and a note when not checked or when no
        allowlist is set (UNVAR-93)."""
        deps = ctx.dependencies
        if not (deps.dependencies or deps.advisories or deps.packages):
            return []
        if not deps.licences_checked:
            offline = ctx.options.get("offline", True) is not False
            why = deps.licences_note or ("offline mode" if offline else "not looked up")
            how = ("set scanners.dependencies.offline: false" if offline
                   else "fix the cause above")
            self.notes.append(
                f"{NAME}: licences: not checked ({why}); osv-scanner reads package licences "
                f"from deps.dev, so no licence is listed in the SBOM export and none is "
                f"checked against an allowlist ({how}, then rerun)")
            return []
        allow = ctx.options.get("licences")
        if allow is None:
            self.notes.append(
                f"{NAME}: licences: checked, but no allowlist is set "
                f"(scanners.dependencies.licences), so no licence is flagged")
            return []
        if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
            self.notes.append(
                f"{NAME}: licences: scanners.dependencies.licences must be a list of SPDX "
                f"licence identifiers; no licence was checked against it")
            return []
        allowed = {x.strip().lower() for x in allow}
        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for p in deps.packages:
            expr = expression(p.licences)
            if expr is not None and satisfied(expr, lambda lic: lic.lower() in allowed):
                continue
            shown = f"{p.name} {p.version}"
            key = (p.manifest or ".", expr or "")
            if shown not in groups[key]:
                groups[key].append(shown)
        out = []
        for (manifest, expr), names in sorted(groups.items()):
            n = len(names)
            listed = ", ".join(names[:MAX_UNPINNED])
            extra = f" (+{n - MAX_UNPINNED} more)" if n > MAX_UNPINNED else ""
            pkgs = plural(n, "package")
            verb = "is" if n == 1 else "are"
            if expr:
                title = f"Dependency licence outside the allowlist: {expr}"
                what = f"{verb} licensed {expr}, which the licence allowlist does not include"
            else:
                title = "Dependency licence not known"
                what = (f"{'has' if n == 1 else 'have'} no licence deps.dev can name, so it "
                        f"cannot be checked against the licence allowlist")
            strong = bool(expr) and copyleft(expr)
            impact = ("A copyleft licence can require the source of software that includes "
                      "the package to be released under the same terms when it is "
                      "distributed; the tool cannot be handed on outside the company until "
                      "legal has cleared it." if strong else
                      "The licence's terms have not been approved for this use, so the tool "
                      "should not be distributed until they are reviewed.")
            out.append(Finding(
                tool=ctx.tool, category=Category.compliance,
                severity=Severity.medium if strong else Severity.low,
                title=title,
                summary=(f"{pkgs} resolved from {manifest} {what} "
                         f"(scanners.dependencies.licences): {listed}{extra}."),
                impact=impact,
                remediation=("Have legal clear the licence for how the tool is used and "
                             "distributed, or replace the package with one under an approved "
                             "licence; add licences legal accepts to "
                             "scanners.dependencies.licences."),
                evidence=[Evidence(path=manifest,
                                   note=f"licence {expr or 'not known'}: {listed}{extra}")],
                source=Source.scanner, scanner=self.name, tags=["licence"],
                **rule_effort(ctx, self.name, "licences"),
            ))
        return out

    def _exploit_notes(self, ctx: ScanContext) -> list[str]:
        """One note without exploit data, or with data older than `max_data_age_days`; the
        findings are made from old data all the same (UNVAR-90)."""
        deps = ctx.dependencies
        if not deps.exploit_data_date:
            why = deps.exploit_data_note or vulndata.NO_BUNDLE
            return [f"{NAME}: exploit data: not checked ({why}); advisories are not marked as "
                    f"known exploited (CISA KEV) or ordered by exploit likelihood (EPSS) (run "
                    f"`unvarnish vulndata refresh` while online, or set {vulndata.DIR_ENV} to "
                    f"a folder holding {vulndata.BUNDLE_NAME}, then rerun)"]
        try:
            fetched = date.fromisoformat(deps.exploit_data_date)
        except ValueError:
            return []
        today = self._today or datetime.now(UTC).date()
        limit = max_data_age_days(ctx.options.get("max_data_age_days"),
                                  DEFAULT_EXPLOIT_DATA_AGE_DAYS)
        age = (today - fetched).days
        if age <= limit:
            return []
        return [f"{NAME}: exploit data dated {fetched.isoformat()} is {age_phrase(age, limit)} "
                f"(max_data_age_days); vulnerabilities CISA added to its KEV catalog since "
                f"then are not marked as known exploited, and EPSS scores are as of that date. "
                f"The findings still use this data (run `unvarnish vulndata refresh` while "
                f"online, then rerun)"]

    def _advisories(self, ctx: ScanContext) -> list[Finding]:
        deps = ctx.dependencies
        if not deps.advisories_checked:
            return []
        groups: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
        for a in deps.advisories:
            key = (a.get("ecosystem", "?"), a.get("package", "?"), a.get("version", "?"),
                   a.get("manifest") or ".")
            groups[key].append(a)
        out: list[Finding] = []
        for (eco, pkg, ver, manifest), advs in sorted(groups.items()):
            advs = sorted(advs, key=exploit_rank)  # stable: unchanged without exploit data
            sev = min((_severity(a.get("severity")) for a in advs),
                      key=SEVERITY_ORDER.__getitem__)
            ids = [a.get("id", "?") for a in advs]
            listed = "; ".join(f"{a.get('id', '?')}: {a.get('summary') or 'no summary'}"
                               f"{exploit_text(a)}" for a in advs[:MAX_LISTED])
            more = f"; and {len(advs) - MAX_LISTED} more" if len(advs) > MAX_LISTED else ""
            n = len(advs)
            count = "1 published advisory affects" if n == 1 else f"{n} published advisories affect"
            impact = ("The tool ships a dependency with publicly documented weaknesses; "
                      "exploit details for published advisories are usually available.")
            known = [a.get("id", "?") for a in advs if a.get("kev")]
            if known:
                impact += (f" CISA's Known Exploited Vulnerabilities catalog lists "
                           f"{', '.join(known)} as exploited in the wild.")
            out.append(Finding(
                tool=ctx.tool, category=self.category, severity=sev,
                title=f"Known vulnerabilities in {pkg} {ver}",
                summary=f"{count} {pkg} {ver} ({eco}), declared in {manifest}: {listed}{more}.",
                impact=impact,
                remediation=(f"Upgrade {pkg} to a release that fixes these advisories, then "
                             "re-run the scan. Check the advisories for configuration "
                             "workarounds if an upgrade must wait."),
                evidence=[Evidence(path=manifest, note="advisories: " + ", ".join(ids))],
                source=Source.scanner, scanner=self.name,
                tags=["advisory", *(["known-exploited"] if known else []), *ids[:5]],
                exploits=_exploits(advs), **rule_effort(ctx, self.name, "advisories"),
            ))
        return out

    def _unpinned(self, ctx: ScanContext) -> list[Finding]:
        names = {PurePosixPath(f.path).name for f in ctx.census.files}
        locked = {eco for eco, files in LOCKFILE_NAMES.items() if names & files}
        loose = [d for d in ctx.dependencies.dependencies
                 if not d.dev and d.ecosystem not in locked and not is_pinned(d)]
        if not loose:
            return []
        by_manifest: dict[str, list[DependencyRecord]] = defaultdict(list)
        for d in loose:
            by_manifest[d.manifest].append(d)
        evidence = []
        for manifest, ds in sorted(by_manifest.items()):
            shown = ", ".join(f"{d.name} {scrub_text(d.constraint or '(any version)')}"
                              for d in ds[:MAX_UNPINNED])
            extra = f" (+{len(ds) - MAX_UNPINNED} more)" if len(ds) > MAX_UNPINNED else ""
            evidence.append(Evidence(path=manifest, note=f"unpinned: {shown}{extra}"))
        n = len(loose)
        return [Finding(
            tool=ctx.tool, category=self.category, severity=Severity.medium,
            title="Unpinned dependencies without a lockfile",
            summary=(f"{plural(n, 'dependency')} across {plural(len(by_manifest), 'manifest')} "
                     f"{'accepts' if n == 1 else 'accept'} a range of versions and no lockfile "
                     f"records which version was actually installed."),
            impact=("Each install can resolve to a different release, including a broken or "
                    "compromised one; builds are not reproducible and an audit cannot say "
                    "what code actually runs."),
            remediation=("Commit the package manager's lockfile, or pin exact versions in the "
                         "manifest, and update them deliberately."),
            evidence=evidence, source=Source.scanner, scanner=self.name, tags=["unpinned"],
            **rule_effort(ctx, self.name, "unpinned"),
        )]
