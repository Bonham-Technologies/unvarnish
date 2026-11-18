from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PurePosixPath

from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.hardcoded_infra import scrub_text
from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
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


class DependenciesScanner:
    name = "dependencies"
    category = Category.dependency

    def run(self, ctx: ScanContext) -> list[Finding]:
        return self._advisories(ctx) + self._unpinned(ctx)

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
            sev = min((_severity(a.get("severity")) for a in advs),
                      key=SEVERITY_ORDER.__getitem__)
            ids = [a.get("id", "?") for a in advs]
            listed = "; ".join(f"{a.get('id', '?')}: {a.get('summary') or 'no summary'}"
                               for a in advs[:MAX_LISTED])
            more = f"; and {len(advs) - MAX_LISTED} more" if len(advs) > MAX_LISTED else ""
            n = len(advs)
            count = "1 published advisory affects" if n == 1 else f"{n} published advisories affect"
            out.append(Finding(
                tool=ctx.tool, category=self.category, severity=sev,
                title=f"Known vulnerabilities in {pkg} {ver}",
                summary=f"{count} {pkg} {ver} ({eco}), declared in {manifest}: {listed}{more}.",
                impact=("The tool ships a dependency with publicly documented weaknesses; "
                        "exploit details for published advisories are usually available."),
                remediation=(f"Upgrade {pkg} to a release that fixes these advisories, then "
                             "re-run the scan. Check the advisories for configuration "
                             "workarounds if an upgrade must wait."),
                evidence=[Evidence(path=manifest, note="advisories: " + ", ".join(ids))],
                source=Source.scanner, scanner=self.name, tags=["advisory", *ids[:5]],
                **rule_effort(ctx, self.name, "advisories"),
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
