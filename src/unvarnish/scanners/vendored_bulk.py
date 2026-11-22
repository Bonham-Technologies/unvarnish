from __future__ import annotations

from pathlib import PurePosixPath

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import is_are, plural, pluralize

MAX_LISTED = 20


def mb(n: int) -> str:
    return f"{n / 1_000_000:.1f} MB"


class VendoredBulkScanner:
    name = "vendored_bulk"
    category = Category.maintainability

    def run(self, ctx: ScanContext) -> list[Finding]:
        return self._directories(ctx) + self._binaries(ctx)

    def _directories(self, ctx: ScanContext) -> list[Finding]:
        dirs: dict[str, list[int]] = {}
        for rec in ctx.census.files:
            reason = rec.exclusion_reason or ""
            if not reason.startswith(("vendored:", "build_output:")):
                continue  # a gitignored directory is "gitignore", so it is not reported
            marker = reason.split(":", 1)[1]
            parts = PurePosixPath(rec.path).parts
            top = "/".join(parts[:parts.index(marker) + 1]) if marker in parts else parts[0]
            agg = dirs.setdefault(top, [0, 0])
            agg[0] += 1
            agg[1] += rec.bytes
        if not dirs:
            return []
        ranked = sorted(dirs.items(), key=lambda kv: (-kv[1][1], kv[0]))
        files = sum(n for n, _ in dirs.values())
        size = sum(b for _, b in dirs.values())
        names = ", ".join(d for d, _ in ranked[:5])
        return [Finding(
            tool=ctx.tool, category=self.category, severity=Severity.medium,
            title="Dependency or build directories in the source",
            summary=(f"{len(dirs)} director{'y' if len(dirs) == 1 else 'ies'} of third-party or "
                     f"build output ({files:,} {pluralize(files, 'file')}, {mb(size)}) "
                     f"{is_are(len(dirs))} part of the source: {names}."),
            impact=("Third-party code is versioned alongside the tool's own: it bloats every "
                    "clone, hides local edits to dependencies, and never receives security "
                    "updates."),
            remediation=("Remove these directories from the source, list them in .gitignore, "
                         "and restore them from the package manager's manifest and lockfile "
                         "at build time."),
            evidence=[Evidence(path=d, note=f"{n:,} {pluralize(n, 'file')}, {mb(b)}")
                      for d, (n, b) in ranked[:MAX_LISTED]],
            source=Source.scanner, scanner=self.name, tags=["vendored"],
            **rule_effort(ctx, self.name, "vendored_directories"),
        )]

    def _binaries(self, ctx: ScanContext) -> list[Finding]:
        limit = int(ctx.options.get("binary_bytes", 1_000_000))
        big = sorted((r for r in ctx.census.files
                      if r.classification == Classification.binary and not r.excluded
                      and r.bytes > limit), key=lambda r: (-r.bytes, r.path))
        if not big:
            return []
        return [Finding(
            tool=ctx.tool, category=self.category, severity=Severity.medium,
            title="Large binary files in the source",
            summary=(f"{plural(len(big), 'binary file')} over {mb(limit)} "
                     f"({mb(sum(r.bytes for r in big))} in total); the largest is {big[0].path} "
                     f"({mb(big[0].bytes)})."),
            impact=("Binaries cannot be reviewed or traced to how they were built, and every "
                    "copy of the source carries them."),
            remediation=("Move build artifacts and data to an artifact store or release assets; "
                         "if a binary must be versioned, use Git LFS."),
            evidence=[Evidence(path=r.path, note=mb(r.bytes)) for r in big[:MAX_LISTED]],
            source=Source.scanner, scanner=self.name, tags=["binary"],
            **rule_effort(ctx, self.name, "binaries"),
        )]
