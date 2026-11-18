from __future__ import annotations

from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural

MAX_LISTED = 10


class GeneratedBulkScanner:
    name = "generated_bulk"
    category = Category.process

    def run(self, ctx: ScanContext) -> list[Finding]:
        g = ctx.git
        if not g.available or not g.large_commits:
            return []
        commits = sorted(g.large_commits, key=lambda c: -(c.lines_added + c.lines_deleted))
        bulk = sum(c.lines_added + c.lines_deleted for c in g.large_commits)
        everything = sum(a.lines_changed for a in [*g.authors, *g.bots])
        share = f", {bulk / everything:.0%} of all changed lines" if everything else ""
        trailers = g.ai_fingerprints.coauthor_trailers
        ai = (" The history carries AI co-author trailers ("
              + ", ".join(f"{name} ×{n}" for name, n in trailers.items())
              + "), consistent with generated code committed in bulk.") if trailers else ""
        evidence = [Evidence(path=".", note=(
            f"{c.sha[:12]} {c.date.date()} {c.author}: +{c.lines_added:,} -{c.lines_deleted:,} "
            f"in {plural(c.files, 'file')}: {c.message_head[:80]}")) for c in commits[:MAX_LISTED]]
        return [Finding(
            tool=ctx.tool, category=self.category, severity=Severity.medium,
            title="Bulk commits",
            summary=(f"{plural(len(g.large_commits), 'commit')} "
                     f"{'changed' if len(g.large_commits) == 1 else 'each changed'} more than "
                     f"{g.large_commit_threshold:,} lines ({bulk:,} lines{share}).{ai}"),
            impact=("Changes this large are rarely reviewed line by line; they are typical of "
                    "generated code pasted in wholesale, so defects and copied secrets slip "
                    "through."),
            remediation=("Review the largest of these commits for code nobody owns, and require "
                         "smaller, reviewed changes from now on."),
            evidence=evidence, source=Source.scanner, scanner=self.name, tags=["bulk"],
            **rule_effort(ctx, self.name, "bulk_commits"),
        )]
