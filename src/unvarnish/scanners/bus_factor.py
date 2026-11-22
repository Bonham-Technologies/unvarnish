from __future__ import annotations

from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural


class BusFactorScanner:
    name = "bus_factor"
    category = Category.process

    def run(self, ctx: ScanContext) -> list[Finding]:
        g = ctx.git
        if not g.available or g.commit_count < 2 or not g.authors:
            return []
        threshold = float(ctx.options.get("single_author_share", 0.9))
        top = g.authors[0]
        shares = ", ".join(f"{a.name} {a.share:.0%}" for a in g.authors[:5])
        evidence = [Evidence(path=".",
                             note=(f"{plural(g.commit_count, 'commit')}; "
                                   f"shares by changed lines: {shares}"))]

        if top.share > threshold:
            return [Finding(
                tool=ctx.tool, category=self.category, severity=Severity.high,
                title="Single-author concentration",
                summary=(f"{top.name} authored {top.share:.0%} of all changed lines across "
                         f"{plural(g.commit_count, 'commit')}; "
                         f"{plural(len(g.authors), 'author')} in total "
                         f"(threshold {threshold:.0%})."),
                impact=("Knowledge of how this tool works lives with one person. If they leave "
                        "or are unavailable, nobody can safely change or operate it."),
                remediation=("Pair a second maintainer with the author now and document the "
                             "design before handover."),
                evidence=evidence, source=Source.scanner, scanner=self.name,
                **rule_effort(ctx, self.name, "single_author"),
            )]
        if g.bus_factor == 1 and len(g.authors) > 1:
            return [Finding(
                tool=ctx.tool, category=self.category, severity=Severity.medium,
                title="Low bus factor",
                summary=(f"One author ({top.name}, {top.share:.0%}) accounts for at least 80% "
                         f"of changes; {plural(len(g.authors), 'author')} in total."),
                impact="Most knowledge of the tool sits with one person.",
                remediation=("Spread ownership through reviews and shared on-call before "
                             "relying on this tool."),
                evidence=evidence, source=Source.scanner, scanner=self.name,
                **rule_effort(ctx, self.name, "low_bus_factor"),
            )]
        return []
