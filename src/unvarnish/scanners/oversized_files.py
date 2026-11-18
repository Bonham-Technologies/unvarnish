from __future__ import annotations

from collections.abc import Callable

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source
from unvarnish.schemas.inventory import FileMetrics
from unvarnish.util.plural import plural

MAX_LISTED = 25


class OversizedFilesScanner:
    name = "oversized_files"
    category = Category.maintainability

    def run(self, ctx: ScanContext) -> list[Finding]:
        file_lines = int(ctx.options.get("file_lines", 1500))
        function_lines = int(ctx.options.get("function_lines", 150))
        script_lines = int(ctx.options.get("html_script_lines", 500))
        findings: list[Finding] = []
        classes = {r.path: r.classification for r in ctx.census.files}
        big_files: list[FileMetrics] = []
        huge: list[FileMetrics] = []
        long_fns: list[FileMetrics] = []

        for fm in ctx.metrics.files:
            if fm.html is not None:
                if fm.html.script_lines > script_lines:
                    findings.append(Finding(
                        tool=ctx.tool, category=self.category, severity=Severity.high,
                        title="Inline script in HTML exceeds threshold",
                        summary=(
                            f"{fm.path} embeds {fm.html.script_lines:,} lines of JavaScript "
                            f"across {plural(fm.html.script_blocks, 'script block')} and "
                            f"{fm.html.style_lines:,} lines of CSS, in a file of "
                            f"{fm.lines:,} lines (threshold {script_lines:,})."
                        ),
                        impact=(
                            "Application logic inside an HTML file cannot be linted, tested, "
                            "or reviewed with standard tooling, and every change risks the "
                            "whole page."
                        ),
                        remediation=(
                            "Move scripts and styles into separate files under a build step; "
                            "split by feature."
                        ),
                        evidence=[Evidence(path=fm.path, line_start=1, line_end=fm.lines)],
                        source=Source.scanner, scanner=self.name,
                        **rule_effort(ctx, self.name, "inline_script"),
                    ))

            if fm.lines > file_lines:
                big_files.append(fm)
            if (fm.max_function_lines and fm.max_function_lines > function_lines
                    and classes.get(fm.path) != Classification.test):
                # A long describe() or test-case callback is not a design problem.
                (huge if fm.max_function_lines > 5 * function_lines else long_fns).append(fm)

        if big_files:
            findings.append(self._group(
                ctx, big_files, rule="file", key=lambda fm: fm.lines, severity=Severity.high,
                titles=("Oversized file", "Oversized files"), noun="file",
                threshold=file_lines,
                impact=("Files this large are not readable in one sitting, hide duplicated "
                        "logic, and make ownership and review impractical."),
                remediation="Split by responsibility into modules of a few hundred lines each.",
                evidence=lambda fm: Evidence(path=fm.path, line_start=1, line_end=fm.lines,
                                             note=f"{fm.lines:,} lines")))
        for group, rule, severity, titles in (
                (huge, "very_large_function", Severity.high,
                 ("Very large function", "Very large functions")),
                (long_fns, "function", Severity.medium,
                 ("Oversized function", "Oversized functions"))):
            if group:
                findings.append(self._group(
                    ctx, group, rule=rule, key=lambda fm: fm.max_function_lines or 0,
                    severity=severity,
                    titles=titles, noun="function", threshold=function_lines,
                    impact=("A function this long cannot be unit tested or reasoned about; "
                            "defects hide in it."),
                    remediation="Extract cohesive steps into named functions with their own tests.",
                    evidence=lambda fm: Evidence(
                        path=fm.path, line_start=fm.max_function_start,
                        line_end=fm.max_function_end,
                        note=f"{fm.max_function_name or 'a function'}: "
                             f"{fm.max_function_lines:,} lines"),
                    label=lambda fm: f"{fm.max_function_name or 'a function'} in {fm.path}"))
        return findings

    def _group(self, ctx: ScanContext, items: list[FileMetrics], *, rule: str,
               key: Callable[[FileMetrics], int], severity: Severity,
               titles: tuple[str, str], noun: str, threshold: int, impact: str,
               remediation: str, evidence: Callable[[FileMetrics], Evidence],
               label: Callable[[FileMetrics], str] | None = None) -> Finding:
        """One finding for every file or function over a threshold, longest first."""
        items = sorted(items, key=lambda fm: (-key(fm), fm.path))
        n, top = len(items), items[0]
        name = label(top) if label else top.path
        if n == 1:
            summary = f"{name} is {key(top):,} lines (threshold {threshold:,})."
        else:
            listed = (f" The {MAX_LISTED} longest are listed." if n > MAX_LISTED else "")
            summary = (f"{n} {noun}s are longer than {threshold:,} lines; the longest is "
                       f"{name} ({key(top):,} lines).{listed}")
        return Finding(
            tool=ctx.tool, category=self.category, severity=severity,
            title=titles[0] if n == 1 else titles[1], summary=summary, impact=impact,
            remediation=remediation, evidence=[evidence(fm) for fm in items[:MAX_LISTED]],
            source=Source.scanner, scanner=self.name, tags=[f"group:{rule}", f"count:{n}"],
            **rule_effort(ctx, self.name, rule),
        )
