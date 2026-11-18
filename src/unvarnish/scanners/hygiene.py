from __future__ import annotations

import re

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source

CI_PATHS = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
            ".circleci", "bitbucket-pipelines.yml", ".travis.yml", "cloudbuild.yaml"]
LINTER_CONFIGS = ["ruff.toml", ".ruff.toml", ".flake8", "setup.cfg", "tox.ini", ".pylintrc",
                  ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs",
                  "eslint.config.js", "eslint.config.mjs", "biome.json", ".prettierrc",
                  ".golangci.yml", ".golangci.yaml", "rustfmt.toml", ".rustfmt.toml",
                  "clippy.toml", "checkstyle.xml", ".editorconfig", ".stylelintrc", "phpcs.xml",
                  ".rubocop.yml"]
README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}
LICENSE_NAMES = {"license", "license.md", "license.txt", "licence", "licence.md", "copying"}
TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
TODO_PER_KLOC_THRESHOLD = 5
MAX_EVIDENCE = 20

EMPTY_HANDLER_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"^\s*except(?:\s+[\w.(), ]+)?\s*:\s*\n\s*pass\b", re.MULTILINE),
    "javascript": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "typescript": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "tsx": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "java": re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"),
    "c_sharp": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "go": re.compile(r"if\s+err\s*!=\s*nil\s*\{\s*\}"),
}


def _pyproject_has_linter(ctx: ScanContext) -> bool:
    p = ctx.source_root / "pyproject.toml"
    if not p.exists():
        return False
    text = p.read_text(errors="replace", encoding="utf-8")
    return any(k in text for k in ("[tool.ruff", "[tool.black", "[tool.flake8",
                                   "[tool.pylint", "[tool.mypy"))



def todo_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) for TODO/FIXME/HACK lines. Lines split on newlines only, so form
    feeds and Unicode line separators do not shift numbers away from the editor's."""
    return [(n, line) for n, line in enumerate(text.split("\n"), start=1)
            if TODO_RE.search(line)]

class HygieneScanner:
    name = "hygiene"
    category = Category.process

    def _presence(self, ctx: ScanContext, rule: str, title: str, severity: Severity,
                  category: Category, summary: str, impact: str, remediation: str) -> Finding:
        return Finding(tool=ctx.tool, category=category, severity=severity, title=title,
                       summary=summary, impact=impact, remediation=remediation,
                       evidence=[Evidence(path=".", note="repository root")],
                       source=Source.scanner, scanner=self.name,
                       **rule_effort(ctx, self.name, rule))

    def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.source_root
        files = [f for f in ctx.census.files if not f.excluded]
        names_lower = {f.path.lower() for f in files}
        findings: list[Finding] = []

        if not any(f.classification == Classification.test for f in files):
            findings.append(self._presence(
                ctx, "no_tests", "No automated tests", Severity.medium, Category.process,
                "The tool has no test files of any kind.",
                "Every change is verified by hand or not at all; regressions reach users.",
                "Add a test runner and cover the main paths before any further change.",
            ))
        if not any((root / p).exists() for p in CI_PATHS):
            findings.append(self._presence(
                ctx, "no_ci", "No continuous integration configuration", Severity.medium,
                Category.process,
                "No CI pipeline definition was found.",
                "Nothing runs tests, linting, or builds automatically; quality depends on "
                "individual discipline.",
                "Add a pipeline that runs tests and linting on every push.",
            ))
        if not any(n in names_lower for n in README_NAMES):
            findings.append(self._presence(
                ctx, "no_readme", "No README", Severity.low, Category.process,
                "No README describes what the tool is or how to run it.",
                "Knowledge lives only in the author's head.",
                "Write a README covering purpose, setup, and operation.",
            ))
        if not any(n in names_lower for n in LICENSE_NAMES):
            findings.append(self._presence(
                ctx, "no_license", "No license file", Severity.low, Category.compliance,
                "No license or ownership statement is present.",
                "Ownership and permitted use of the code are undefined, which matters once it "
                "is shared or handed over.",
                "Add an internal-use license or ownership notice agreed with legal.",
            ))
        linter_names = set(LINTER_CONFIGS)
        has_linter = any(f.path.rsplit("/", 1)[-1] in linter_names for f in files)
        if not has_linter and not _pyproject_has_linter(ctx):
            findings.append(self._presence(
                ctx, "no_linter", "No linter or formatter configuration", Severity.low,
                Category.maintainability,
                "No linting or formatting configuration was found.",
                "Style and common defects are not checked automatically.",
                "Adopt the standard linter for the language and run it in CI.",
            ))

        # TODO density and swallowed errors over source files
        source_files = [
            f for f in files
            if f.classification in (Classification.source, Classification.test) and f.language
        ]
        total_lines = sum(f.lines for f in source_files) or 1
        todo_evidence: list[Evidence] = []
        handler_evidence: list[Evidence] = []
        todo_count = 0
        for f in source_files:
            text = (root / f.path).read_text(errors="replace", encoding="utf-8")
            for lineno, line in todo_lines(text):
                if True:
                    todo_count += 1
                    if len(todo_evidence) < MAX_EVIDENCE:
                        todo_evidence.append(Evidence(path=f.path, line_start=lineno,
                                                      excerpt=line.strip()[:120]))
            pattern = EMPTY_HANDLER_PATTERNS.get(f.language or "")
            if pattern:
                for m in pattern.finditer(text):
                    if len(handler_evidence) >= MAX_EVIDENCE:
                        break
                    lineno = text.count("\n", 0, m.start()) + 1
                    handler_evidence.append(Evidence(path=f.path, line_start=lineno,
                                                     excerpt=m.group(0).strip()[:120]))

        if todo_evidence and (todo_count * 1000 / total_lines) > TODO_PER_KLOC_THRESHOLD:
            findings.append(Finding(
                tool=ctx.tool, category=Category.maintainability, severity=Severity.low,
                title="High density of TODO/FIXME/HACK markers",
                summary=f"{todo_count} unresolved markers across {total_lines:,} source lines.",
                impact="Known gaps are documented only as comments and will be forgotten.",
                remediation="Convert markers into tracked issues or resolve them.",
                evidence=todo_evidence, source=Source.scanner, scanner=self.name,
                tags=["group:todo_density", f"count:{todo_count}"],
                **rule_effort(ctx, self.name, "todo_density"),
            ))
        if handler_evidence:
            findings.append(Finding(
                tool=ctx.tool, category=Category.reliability, severity=Severity.medium,
                title="Swallowed errors",
                summary=(f"{len(handler_evidence)} empty exception or error handlers discard "
                         f"failures silently."),
                impact="Failures go unnoticed; data may be lost or corrupted without any signal.",
                remediation=("Log and surface errors, or handle them explicitly with a "
                             "documented reason."),
                evidence=handler_evidence, source=Source.scanner, scanner=self.name,
                tags=["group:swallowed_errors", f"count:{len(handler_evidence)}"],
                **rule_effort(ctx, self.name, "swallowed_errors"),
            ))
        return findings
