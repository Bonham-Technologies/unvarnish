"""Code-level flaws from Opengrep with the consultant's own local rules (UNVAR-89).

Optional: it runs when `opengrep` is on PATH and `scanners.sast.rules` names a local rules
directory; otherwise the run says "sast: not checked" under "Not analysed". One finding per
rule, its evidence capped at `max_evidence`, excerpts redacted. Ignore files and `nosem`
comments in the vetted source never hide a result; they are reported as suppressions.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath

from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.opengrep import rules_digest, run_opengrep
from unvarnish.scanners.secrets import MAX_SCAN_BYTES, gitleaks_title, redact_text
from unvarnish.schemas.finding import SEVERITY_ORDER, Category, Evidence, Finding, Severity, Source
from unvarnish.util.plural import plural

SEVERITIES = {
    "CRITICAL": Severity.critical, "ERROR": Severity.high, "HIGH": Severity.high,
    "WARNING": Severity.medium, "MEDIUM": Severity.medium, "INFO": Severity.low,
    "LOW": Severity.low, "INVENTORY": Severity.low, "EXPERIMENT": Severity.low,
}
CATEGORIES = {
    "security": Category.security, "correctness": Category.reliability,
    "performance": Category.reliability, "best-practice": Category.maintainability,
    "maintainability": Category.maintainability, "portability": Category.reliability,
}
IGNORE_FILES = {
    ".semgrepignore": "Opengrep's ignore file; disregarded: Unvarnish runs Opengrep with "
                      "--x-ignore-semgrepignore-files",
    # Not a default name, but what a client passes with --semgrepignore-filename.
    ".opengrepignore": "an ignore file for Opengrep's --semgrepignore-filename; disregarded: "
                       "Unvarnish runs Opengrep with --x-ignore-semgrepignore-files",
}
NOSEM_NOTE = "inline nosem comment; disregarded: Unvarnish runs Opengrep with --disable-nosem"
# Opengrep's default markers: nosem, nosemgrep and (since Opengrep 1.15) noopengrep.
NOSEM_RE = re.compile(r"\b(?:nosem(?:grep)?|noopengrep)\b", re.IGNORECASE)
EXCERPT_CHARS = 200
MESSAGE_CHARS = 400


def _excerpt(text: object) -> str | None:
    line = next((ln.strip() for ln in str(text or "").splitlines() if ln.strip()), "")
    return redact_text(line)[:EXCERPT_CHARS] or None


def _line(pos: object) -> int | None:
    value = pos.get("line") if isinstance(pos, dict) else None
    return value if isinstance(value, int) and value > 0 else None


class SastScanner:
    name = "sast"
    category = Category.security

    def __init__(self) -> None:
        self.notes: list[str] = []

    def inputs_digest(self, options: dict, engagement_root: Path | None) -> str:
        """The rule files and whether opengrep is installed: a change to either rescans."""
        return rules_digest(options.get("rules"), engagement_root)

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.notes = []
        results, errors, note = run_opengrep(ctx.source_root, ctx.options.get("rules"),
                                             base=ctx.engagement_root)
        findings: list[Finding] = []
        if note:
            self.notes.append(f"sast: not checked ({note})")
        else:
            if errors:
                first = redact_text(errors[0].splitlines()[0] if errors[0] else "?")[:200]
                self.notes.append(f"sast: Opengrep reported {plural(len(errors), 'error')}; "
                                  f"the first: {first}")
            findings = self._grouped(ctx, results)
        return findings + self._suppression(ctx)

    def _skipped(self, ctx: ScanContext) -> set[str]:
        return {r.path for r in ctx.census.files
                if r.excluded or r.classification in (Classification.binary,
                                                      Classification.vendored)}

    def _grouped(self, ctx: ScanContext, results: list[dict]) -> list[Finding]:
        max_evidence = max(1, int(ctx.options.get("max_evidence", 25)))
        known = {r.path for r in ctx.census.files}
        skipped = self._skipped(ctx)
        by_rule: dict[str, list[dict]] = {}
        for r in results:
            path = str(r.get("path") or "")
            if not path or path not in known or path in skipped:
                continue
            by_rule.setdefault(str(r.get("check_id") or "unknown"), []).append(r)
        out: list[Finding] = []
        for rule, items in sorted(by_rule.items()):
            places: dict[tuple[str, int | None], dict] = {}
            for r in sorted(items, key=lambda r: (r["path"], _line(r.get("start")) or 0)):
                places.setdefault((r["path"], _line(r.get("start"))), r)
            out.append(self._finding(ctx, rule, list(places.values()), max_evidence))
        return out

    def _finding(self, ctx: ScanContext, rule: str, items: list[dict],
                 max_evidence: int) -> Finding:
        extras = [r.get("extra") if isinstance(r.get("extra"), dict) else {} for r in items]
        severity = min((SEVERITIES.get(str(e.get("severity", "")).upper(), Severity.medium)
                        for e in extras), key=lambda s: SEVERITY_ORDER[s])
        meta = next((e["metadata"] for e in extras if isinstance(e.get("metadata"), dict)), {})
        category = CATEGORIES.get(str(meta.get("category", "")).lower(), Category.security)
        message = next((str(e["message"]) for e in extras if e.get("message")), rule)
        message = redact_text(" ".join(message.split()))[:MESSAGE_CHARS].rstrip(".")
        fp = hashlib.sha256(f"sast:{rule}".encode()).hexdigest()[:12]
        evidence = []
        for r, extra in list(zip(items, extras, strict=True))[:max_evidence]:
            start, end = _line(r.get("start")), _line(r.get("end"))
            note = f"opengrep {rule}"
            if extra.get("is_ignored"):
                note += "; marked nosem in the source, reported anyway"
            evidence.append(Evidence(path=r["path"], line_start=start, line_end=end or start,
                                     excerpt=_excerpt(extra.get("lines")), fingerprint=fp,
                                     note=note))
        files = len({r["path"] for r in items})
        shown = (f" Showing the first {max_evidence} of {len(items)}."
                 if len(items) > max_evidence else "")
        return Finding(
            tool=ctx.tool, category=category, severity=severity,
            title=f"{gitleaks_title(rule.rsplit('.', 1)[-1])} (opengrep)",
            summary=(f"Opengrep rule {rule} matched {plural(len(items), 'place')} in "
                     f"{plural(files, 'file')}: {message}.{shown}"),
            impact=("Each place matches a pattern the rule set treats as a code-level flaw; "
                    "the rule's message says what can go wrong there."),
            remediation=("Fix each place as the rule's message says, add a test that exercises "
                         "it, and rerun the scan. Close a false positive in the rule set, not "
                         "with a nosem comment."),
            evidence=evidence, source=Source.scanner, scanner=self.name,
            tags=["opengrep", f"group:{rule}", f"count:{len(items)}"],
            **rule_effort(ctx, self.name, "rule"),
        )

    def _suppression(self, ctx: ScanContext) -> list[Finding]:
        evidence: list[Evidence] = []
        for rec in ctx.census.files:
            name = PurePosixPath(rec.path).name
            if name in IGNORE_FILES:
                evidence.append(Evidence(path=rec.path, note=IGNORE_FILES[name]))
        skipped = self._skipped(ctx)
        for rec in ctx.census.files:
            if (rec.path in skipped or rec.bytes > MAX_SCAN_BYTES
                    or PurePosixPath(rec.path).name in IGNORE_FILES):
                continue
            try:
                text = (ctx.source_root / rec.path).read_text(encoding="utf-8",
                                                               errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            if "nosem" not in lowered and "noopengrep" not in lowered:
                continue
            for lineno, line in enumerate(text.split("\n"), start=1):
                if NOSEM_RE.search(line):
                    evidence.append(Evidence(path=rec.path, line_start=lineno,
                                             line_end=lineno, excerpt=_excerpt(line),
                                             note=NOSEM_NOTE))
        if not evidence:
            return []
        max_evidence = max(1, int(ctx.options.get("max_evidence", 25)))
        shown = (f" Showing the first {max_evidence} of {len(evidence)}."
                 if len(evidence) > max_evidence else "")
        return [Finding(
            tool=ctx.tool, category=self.category, severity=Severity.low,
            title="Opengrep suppressions in the source",
            summary=(f"The source tells Opengrep or Semgrep what to ignore in "
                     f"{plural(len(evidence), 'place')}: ignore files or nosem comments. "
                     f"Unvarnish's sast scan disregards them, so a flaw they hide is still "
                     f"reported when the scan runs.{shown}"),
            impact=("A suppression can silence a real flaw for everyone who relies on the "
                    "client's own scans."),
            remediation=("Review every entry. Each should name a confirmed false positive and "
                         "the reason; fix and remove entries that hide real issues."),
            evidence=evidence[:max_evidence], source=Source.scanner, scanner=self.name,
            tags=["suppression", "group:suppression", f"count:{len(evidence)}"],
            **rule_effort(ctx, self.name, "suppression"),
        )]
