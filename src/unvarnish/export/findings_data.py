"""Findings as data: SARIF 2.1.0 for code-scanning dashboards, CSV for tracker imports.

Both carry exactly the findings the findings document shows (scanner findings and the model
findings verification did not reject) and pass every string through the secrets redactor.
Neither needs pandoc."""

from __future__ import annotations

import csv
import hashlib
import io
import re
from urllib.parse import quote

from unvarnish import __version__
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import ToolPaths
from unvarnish.render.findings import merged_findings
from unvarnish.render.inputs import _optional
from unvarnish.scanners.secrets import redact_model_text
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.verify import ModelFindings

SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                "sarif-schema-2.1.0.json")
SARIF_VERSION = "2.1.0"
DRIVER_NAME = "Unvarnish"
MAX_RESULTS_PER_RUN = 25_000  # GitHub code scanning rejects a run with more results
LEVELS: dict[Severity, str] = {
    Severity.critical: "error", Severity.high: "error", Severity.medium: "warning",
    Severity.low: "note", Severity.info: "note",
}
# GitHub ranks security alerts by this score: 9.0+ critical, 7.0+ high, 4.0+ medium, else low.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.critical: "9.5", Severity.high: "8.0", Severity.medium: "5.5", Severity.low: "3.0",
}
CSV_COLUMNS = ("Summary", "Description", "Severity", "Tool", "Category", "Source", "Path",
               "Lines", "FindingId", "Verification")
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")  # a spreadsheet would evaluate these


def load_findings(paths: ToolPaths) -> list[Finding]:
    """The tool's findings as the findings document lists them, by severity, redacted. The id
    is kept from the unredacted finding, so it still matches findings.json."""
    scan = read_artifact(paths.scanner_findings, ScannerFindings).data
    model = _optional(paths.model_findings, ModelFindings)
    return [redact_model_text(f) for f in
            merged_findings(scan.findings, model.findings if model else [])]


def _verification(f: Finding) -> str:
    return f.verification.value if f.verification else "unverified"


def _lines(e: Evidence) -> str:
    if e.line_start is None:
        return ""
    if e.line_end is not None and e.line_end > e.line_start:
        return f"{e.line_start}-{e.line_end}"
    return str(e.line_start)


# --- SARIF ------------------------------------------------------------------------------------

def rule_id(f: Finding) -> str:
    """One rule per (source, category, title): readable, and unique by the hash."""
    slug = re.sub(r"[^a-z0-9]+", "-", f.title.lower()).strip("-")[:48].strip("-") or "finding"
    digest = hashlib.sha256(f"{f.source}|{f.category}|{f.title}".encode()).hexdigest()[:8]
    return f"{f.source.value}/{f.category.value}/{slug}-{digest}"


def _location(e: Evidence) -> dict:
    physical: dict = {"artifactLocation": {"uri": quote(e.path)}}
    if e.line_start is not None and e.line_start >= 1:
        region: dict = {"startLine": e.line_start}
        if e.line_end is not None and e.line_end >= e.line_start:
            region["endLine"] = e.line_end
        if e.excerpt:
            region["snippet"] = {"text": e.excerpt}
        physical["region"] = region
    return {"physicalLocation": physical}


def _rule(rid: str, f: Finding) -> dict:
    """The rule from its first, so most severe, finding (findings arrive by severity)."""
    props: dict = {"tags": [f.category.value, f.source.value]}
    if f.category == Category.security and f.severity in SECURITY_SEVERITY:
        props["security-severity"] = SECURITY_SEVERITY[f.severity]
    return {
        "id": rid,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.summary or f.title},
        "help": {"text": f.remediation or f.summary or f.title},
        "defaultConfiguration": {"level": LEVELS[f.severity]},
        "properties": props,
    }


def _result(f: Finding, rid: str, index: int) -> dict:
    message = "\n\n".join(p for p in (f.summary, f.impact and f"Impact: {f.impact}") if p)
    props: dict = {"severity": f.severity.value, "source": f.source.value,
                   "category": f.category.value, "verification": _verification(f)}
    if f.confidence is not None:
        props["confidence"] = f.confidence
    if f.exploits is not None:  # per advisory: CISA KEV and EPSS (UNVAR-90)
        props["exploits"] = [e.model_dump(mode="json") for e in f.exploits]
    result: dict = {
        "ruleId": rid, "ruleIndex": index, "level": LEVELS[f.severity],
        "message": {"text": message or f.title},
        "locations": [_location(f.evidence[0])],
        "partialFingerprints": {"unvarnishFindingId": f.id},
        "properties": props,
    }
    if len(f.evidence) > 1:
        result["relatedLocations"] = [
            {"id": n, **_location(e), **({"message": {"text": e.note}} if e.note else {})}
            for n, e in enumerate(f.evidence[1:], start=1)]
    return result


def _run(findings: list[Finding], automation_id: str) -> dict:
    rules: list[dict] = []
    index: dict[str, int] = {}
    results: list[dict] = []
    for f in findings:
        rid = rule_id(f)
        if rid not in index:
            index[rid] = len(rules)
            rules.append(_rule(rid, f))
        results.append(_result(f, rid, index[rid]))
    driver = {"name": DRIVER_NAME, "version": __version__, "semanticVersion": __version__,
              "rules": rules}
    return {"tool": {"driver": driver}, "automationDetails": {"id": automation_id},
            "results": results}


def sarif_documents(tool: str, findings: list[Finding]) -> list[dict]:
    """One SARIF log with one run for the tool, or one log per MAX_RESULTS_PER_RUN results,
    each with its own automation id (GitHub's upload category) so uploads don't replace
    each other."""
    limit = MAX_RESULTS_PER_RUN
    chunks = [findings[i:i + limit] for i in range(0, len(findings), limit)] or [[]]
    many = len(chunks) > 1
    return [{"$schema": SARIF_SCHEMA, "version": SARIF_VERSION,
             "runs": [_run(chunk, f"unvarnish/{tool}-part{n}/" if many else f"unvarnish/{tool}/")]}
            for n, chunk in enumerate(chunks, start=1)]


# --- CSV --------------------------------------------------------------------------------------

def _description(f: Finding) -> str:
    parts = [f.summary, f.impact and f"Impact: {f.impact}",
             f.remediation and f"Remediation: {f.remediation}"]
    if len(f.evidence) > 1:
        further = []
        for e in f.evidence[1:]:
            where = f"{e.path}:{_lines(e)}" if _lines(e) else e.path
            further.append(f"- {where} ({e.note})" if e.note else f"- {where}")
        parts.append("Further evidence:\n" + "\n".join(further))
    return "\n\n".join(p for p in parts if p)


def _cell(value: str) -> str:
    return f"'{value}" if value.startswith(FORMULA_START) else value


def csv_text(findings: list[Finding]) -> str:
    """One row per finding; csv quotes every cell that holds a newline, comma or quote."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        e = f.evidence[0]
        writer.writerow([_cell(v) for v in (
            f.title, _description(f), f.severity.value, f.tool, f.category.value,
            f.source.value, e.path, _lines(e), f.id, _verification(f))])
    return buf.getvalue()
