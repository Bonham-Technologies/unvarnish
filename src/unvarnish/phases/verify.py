from __future__ import annotations

import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.model.base import Backend
from unvarnish.model.budget import BudgetTracker, record_cost
from unvarnish.model.prompts.verify import (
    VERIFY_PROMPT_VERSION,
    build_verify_request,
    build_verify_system,
)
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.phases.modelrun import ItemOutcome, call_structured, merge_failures, run_parallel
from unvarnish.scanners.secrets import is_placeholder, redact_text
from unvarnish.schemas.analysis import UnitResult, UnitsIndex
from unvarnish.schemas.cost import CostEntry
from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
    Evidence,
    Finding,
    Severity,
    Source,
    Verification,
)
from unvarnish.schemas.rollup import Module, module_file_id
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings, Verdict

log = logging.getLogger("unvarnish.verify")
VERIFY_SEVERITIES = {Severity.critical, Severity.high}
CONTEXT_LINES = 5
MAX_EXCERPT_LINES = 80
MAX_EVIDENCE = 6
WHOLE_FILE_MAX_LINES = 600    # a tool-level finding's cited files are shown whole when small
WHOLE_FILES_MAX_LINES = 1500

VerdictItem = tuple[str, Verdict | None, str | None]  # finding id, verdict, error
# Bump when the phase's own judgement changes (evidence grounding, placeholder rejection), so a
# verify artifact written by older code is not taken as fresh.
VERIFY_LOGIC_VERSION = "2026-10-19.2"
TOOL_LEVEL_NOTE = ("tool-level finding: not independently verifiable from cited lines; "
                   "review manually")


def has_cited_lines(f: Finding) -> bool:
    return any(e.line_start is not None for e in f.evidence)


def current_artifacts(ctx: ToolContext) -> tuple[list[Path], list[Path]]:
    """Unit and module artifacts named by the current units index. Artifacts left from an
    earlier split (a unit_tokens change, a source change) are not part of this analysis."""
    if not ctx.paths.units_index.exists():
        return [], []
    try:
        index = read_artifact(ctx.paths.units_index, UnitsIndex).data
    except Exception:
        return [], []
    units = [ctx.paths.unit_dir / f"{u.id}.json" for u in index.units]
    modules = [ctx.paths.module_dir / f"{module_file_id(m)}.json" for m in index.modules]
    return [p for p in units if p.exists()], [p for p in modules if p.exists()]


def collect_model_findings(ctx: ToolContext) -> list[Finding]:
    out: list[Finding] = []
    unit_paths, module_paths = current_artifacts(ctx)
    for p in sorted(unit_paths):
        try:
            out.extend(read_artifact(p, UnitResult).data.findings)
        except Exception:
            log.warning("skipping unreadable unit artifact %s", p.name)
    for p in sorted(module_paths):
        try:
            out.extend(read_artifact(p, Module).data.findings)
        except Exception:
            log.warning("skipping unreadable module artifact %s", p.name)
    if ctx.paths.tool_model.exists():
        try:
            out.extend(read_artifact(ctx.paths.tool_model, ToolModel).data.findings)
        except Exception:
            log.warning("skipping unreadable tool.json")
    return [f for f in out if f.source == Source.model]


def _norm(title: str) -> str:
    return " ".join(title.lower().split())


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same category, title, and primary path; keep all evidence."""
    by_key: dict[tuple[str, str, str], Finding] = {}
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path,
                                              f.evidence[0].line_start or 0))
    for f in ordered:
        key = (f.category.value, _norm(f.title), f.evidence[0].path)
        kept = by_key.get(key)
        if kept is None:
            by_key[key] = f.model_copy(deep=True)
            continue
        seen = {(e.path, e.line_start, e.line_end) for e in kept.evidence}
        kept.evidence.extend(e for e in f.evidence
                             if (e.path, e.line_start, e.line_end) not in seen)
        known = [c for c in (kept.confidence, f.confidence) if c is not None]
        kept.confidence = max(known) if known else None
        n = next((int(t.split(":", 1)[1]) for t in kept.tags if t.startswith("occurrences:")), 1)
        kept.tags = [t for t in kept.tags if not t.startswith("occurrences:")]
        kept.tags.append(f"occurrences:{n + 1}")  # how many findings this one stands for
    return list(by_key.values())


def evidence_excerpt(source_root: Path, ev: Evidence, context: int = CONTEXT_LINES,
                     max_lines: int = MAX_EXCERPT_LINES) -> str:
    recorded = f"\nrecorded excerpt: {ev.excerpt}" if ev.excerpt else ""
    try:
        lines = (source_root / ev.path).read_text(encoding="utf-8",
                                                  errors="replace").splitlines()
    except OSError:
        return f"{ev.path}: (file not readable){recorded}"
    if ev.line_start is None:
        return f"{ev.path}: (whole file cited){recorded}"
    lo = max(1, ev.line_start - context)
    hi = min(len(lines), (ev.line_end or ev.line_start) + context, lo + max_lines - 1)
    body = "\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(lo, hi + 1))
    return f"{ev.path} lines {lo}-{hi}:\n{body}"


WINDOW_CONTEXT = 12          # lines either side of a matching line
MAX_WINDOWS_PER_FILE = 6
KEYWORD_RE = re.compile(r"`([^`]+)`|\b([A-Za-z_][A-Za-z0-9_]{4,})\b")
COMMON_WORDS = {"about", "across", "after", "allow", "allows", "anyone", "being", "cannot",
                "could", "every", "files", "first", "found", "their", "there", "these",
                "those", "through", "under", "until", "using", "where", "which", "while",
                "without", "would", "should", "other", "never", "still", "since", "before"}


def finding_keywords(f: Finding) -> set[str]:
    """Identifiers in backticks and longer words from the claim, lower-cased."""
    words: set[str] = set()
    for code, word in KEYWORD_RE.findall(f"{f.title} {f.summary}"):
        if code:
            words.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", code))
        elif word.lower() not in COMMON_WORDS:
            words.add(word)
    return {w.lower() for w in words}


def _windows(lines: list[str], keywords: set[str]) -> list[tuple[int, int]]:
    scored = []
    for n, text in enumerate(lines, start=1):
        low = text.lower()
        score = sum(1 for k in keywords if k in low)
        if score:
            scored.append((-score, n))
    spans: list[tuple[int, int]] = []
    for _, n in sorted(scored):
        if len(spans) >= MAX_WINDOWS_PER_FILE:
            break
        lo, hi = max(1, n - WINDOW_CONTEXT), min(len(lines), n + WINDOW_CONTEXT)
        if any(a <= n <= b for a, b in spans):
            continue
        spans.append((lo, hi))
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def whole_file_evidence(source_root: Path, f: Finding) -> list[str] | None:
    """Evidence for a finding that cites files without lines: small files whole, larger files
    as windows around the lines that match the claim's identifiers and words. None when a file
    is unreadable, a large file has no matching lines, or the total is too long to show."""
    keywords = finding_keywords(f)
    out: list[str] = []
    total = 0
    for path in dict.fromkeys(e.path for e in f.evidence[:MAX_EVIDENCE]):
        try:
            lines = (source_root / path).read_text(encoding="utf-8",
                                                   errors="replace").splitlines()
        except OSError:
            return None
        if len(lines) <= WHOLE_FILE_MAX_LINES:
            spans = [(1, len(lines))] if lines else []
            label = f"{path} (whole file, {len(lines)} lines)"
        else:
            spans = _windows(lines, keywords)
            if not spans:
                return None
            label = f"{path} (excerpts around lines matching the claim, of {len(lines)} lines)"
        total += sum(hi - lo + 1 for lo, hi in spans)
        if total > WHOLE_FILES_MAX_LINES:
            return None
        body = "\n  ...\n".join("\n".join(f"{n:>6}: {lines[n - 1]}" for n in range(lo, hi + 1))
                               for lo, hi in spans)
        out.append(f"{label}:\n{body}")
    return out or None


# The extract phase stores excerpts redacted ("sk-p…[redacted 38 chars]"); a redaction marker
# stands in for source text the way an elision does.
REDACTION_RE = re.compile(r"\[redacted \d+ chars\]|\[(?:line|text) redacted\]")
ELISION_RE = re.compile(r"…?\[redacted \d+ chars\]|\[(?:line|text) redacted\]|\.\.\.|…")
WHITESPACE_RE = re.compile(r"\s+")


def _squash(text: str) -> str:
    return WHITESPACE_RE.sub("", text)


def is_verbatim(excerpt: str, source: str) -> bool:
    """The excerpt's pieces between elisions appear in the source in order, whitespace aside."""
    text, pos = _squash(source), 0
    for piece in (_squash(p) for p in ELISION_RE.split(excerpt)):
        if not piece:
            continue
        pos = text.find(piece, pos)
        if pos < 0:
            return False
        pos += len(piece)
    return True


def ground_evidence(findings: list[Finding], source_root: Path) -> None:
    """A model's "excerpt" that is not in the cited file is a description, not a quote: keep
    it as the evidence note so the report never prints prose as if it were the code."""
    texts: dict[str, str | None] = {}
    for f in findings:
        for e in f.evidence:
            if not e.excerpt:
                continue
            if e.path not in texts:
                try:
                    texts[e.path] = (source_root / e.path).read_text(encoding="utf-8",
                                                                     errors="replace")
                except OSError:
                    texts[e.path] = None
            text = texts[e.path]
            if text is None or is_verbatim(e.excerpt, text):
                continue
            e.note = f"{e.note}; {e.excerpt}" if e.note else e.excerpt
            e.excerpt = None


CREDENTIAL_CLAIM_RE = re.compile(
    r"credential|secret|password|passwd|token|api[ _-]?key|private key", re.IGNORECASE)
# Only a claim that the value is written into the source is answered by the value being a
# placeholder; "password kept in localStorage" is about handling, whatever the literals are.
IN_SOURCE_CLAIM_RE = re.compile(
    r"hard[ -]?coded|embedded|committed|checked[ -]in|literal|"
    r"in (?:the )?(?:source|code|repo|repository|config|configuration)\b", re.IGNORECASE)
# A string literal on one line: escapes honoured, an optional Python prefix (f"", rb''), and
# never opened by an apostrophe inside a word ("don't").
QUOTED_RE = re.compile(r"""(?<!\w)(?:[rbuf]{1,2})?(["'`])((?:\\.|(?!\1)[^\\\n])*)\1""",
                       re.IGNORECASE)
# A quote left over once the literals are taken out: a truncated excerpt or a multi-line
# string, so the values cannot be read reliably.
STRAY_QUOTE_RE = re.compile(r"""["`]|(?<!\w)'""")
KEY_COLON_RE = re.compile(r"\s*:")
# An unquoted value assigned to a credential-like key (.env, YAML, INI, shell).
UNQUOTED_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?[\w.-]*(?:auth|credential|secret|pass|pwd|token|key)[\w.-]*"
    r"[ \t]*[:=][ \t]*(?P<v>[^\s\"'`#;,{}\[\]()][^#;,\n]*)", re.IGNORECASE | re.MULTILINE)
AUTH_SCHEME_RE = re.compile(r"^(?:bearer|basic|token)\s+", re.IGNORECASE)
PLACEHOLDER_MAX_LINES = 5


def _cited_values(cited: str) -> list[str] | None:
    """The values in cited source: quoted literals that are not object keys, and unquoted
    values of credential-like keys. None when they cannot be read reliably."""
    if REDACTION_RE.search(cited):
        return None  # a secret rule recognised a real-looking value here
    values: list[str] = []
    masked = list(cited)
    for m in QUOTED_RE.finditer(cited):
        masked[m.start():m.end()] = "\0" * (m.end() - m.start())
        before = cited[:m.start()].rstrip(" \t")
        # "key": in an object or mapping; the first branch of a ternary ends in ":" too
        if KEY_COLON_RE.match(cited, m.end()) and (not before or before[-1] in "{,\n"):
            continue
        values.append(AUTH_SCHEME_RE.sub("", m.group(2)))
    if STRAY_QUOTE_RE.search("".join(masked)):
        return None
    for m in UNQUOTED_RE.finditer(cited):
        values.append(AUTH_SCHEME_RE.sub("", m.group("v").strip()))
    return values


TEMPLATE_WORDS = ("replace_me", "replaceme", "your_", "your-", "placeholder", "example",
                  "insert_", "<", "${", "{{", "%(")
WEAK_DEFAULTS = {"password", "secret", "changeme", "change_me", "admin", "test", "pass",
                 "root", "default"}


def is_template_value(value: str) -> bool:
    """A value only a template would hold. Narrower than the secrets scanner's placeholder
    rule: `password`, `changeme`, and the empty string are weak real credentials here."""
    v = value.strip().lower()
    if not v or v in WEAK_DEFAULTS or not is_placeholder(v):
        return False
    return any(w in v for w in TEMPLATE_WORDS) or v.endswith(">") or \
        (len(v) >= 4 and len(set(v)) <= 2)  # "xxxxxxxx", "********"


def placeholder_credential(f: Finding, source_root: Path) -> str | None:
    """Why a credential claim is about a placeholder, when every cited line's quoted values
    are placeholders ("Bearer REPLACE_ME", "<your-key>"); None when any value might be real."""
    claim = f"{f.title} {f.summary}"
    if not (CREDENTIAL_CLAIM_RE.search(claim) and IN_SOURCE_CLAIM_RE.search(claim)):
        return None
    seen: list[str] = []
    for e in f.evidence:
        cited = e.excerpt  # verbatim after ground_evidence, and models miscount lines
        if not cited:
            if e.line_start is None or (e.line_end or e.line_start) - e.line_start >= \
                    PLACEHOLDER_MAX_LINES:
                return None
            try:
                lines = (source_root / e.path).read_text(encoding="utf-8",
                                                         errors="replace").splitlines()
            except OSError:
                return None
            cited = "\n".join(lines[e.line_start - 1:(e.line_end or e.line_start)])
        values = _cited_values(cited)
        if not values or not all(is_template_value(v) for v in values):
            return None
        seen.extend(values)
    if not seen:
        return None
    shown = ", ".join(sorted(set(seen))[:3])
    return f"rejected without a model call: the cited value is a placeholder ({shown})"


def adjust_effort(f: Finding, verdict: Verdict) -> None:
    """The verifier may move a finding's band; a rejected finding keeps the claimed one."""
    if verdict.effort is None or verdict.verdict == "rejected" or verdict.effort == f.effort:
        return
    claimed = f"claimed {f.effort}" if f.effort else "no band claimed"
    f.effort_note = (f"set by the verifier ({claimed})"
                     + (f"; the claim's reason: {f.effort_note}" if f.effort_note else ""))
    f.effort = verdict.effort


def downgrade(sev: Severity) -> Severity:
    order = list(Severity)
    return order[min(order.index(sev) + 1, len(order) - 1)]


class VerifyPhase:
    name = "verify"
    reads_source = True  # fails when the source is gone (UNVAR-31)
    depends_on = ("extract", "rollup_modules", "rollup_tool")

    def __init__(self, backend: Backend | None = None) -> None:
        self._backend = backend

    def _resolve(self, ctx: ToolContext) -> Backend | None:
        if self._backend is not None:
            return self._backend
        try:
            return resolve_backend(ctx.engagement, self.name)
        except NoModelConfigured:
            return None

    def inputs_hash(self, ctx: ToolContext) -> str:
        ref = resolve_model_ref(ctx.config, self.name)
        model_part = f"{ref.backend}|{ref.model}|{ref.effort or ''}" if ref else "no-model"
        return hash_inputs([hash_files([ctx.paths.extract_state, ctx.paths.modules_index,
                                        ctx.paths.tool_model]),
                            model_part, VERIFY_PROMPT_VERSION, VERIFY_LOGIC_VERSION])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.model_findings]

    def run(self, ctx: ToolContext) -> PhaseResult:
        backend = self._resolve(ctx)
        if backend is None:
            return PhaseResult(phase=self.name, status=PhaseStatus.skipped,
                               message="skipped: no model configured (set models.default)")
        ref = resolve_model_ref(ctx.config, self.name)
        effort = ref.effort if ref else None
        budget = ctx.budget or BudgetTracker(ctx.config.budget.max_tokens)
        system = build_verify_system()
        findings = dedupe_findings(collect_model_findings(ctx))
        ground_evidence(findings, ctx.source_root)
        high = [f for f in findings if f.severity in VERIFY_SEVERITIES]
        placeholders = 0
        for f in high:
            reason = placeholder_credential(f, ctx.source_root)
            if reason is not None:
                f.verification, f.verification_note = Verification.rejected, reason
                placeholders += 1
        checked = [f for f in high if f.verification != Verification.rejected]
        # A strict verifier shown no lines would reject every cross-cutting finding. A
        # line-less (tool-level) finding is verified against its cited files when they are
        # small enough to show whole, and is otherwise left visibly unverified.
        whole: dict[str, list[str]] = {}
        for f in checked:
            if not has_cited_lines(f):
                shown = whole_file_evidence(ctx.source_root, f)
                if shown is not None:
                    whole[f.id] = shown
        to_verify = [f for f in checked if has_cited_lines(f) or f.id in whole]
        unverified = 0
        for f in findings:
            if f.severity not in VERIFY_SEVERITIES:
                f.verification = Verification.not_required
            elif (not has_cited_lines(f) and f.id not in whole
                  and f.verification != Verification.rejected):
                f.verification_note = TOOL_LEVEL_NOTE
                unverified += 1

        def worker(f: Finding, stop: threading.Event) -> ItemOutcome[VerdictItem]:
            excerpts = whole.get(f.id) or [evidence_excerpt(ctx.source_root, e)
                                           for e in f.evidence[:MAX_EVIDENCE]]
            req = build_verify_request(f, excerpts, effort, system=system)
            res, failure = call_structured(backend, req, Verdict, phase=self.name,
                                           item_id=f.id, path=f.evidence[0].path, stop=stop)
            if res is None:
                return ItemOutcome(result=(f.id, None, failure.error if failure else "?"),
                                   failures=[failure] if failure else [])
            return ItemOutcome(result=(f.id, res.parsed, None), usage=res.usage)

        outcome = run_parallel(to_verify, worker, workers=ctx.config.pipeline.concurrency,
                               budget=budget, phase=self.name)
        verdicts: dict[str, tuple[Verdict | None, str | None]] = {
            fid: (v, err) for fid, v, err in outcome.results}
        counts = {"confirmed": 0, "downgraded": 0, "rejected": placeholders}
        for f in to_verify:
            got = verdicts.get(f.id)
            if got is None:
                f.verification_note = f"not verified: {budget.stop_reason}"
                continue
            verdict, err = got
            if verdict is None:
                unverified += 1
                f.verification_note = f"verification failed: {err}"
                continue
            f.verification = Verification(verdict.verdict)
            f.verification_note = redact_text(verdict.reason)
            counts[verdict.verdict] += 1
            adjust_effort(f, verdict)
            if verdict.verdict == "downgraded":
                f.severity = downgrade(f.severity)
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path,
                                     f.evidence[0].line_start or 0))
        mf = ModelFindings(tool=ctx.tool, findings=findings, verified=sum(counts.values()),
                           confirmed=counts["confirmed"], downgraded=counts["downgraded"],
                           rejected=counts["rejected"], unverified=unverified,
                           usage=outcome.usage, stopped_for_budget=outcome.stopped_for_budget)
        write_artifact(ctx.paths.model_findings, mf, produced_by=self.name,
                       inputs_hash="" if outcome.stopped else self.inputs_hash(ctx))
        if outcome.usage.total():
            record_cost(ctx.engagement, CostEntry(
                tool=ctx.tool, phase=self.name, backend=backend.name, model=backend.model,
                usage=outcome.usage, at=datetime.now(UTC)))
        merge_failures(ctx, self.name, outcome.failures)
        if outcome.fatal is not None:
            raise outcome.fatal
        msg = (f"{len(findings)} model findings, {len(high)} high or critical, "
               f"{len(to_verify) + placeholders} verifiable: "
               f"{counts['confirmed']} confirmed, {counts['downgraded']} downgraded, "
               f"{counts['rejected']} rejected, {unverified} unverified, "
               f"{outcome.usage.total():,} tokens")
        status = PhaseStatus.stopped if outcome.stopped_for_budget else PhaseStatus.ok
        if outcome.stopped_for_budget:
            msg = f"{budget.stop_reason}: " + msg
        log.info("verify %s: %s", ctx.tool, msg)
        return PhaseResult(phase=self.name, status=status, message=msg,
                           failures=[f"{f.path}: {f.error}" for f in outcome.failures])
