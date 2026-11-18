"""Re-audit delta (UNVAR-40): this run's findings against a previous review's.

No model calls. `load_baseline` resolves what `run --baseline` points at, per tool, into a
snapshot; `compute_delta` matches findings by id, then by title and path within a line-drift
tolerance, then by secret fingerprint.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from unvarnish.artifacts import ArtifactMeta
from unvarnish.engagement import CONFIG_NAME, ToolPaths
from unvarnish.phases.ingest import load_tool_meta
from unvarnish.render.findings import merged_findings
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.delta import (
    FINDINGS_SCHEMA_VERSION,
    BaselineInfo,
    BaselineSnapshot,
    Delta,
    DeltaEntry,
    DeltaStatus,
)
from unvarnish.schemas.finding import Finding, Source, Verification
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.verify import ModelFindings


class BaselineError(ValueError):
    """The --baseline path cannot be used; the message says why."""


def _read(path: Path) -> tuple[ArtifactMeta, ScannerFindings | ModelFindings]:
    """A findings artifact (scanner-findings.json or findings.json), schema version checked."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"{path}: not a readable findings artifact ({exc})") from exc
    if not (isinstance(raw, dict) and isinstance(raw.get("meta"), dict)
            and isinstance(raw.get("data"), dict) and "findings" in raw["data"]):
        raise BaselineError(f"{path}: not an Unvarnish findings artifact (scanner-findings.json "
                            "or findings.json)")
    version = raw["meta"].get("schema_version")
    if not isinstance(version, int) or version < FINDINGS_SCHEMA_VERSION:
        raise BaselineError(
            f"{path} has schema version {version}, older than the version "
            f"{FINDINGS_SCHEMA_VERSION} this Unvarnish compares: its finding ids are not "
            "comparable. Re-run the previous review with this version of Unvarnish, or run "
            "without --baseline.")
    if version > FINDINGS_SCHEMA_VERSION:
        raise BaselineError(
            f"{path} has schema version {version}, written by a newer Unvarnish; this version "
            f"compares {FINDINGS_SCHEMA_VERSION}. Upgrade Unvarnish to compare with it.")
    cls: type[BaseModel] = ModelFindings if "verified" in raw["data"] else ScannerFindings
    try:
        meta = ArtifactMeta.model_validate(raw["meta"])
        data = cls.model_validate(raw["data"])
    except ValidationError as exc:
        raise BaselineError(f"{path}: not a valid findings artifact ({exc.error_count()} "
                            "error(s))") from exc
    return meta, data  # type: ignore[return-value]


def _live(mf: ModelFindings) -> list[Finding]:
    return [f for f in mf.findings if f.verification != Verification.rejected]


def _latest(*times: datetime | None) -> datetime | None:
    known = [t for t in times if t is not None]
    return max(known) if known else None


def load_baseline(path: Path, tool: str) -> BaselineSnapshot | None:
    """The previous review of `tool` at `path`: a prior engagement folder, a tool folder, or one
    findings artifact. None when `path` holds nothing for this tool."""
    path = path.expanduser()
    if path.is_file():
        meta, data = _read(path)
        if data.tool != tool:
            return None
        is_model = isinstance(data, ModelFindings)
        complete = is_model and not data.stopped_for_budget  # type: ignore[union-attr]
        findings = (_live(data) if complete else []) if is_model else list(data.findings)
        info = BaselineInfo(source=str(path.resolve()), reviewed_at=meta.produced_at,
                            scanner=not is_model, model=complete)
        return _snapshot(tool, info, findings)
    if not path.is_dir():
        raise BaselineError(f"{path} does not exist")
    if (path / CONFIG_NAME).exists():
        tool_dir = path / "tools" / tool
    elif (path / "inventory" / "scanner-findings.json").exists():
        tool_dir = path
    else:
        raise BaselineError(f"{path} is not an engagement folder, a tool folder, or a findings "
                            "artifact")
    tp = ToolPaths(tool_dir)
    if not tp.scanner_findings.exists():
        return None  # not in that engagement, or never scanned there
    smeta, scan = _read(tp.scanner_findings)
    if scan.tool != tool:
        return None
    findings = list(scan.findings)
    reviewed_at, complete = smeta.produced_at, False
    if tp.model_findings.exists():
        mmeta, mf = _read(tp.model_findings)
        complete = isinstance(mf, ModelFindings) and not mf.stopped_for_budget
        if complete:
            findings += _live(mf)  # type: ignore[arg-type]
            reviewed_at = _latest(reviewed_at, mmeta.produced_at)
    try:
        commit = load_tool_meta(tp).commit
    except Exception:  # a missing or unreadable tool.yaml only loses the commit
        commit = None
    info = BaselineInfo(source=str(tool_dir.resolve()), reviewed_at=reviewed_at, commit=commit,
                        scanner=True, model=complete)
    return _snapshot(tool, info, findings)


def _snapshot(tool: str, info: BaselineInfo, findings: list[Finding]) -> BaselineSnapshot:
    """Excerpts are redacted again: a baseline written by an older or edited run must never
    put a secret into this engagement's artifacts or documents."""
    out = []
    for f in findings:
        f = f.model_copy(deep=True)
        # Every free-text field, the title included (the document shows it); never the id or
        # the fingerprint, which matching needs.
        for field in ("title", "summary", "impact", "remediation", "verification_note",
                      "effort_note"):
            if text := getattr(f, field):
                setattr(f, field, redact_text(text))
        for e in f.evidence:
            if e.excerpt:
                e.excerpt = redact_text(e.excerpt)
            if e.note:
                e.note = redact_text(e.note)
        out.append(f)
    return BaselineSnapshot(tool=tool, info=info, findings=out)


def _line(f: Finding) -> int | None:
    return f.evidence[0].line_start


def _fingerprint(f: Finding) -> str | None:
    return f.evidence[0].fingerprint


def _near(b: Finding, c: Finding, drift: int) -> int | None:
    """Line distance when within `drift`, else None. Two line-less findings are distance 0."""
    lb, lc = _line(b), _line(c)
    if lb is None or lc is None:
        return 0 if lb is None and lc is None else None
    d = abs(lb - lc)
    return d if d <= drift else None


def _same_place(b: Finding, c: Finding, drift: int) -> int | None:
    """Same title and path, within the drift, and not two different secrets."""
    if b.title != c.title or b.evidence[0].path != c.evidence[0].path:
        return None
    fb, fc = _fingerprint(b), _fingerprint(c)
    if fb and fc and fb != fc:
        return None
    return _near(b, c, drift)


def _pair(b: Finding, c: Finding, how: str) -> DeltaEntry:
    eb, ec = b.evidence[0], c.evidence[0]
    moved = (eb.path, eb.line_start) != (ec.path, ec.line_start)
    status = (DeltaStatus.changed if moved or b.severity != c.severity
              else DeltaStatus.persistent)
    return DeltaEntry(status=status, finding=c, matched_by=how,  # type: ignore[arg-type]
                      previous_id=b.id, previous_severity=b.severity,
                      previous_path=eb.path, previous_line=eb.line_start)


def match_findings(base: list[Finding], cur: list[Finding], drift: int) -> list[DeltaEntry]:
    """Pair each current finding with at most one baseline finding: by id, then by title and
    path within `drift` lines (nearest pairs first), then by secret fingerprint."""
    left: list[Finding | None] = list(base)
    entries: list[DeltaEntry | None] = [None] * len(cur)

    def take(i: int, j: int, how: str) -> None:
        b = left[j]
        assert b is not None
        entries[i] = _pair(b, cur[i], how)
        left[j] = None

    for i, c in enumerate(cur):
        j = next((j for j, b in enumerate(left) if b is not None and b.id == c.id), None)
        if j is not None:
            take(i, j, "id")
    # Nearest pair first across every candidate, ties to the earlier current then baseline
    # finding, so the pairing does not depend on which current finding is looked at first.
    near = sorted((d, i, j) for i, c in enumerate(cur) if entries[i] is None
                  for j, b in enumerate(left)
                  if b is not None and (d := _same_place(b, c, drift)) is not None)
    for _, i, j in near:
        if entries[i] is None and left[j] is not None:
            take(i, j, "title_path")
    for i, c in enumerate(cur):
        fp = _fingerprint(c)
        if entries[i] is not None or not fp:
            continue
        j = next((j for j, b in enumerate(left) if b is not None and _fingerprint(b) == fp),
                 None)
        if j is not None:
            take(i, j, "fingerprint")
    out = [e if e is not None else DeltaEntry(status=DeltaStatus.new, finding=cur[i])
           for i, e in enumerate(entries)]
    out += [DeltaEntry(status=DeltaStatus.resolved, finding=b, previous_id=b.id,
                       previous_severity=b.severity, previous_path=b.evidence[0].path,
                       previous_line=_line(b))
            for b in left if b is not None]
    return out


def compute_delta(tool: str, snapshot: BaselineSnapshot, scan: ScannerFindings,
                  model: ModelFindings | None, *, accepted: list[str],
                  drift: int) -> Delta:
    """Only sources both reviews hold completely are compared: a model analysis present on one
    side only would otherwise show every model finding as new or resolved."""
    current_model = model is not None and not model.stopped_for_budget
    sources = [s for s, ok in (("scanner", snapshot.info.scanner),
                               ("model", snapshot.info.model and current_model)) if ok]
    notes: list[str] = []
    if snapshot.info.model != current_model:
        side = "the previous review" if current_model else "this review"
        notes.append(f"Model findings were not compared: {side} has no complete model "
                     "analysis.")
    if not snapshot.info.scanner:
        notes.append("Scanner findings were not compared: the baseline holds model findings "
                     "only.")
    wanted = {Source(s) for s in sources}
    base = [f for f in snapshot.findings if f.source in wanted]
    cur = [f for f in merged_findings(scan.findings, model.findings if model else [])
           if f.source in wanted]
    entries = match_findings(base, cur, drift)
    ids = set(accepted)
    for e in entries:
        if e.finding.id in ids or (e.previous_id and e.previous_id in ids):
            e.status = DeltaStatus.accepted
    return Delta(tool=tool, baseline=snapshot.info, line_drift=drift, compared_sources=sources,
                 notes=notes, entries=entries)
