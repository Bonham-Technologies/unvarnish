from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.finding import Finding, Severity

# The schema version of the findings artifacts a baseline is read from (scanner-findings.json,
# findings.json). Bump it when the finding id formula or the Finding model changes in a way that
# makes ids from older runs incomparable: such baselines are then refused (UNVAR-40).
FINDINGS_SCHEMA_VERSION = 1
# The schema version of analysis/baseline.json and analysis/delta.json themselves.
DELTA_SCHEMA_VERSION = 1


class DeltaStatus(StrEnum):
    new = "new"
    resolved = "resolved"
    changed = "changed"        # the same finding, moved lines, re-rated, or a group's count
    persistent = "persistent"
    accepted = "accepted"      # listed in baseline.accepted: rendered "Risk accepted"


class BaselineInfo(BaseModel):
    source: str                        # what --baseline resolved to for this tool
    reviewed_at: datetime | None = None
    commit: str | None = None
    scanner: bool = True               # the baseline holds scanner findings
    model: bool = False                # the baseline holds complete model findings


class BaselineSnapshot(BaseModel):
    """Artifact analysis/baseline.json: the previous review's findings, copied when
    `run --baseline` starts, so the delta survives reruns and a moved prior engagement."""

    schema_version: int = DELTA_SCHEMA_VERSION
    tool: str
    info: BaselineInfo
    findings: list[Finding] = Field(default_factory=list)


class DeltaEntry(BaseModel):
    status: DeltaStatus
    finding: Finding                   # the current finding; the baseline's when resolved
    matched_by: Literal["id", "group", "title_path", "fingerprint"] | None = None
    previous_id: str | None = None
    previous_severity: Severity | None = None
    previous_path: str | None = None
    previous_line: int | None = None
    # A grouped scanner finding matched with the baseline's (UNVAR-49): "<scanner>.<rule>", and
    # how many files, functions or values the group held then and now (None when unknown).
    group: str | None = None
    previous_count: int | None = None
    count: int | None = None


class Delta(BaseModel):
    """Artifact analysis/delta.json: this run's findings against the baseline's."""

    schema_version: int = DELTA_SCHEMA_VERSION
    tool: str
    baseline: BaselineInfo
    line_drift: int
    compared_sources: list[str] = Field(default_factory=list)  # "scanner", "model"
    notes: list[str] = Field(default_factory=list)
    entries: list[DeltaEntry] = Field(default_factory=list)

    def of(self, status: DeltaStatus) -> list[DeltaEntry]:
        return [e for e in self.entries if e.status == status]

    def counts(self) -> dict[str, int]:
        return {s.value: len(self.of(s)) for s in DeltaStatus}
