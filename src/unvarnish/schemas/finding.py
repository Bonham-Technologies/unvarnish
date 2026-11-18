from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator


class Category(StrEnum):
    security = "security"
    data_handling = "data_handling"
    maintainability = "maintainability"
    reliability = "reliability"
    operability = "operability"
    compliance = "compliance"
    process = "process"
    dependency = "dependency"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_ORDER: dict[Severity, int] = {s: i for i, s in enumerate(Severity)}


class Source(StrEnum):
    scanner = "scanner"
    model = "model"


class Effort(StrEnum):
    """Remediation-effort band (UNVAR-42): an input to the consultant's judgment, not a quote."""

    S = "S"
    M = "M"
    L = "L"
    XL = "XL"


EFFORT_PLACEHOLDERS = {"", "NONE", "NULL", "N/A", "NA", "UNKNOWN"}


def coerce_effort(value: object) -> object:
    """A model writes "m" or "None" for a band: upper-case it, and read a placeholder as no
    band. Anything else is left for the enum to reject."""
    if isinstance(value, str):
        value = value.strip().upper()
        return None if value in EFFORT_PLACEHOLDERS else value
    return value


class Verification(StrEnum):
    confirmed = "confirmed"
    downgraded = "downgraded"
    rejected = "rejected"
    not_required = "not_required"


class Evidence(BaseModel):
    path: str
    line_start: int | None = None
    line_end: int | None = None
    excerpt: str | None = None
    fingerprint: str | None = None
    note: str | None = None

    @field_validator("path")
    @classmethod
    def _relative_posix(cls, v: str) -> str:
        if v.startswith("/") or "\\" in v or v.startswith("../"):
            raise ValueError("evidence path must be a relative POSIX path inside the tool")
        return v


def compute_finding_id(tool: str, category: Category, title: str, evidence: Evidence) -> str:
    key = (f"{tool}|{category}|{title}|{evidence.path}|{evidence.line_start}"
           f"|{evidence.fingerprint or ''}")
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    id: str = ""
    tool: str
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    evidence: list[Evidence] = Field(min_length=1)
    effort: Effort | None = None  # remediation band; None renders "not estimated" (UNVAR-42)
    effort_note: str | None = None  # one line: why this band
    source: Source
    scanner: str | None = None
    model: str | None = None
    verification: Verification | None = None
    verification_note: str | None = None  # the verifier's one-line reason
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _finalise(self) -> Finding:
        if not self.id:
            self.id = compute_finding_id(self.tool, self.category, self.title, self.evidence[0])
        if self.source == Source.scanner and self.verification is None:
            self.verification = Verification.not_required
        return self
