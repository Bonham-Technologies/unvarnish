from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Category, Effort, Finding, Severity, coerce_effort


class UnitKind(StrEnum):
    function = "function"
    class_def = "class"
    method = "method"
    group = "group"
    script_block = "script_block"
    style_block = "style_block"
    markup = "markup"
    window = "window"
    file = "file"


class Unit(BaseModel):
    id: str
    tool: str
    module_id: str
    path: str
    language: str | None
    kind: UnitKind
    name: str | None = None
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    token_estimate: int
    split_method: Literal["structural", "windowed"]
    generated: bool = False


class SkippedFile(BaseModel):
    path: str
    reason: str


class UnitsIndex(BaseModel):
    tool: str
    unit_tokens: int
    units: list[Unit]
    modules: dict[str, list[str]] = Field(default_factory=dict)
    skipped: list[SkippedFile] = Field(default_factory=list)


class ExternalRef(BaseModel):
    system: str
    kind: Literal["http", "db", "file", "queue", "env", "process", "library", "other"]
    detail: str


class CandidateFinding(BaseModel):
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    effort: Effort | None = None
    effort_note: str | None = None
    line_start: int
    line_end: int
    excerpt: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("effort", mode="before")
    @classmethod
    def _effort(cls, value: object) -> object:
        return coerce_effort(value)


PLACEHOLDER_RE = re.compile(
    r"^\W*(?:none|n/?a|nil|null|not applicable|no(?:ne)?(?: \w+)? (?:identified|found|known)"
    r"|no risks?|nothing|-+)\W*$", re.I)


def _real(value: str | None) -> bool:
    return bool(value and value.strip() and not PLACEHOLDER_RE.match(value.strip()))


class UnitExtraction(BaseModel):
    purpose: str
    interface: list[str] = Field(default_factory=list)
    external_calls: list[ExternalRef] = Field(default_factory=list)
    data_read: list[str] = Field(default_factory=list)
    data_written: list[str] = Field(default_factory=list)
    auth_behaviour: str | None = None
    error_handling: str | None = None
    risks: list[str] = Field(default_factory=list)
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("interface", "data_read", "data_written", "risks")
    @classmethod
    def _drop_placeholders(cls, values: list[str]) -> list[str]:
        """Smaller models write "None" or "N/A" where the schema wants an empty list."""
        return [v for v in values if _real(v)]

    @field_validator("auth_behaviour", "error_handling")
    @classmethod
    def _null_placeholders(cls, value: str | None) -> str | None:
        return value if _real(value) else None


class UnitResult(BaseModel):
    unit: Unit
    extraction: UnitExtraction
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class FailureRecord(BaseModel):
    phase: str
    unit_id: str | None = None
    path: str | None = None
    error: str
    attempts: int = 1


class Failures(BaseModel):
    tool: str
    items: list[FailureRecord] = Field(default_factory=list)


class ExtractState(BaseModel):
    tool: str
    backend: str
    model: str
    prompt_version: str
    units_total: int = 0
    units_done: int = 0
    units_failed: int = 0
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
    # Digest of the done units' ids and inputs hashes (backend, model, effort, prompt, source),
    # and of the recorded inputs hash of any artifact an undone unit still has on disk.
    # A state written while units are still failing records no inputs hash, so this is what
    # tells the rollups which extractions they read (UNVAR-47). Empty in older states.
    units_digest: str = ""
