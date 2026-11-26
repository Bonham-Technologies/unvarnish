from __future__ import annotations

from pydantic import BaseModel, Field

from unvarnish.schemas.finding import Finding


class SkippedScanner(BaseModel):
    name: str
    error: str


class ScannerFindings(BaseModel):
    tool: str
    findings: list[Finding] = Field(default_factory=list)
    skipped: list[SkippedScanner] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # e.g. "gitleaks: not installed"
    # What a scanner read, by kind, for a document to say what was checked: the
    # deployment_exposure scanner's files per family (UNVAR-98).
    coverage: dict[str, dict[str, int]] = Field(default_factory=dict)
