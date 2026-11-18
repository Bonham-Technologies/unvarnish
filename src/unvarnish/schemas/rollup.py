from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from unvarnish.schemas.analysis import CandidateFinding
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Finding


def module_file_id(path: str) -> str:
    """Stable, file-safe id for a module (a source file path)."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]


class ModuleRollup(BaseModel):
    """Model output for one module (file) over its unit extractions."""

    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    interface: list[str] = Field(default_factory=list)
    dependencies_in: list[str] = Field(default_factory=list)
    dependencies_out: list[str] = Field(default_factory=list)
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class Module(BaseModel):
    """Artifact analysis/modules/<module_file_id>.json."""

    id: str
    tool: str
    path: str
    unit_ids: list[str]
    rollup: ModuleRollup
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class ModuleDigest(BaseModel):
    """Compact row in modules.json: the input to the tool rollup and the module map."""

    id: str
    path: str
    language: str | None = None
    units: int
    lines: int
    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    interface: list[str] = Field(default_factory=list)
    dependencies_out: list[str] = Field(default_factory=list)
    external_systems: list[str] = Field(default_factory=list)
    data_read: list[str] = Field(default_factory=list)
    data_written: list[str] = Field(default_factory=list)
    findings: int = 0


class ModulesIndex(BaseModel):
    tool: str
    modules: list[ModuleDigest] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)  # module paths whose rollup call failed
    skipped: list[str] = Field(default_factory=list)  # modules with no extracted units
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
