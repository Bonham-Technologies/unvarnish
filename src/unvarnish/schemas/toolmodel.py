from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import (
    Category,
    Effort,
    Evidence,
    Finding,
    Severity,
    coerce_effort,
)


class Actor(BaseModel):
    name: str
    description: str


class EntryPoint(BaseModel):
    name: str
    kind: Literal["http", "cli", "ui", "job", "queue", "library", "other"]
    module: str
    description: str


class DataStore(BaseModel):
    name: str
    kind: Literal["db", "file", "cache", "queue", "object_store", "spreadsheet",
                  "browser_storage", "other"]
    description: str
    modules: list[str] = Field(default_factory=list)


class ExternalSystem(BaseModel):
    name: str
    kind: Literal["http", "db", "queue", "email", "auth", "payment", "storage", "other"]
    direction: Literal["inbound", "outbound", "both"]
    description: str
    modules: list[str] = Field(default_factory=list)


class ModuleMapEntry(BaseModel):
    path: str
    role: str
    depends_on: list[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    source: str
    target: str
    data: str
    via: str | None = None


class CapabilityOut(BaseModel):
    actor: str
    action: str
    object: str
    description: str
    implementing_modules: list[str] = Field(default_factory=list)
    data_touched: list[str] = Field(default_factory=list)
    implicit: bool = False


def capability_id(tool: str, actor: str, action: str, obj: str) -> str:
    key = f"{tool}|{actor.strip().lower()}|{action.strip().lower()}|{obj.strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


class Capability(CapabilityOut):
    id: str
    tool: str
    evidence: list[Evidence] = Field(default_factory=list)  # empty: no known module cited


class BusinessRule(BaseModel):
    description: str
    module: str
    kind: Literal["hardcoded_list", "threshold", "exemption", "mapping", "schedule", "other"]


class ToolCandidateFinding(BaseModel):
    category: Category
    severity: Severity
    title: str
    summary: str
    impact: str
    remediation: str
    effort: Effort | None = None
    effort_note: str | None = None
    paths: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("effort", mode="before")
    @classmethod
    def _effort(cls, value: object) -> object:
        return coerce_effort(value)


class DirectoryRollup(BaseModel):
    """Model output over one chunk of module digests when a tool is too big for one call."""

    summary: str
    responsibilities: list[str] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    external_systems: list[ExternalSystem] = Field(default_factory=list)
    notable_modules: list[ModuleMapEntry] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    candidate_findings: list[ToolCandidateFinding] = Field(default_factory=list)


class ToolRollup(BaseModel):
    """Model output for the whole tool."""

    purpose: str
    actors: list[Actor] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    external_systems: list[ExternalSystem] = Field(default_factory=list)
    internal_stack: list[str] = Field(default_factory=list)
    module_map: list[ModuleMapEntry] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    deployment_assumptions: list[str] = Field(default_factory=list)
    capabilities: list[CapabilityOut] = Field(default_factory=list)
    business_rules: list[BusinessRule] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    candidate_findings: list[ToolCandidateFinding] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class ToolModel(BaseModel):
    """Artifact analysis/tool.json."""

    tool: str
    purpose: str
    actors: list[Actor]
    entry_points: list[EntryPoint]
    data_stores: list[DataStore]
    external_systems: list[ExternalSystem]
    internal_stack: list[str]
    module_map: list[ModuleMapEntry]
    data_flows: list[DataFlow]
    deployment_assumptions: list[str]
    capabilities: list[Capability]
    business_rules: list[BusinessRule]
    open_questions: list[str]
    findings: list[Finding] = Field(default_factory=list)
    dropped_findings: int = 0
    hierarchical: bool = False
    chunks: int = 0  # directory chunks that succeeded
    chunks_attempted: int = 0
    chunks_failed: list[str] = Field(default_factory=list)  # path prefixes of failed chunks
    modules_covered: int = 0  # modules whose digests reached the tool rollup
    confidence: float
    backend: str
    model: str
    usage: Usage
    prompt_version: str
    attempts: int = 1


class DataInventoryRow(BaseModel):
    name: str
    kind: str
    description: str
    used_by: list[str] = Field(default_factory=list)  # capability ids


class RequirementsInventory(BaseModel):
    """Artifact analysis/capabilities.json: the requirements view of the tool model."""

    tool: str
    actors: list[Actor]
    capabilities: list[Capability]
    data_inventory: list[DataInventoryRow]
    business_rules: list[BusinessRule]
    open_questions: list[str]
