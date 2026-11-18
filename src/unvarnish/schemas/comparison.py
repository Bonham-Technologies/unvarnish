from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.config import ConsolidationConstraints
from unvarnish.schemas.cost import Usage


class CapabilityRef(BaseModel):
    tool: str
    capability_id: str


class NormalisedCapability(BaseModel):
    name: str
    description: str
    actor: str
    members: list[CapabilityRef] = Field(default_factory=list)


class CapabilityNormalisation(BaseModel):
    """Model output: every tool's capabilities grouped into cross-tool capabilities."""

    capabilities: list[NormalisedCapability] = Field(default_factory=list)


class MatrixCell(BaseModel):
    tool: str
    labels: list[str] = Field(default_factory=list)  # "actor can action object" per member


class MatrixRow(BaseModel):
    name: str
    description: str
    actor: str
    cells: list[MatrixCell]
    tools_covering: int
    unmapped: bool = False  # a tool capability the model did not place in any group


class IntegrationEntry(BaseModel):
    tool: str
    kind: str
    direction: str | None = None
    description: str


class IntegrationRow(BaseModel):
    name: str
    category: Literal["data_store", "external_system"]
    entries: list[IntegrationEntry]
    tools: list[str]


class IntegrationItem(BaseModel):
    """One store or external system as one tool describes it; the input to grouping."""

    id: str        # "<tool>#<n>"
    tool: str
    category: Literal["data_store", "external_system"]
    name: str
    kind: str
    direction: str | None = None
    description: str


class IntegrationGroup(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)
    internal: bool = False   # in-process state (memory caches, UI stores): not an integration


class IntegrationGrouping(BaseModel):
    """Model output: which tools' stores and systems are the same thing."""

    groups: list[IntegrationGroup] = Field(default_factory=list)


class RiskRow(BaseModel):
    tool: str
    model_analysed: bool
    files_analysed: int
    source_lines: int
    largest_file_lines: int
    tests_present: bool
    secrets_current: int
    secrets_history: int
    bus_factor: int | None
    top_author_share: float | None
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    critical_or_high: int = 0
    ai_indicators: int = 0
    dependency_vulnerabilities: int | None = None
    # None when the client_exposure scanner did not run for the tool (UNVAR-39).
    client_exposed_credentials: int | None = None
    open_tables: int | None = None
    # Findings per remediation-effort band, "none" for not estimated (UNVAR-42); empty in a
    # comparison written before the bands existed.
    findings_by_effort: dict[str, int] = Field(default_factory=dict)


class AbstractRequirement(BaseModel):
    statement: str
    serves: list[str] = Field(default_factory=list)  # tool names whose users it serves


class ApproachRecommendation(BaseModel):
    capability: str
    recommended_tool: str
    rationale: str


class Consolidation(BaseModel):
    """Model output: a starting point for the consultant's consolidation architecture."""

    union_capabilities: list[str] = Field(default_factory=list)
    abstract_requirements: list[AbstractRequirement] = Field(default_factory=list)
    recommended_approach: list[ApproachRecommendation] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    constraint_conflicts: list[str] = Field(default_factory=list)


class ToolSummary(BaseModel):
    tool: str
    purpose: str | None
    actors: list[str] = Field(default_factory=list)
    capabilities: int = 0
    source_lines: int = 0
    model_analysed: bool = False


class Comparison(BaseModel):
    """Artifact comparison/comparison.json."""

    tools: list[str]
    tools_with_model: list[str]
    tools_not_run: list[str] = Field(default_factory=list)  # registered but never analysed
    summaries: list[ToolSummary]
    capability_matrix: list[MatrixRow] = Field(default_factory=list)
    unmapped_capabilities: int = 0
    dropped_references: int = 0
    integration_map: list[IntegrationRow] = Field(default_factory=list)
    risk_table: list[RiskRow] = Field(default_factory=list)
    consolidation: Consolidation | None = None
    constraints: ConsolidationConstraints | None = None
    normalised: bool = True  # False when capability matching did not run or failed
    skipped_reason: str | None = None
    backend: str | None = None
    model: str | None = None
    usage: Usage = Field(default_factory=Usage)
    prompt_version: str | None = None
    stopped_for_budget: bool = False
