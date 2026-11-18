from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from unvarnish.schemas.cost import Usage
from unvarnish.schemas.finding import Effort, Finding, coerce_effort


class Verdict(BaseModel):
    """Model output of one independent verification call."""

    verdict: Literal["confirmed", "downgraded", "rejected"]
    reason: str
    effort: Effort | None = None  # the band the lines support; None keeps the claimed one

    @field_validator("effort", mode="before")
    @classmethod
    def _effort(cls, value: object) -> object:
        return coerce_effort(value)


class ModelFindings(BaseModel):
    """Artifact analysis/findings.json: deduplicated model findings after verification."""

    tool: str
    findings: list[Finding] = Field(default_factory=list)
    verified: int = 0
    confirmed: int = 0
    downgraded: int = 0
    rejected: int = 0
    unverified: int = 0
    usage: Usage = Field(default_factory=Usage)
    stopped_for_budget: bool = False
