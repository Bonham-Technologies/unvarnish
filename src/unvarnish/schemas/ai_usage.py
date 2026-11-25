"""The AI services a tool's own code uses (UNVAR-91): `inventory/ai-usage.json`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Hosting = Literal["hosted", "local", "unknown"]


class AIService(BaseModel):
    """One provider (and model, when named) at one place in the code."""

    provider: str
    model: str | None = None  # the model id, when the code names one
    hosting: Hosting
    path: str
    line: int
    # How the code reaches it when that differs from the provider: "OpenAI SDK" for a local
    # server called through the OpenAI client, "LangChain" for a framework adapter.
    via: str | None = None
    detected_by: Literal["import", "endpoint", "model id", "dependency"]


class AICall(BaseModel):
    """A call that sends a request to a model."""

    path: str
    line: int
    provider: str | None = None
    bounded: bool = True  # a token cap or a timeout was found for it


class AIToolDefinition(BaseModel):
    """A tool (function schema) handed to a model, or an agent that calls tools."""

    path: str
    line: int
    kind: Literal["tool", "agent"]
    name: str | None = None


class AIUsage(BaseModel):
    tool: str
    services: list[AIService] = Field(default_factory=list)
    calls: list[AICall] = Field(default_factory=list)
    tool_definitions: list[AIToolDefinition] = Field(default_factory=list)

    def providers_by_hosting(self) -> dict[str, list[str]]:
        """Distinct providers per hosting kind, for the comparison's risk table."""
        out: dict[str, set[str]] = {}
        for s in self.services:
            out.setdefault(s.hosting, set()).add(s.provider)
        return {k: sorted(v) for k, v in sorted(out.items())}
