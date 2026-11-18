from __future__ import annotations

from pydantic import BaseModel, Field


class RenderState(BaseModel):
    tool: str
    documents: dict[str, str] = Field(default_factory=dict)
