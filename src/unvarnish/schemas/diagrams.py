from __future__ import annotations

from pydantic import BaseModel, Field

from unvarnish.render.diagram import Diagram


class DiagramSet(BaseModel):
    """Artifact docs/diagrams.json (per tool) and comparison/diagrams.json: the diagrams a
    render drew, by the name the document's marker comments use."""

    diagrams: dict[str, Diagram] = Field(default_factory=dict)
