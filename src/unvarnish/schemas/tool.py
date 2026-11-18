from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

OriginKind = Literal["repo", "files", "link"]


class ToolMeta(BaseModel):
    name: str
    origin_kind: OriginKind
    origin: str
    branch: str | None = None
    commit: str | None = None
    ingested_at: datetime
    source_path: str | None = None
    external: bool = False
    # Untracked dependency or build-output directories a local --repo copy left out (UNVAR-8).
    skipped_at_ingest: list[str] = Field(default_factory=list)
