from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from unvarnish.schemas.finding import Category, Finding
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics


@dataclass
class ScanContext:
    tool: str
    source_root: Path
    census: Census
    metrics: Metrics
    git: GitStats
    dependencies: Dependencies
    options: dict[str, Any] = field(default_factory=dict)
    engagement_root: Path | None = None  # relative option paths resolve against it
    # An inventory artifact the scanner built, which the scan phase writes beside its
    # findings: the ai_usage scanner's AIUsage (UNVAR-91).
    inventory: Any = None


class Scanner(Protocol):
    name: str
    category: Category

    def run(self, ctx: ScanContext) -> list[Finding]: ...
