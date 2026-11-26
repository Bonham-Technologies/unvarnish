from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import ToolContext
from unvarnish.schemas.ai_usage import AIUsage
from unvarnish.schemas.analysis import ExtractState, Failures, UnitsIndex
from unvarnish.schemas.delta import Delta
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.rollup import ModulesIndex
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.sensitive_data import SensitiveData
from unvarnish.schemas.toolmodel import RequirementsInventory, ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.render")


@dataclass
class RenderInputs:
    census: Census
    metrics: Metrics
    git: GitStats
    deps: Dependencies
    scan: ScannerFindings
    units: UnitsIndex | None = None
    extract_state: ExtractState | None = None
    modules: ModulesIndex | None = None
    tool_model: ToolModel | None = None
    requirements: RequirementsInventory | None = None
    model_findings: ModelFindings | None = None
    failures: Failures | None = None
    ai_usage: AIUsage | None = None  # None when the ai_usage scanner did not run (UNVAR-91)
    # None when the sensitive_data scanner did not run (UNVAR-100)
    sensitive_data: SensitiveData | None = None
    delta: Delta | None = None  # set by the render phase when there is a baseline (UNVAR-40)


def _optional[T: BaseModel](path: Path, cls: type[T]) -> T | None:
    if not path.exists():
        return None
    try:
        return read_artifact(path, cls).data
    except Exception as exc:  # a corrupt optional artifact must not block the documents
        log.warning("ignoring unreadable %s: %r", path.name, exc)
        return None


def load_render_inputs(ctx: ToolContext) -> RenderInputs:
    p = ctx.paths
    return RenderInputs(
        census=read_artifact(p.census, Census).data,
        metrics=read_artifact(p.metrics, Metrics).data,
        git=read_artifact(p.git, GitStats).data,
        deps=read_artifact(p.dependencies, Dependencies).data,
        scan=read_artifact(p.scanner_findings, ScannerFindings).data,
        units=_optional(p.units_index, UnitsIndex),
        extract_state=_optional(p.extract_state, ExtractState),
        modules=_optional(p.modules_index, ModulesIndex),
        tool_model=_optional(p.tool_model, ToolModel),
        requirements=_optional(p.capabilities, RequirementsInventory),
        model_findings=_optional(p.model_findings, ModelFindings),
        failures=_optional(p.failures, Failures),
        ai_usage=_optional(p.ai_usage, AIUsage),
        sensitive_data=_optional(p.sensitive_data, SensitiveData),
    )
