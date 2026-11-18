from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

log = logging.getLogger("unvarnish.config")

DEFAULT_SCANNER_OPTIONS: dict[str, dict[str, Any]] = {
    "oversized_files": {"file_lines": 1500, "function_lines": 150, "html_script_lines": 500},
    "bus_factor": {"single_author_share": 0.9},
    "generated_bulk": {"commit_lines": 2000},
    "dependencies": {"offline": True},
    "secrets": {"use_gitleaks": True},
    "hardcoded_infra": {"max_evidence": 25, "include_tests": False},
    "vendored_bulk": {"binary_bytes": 1_000_000},
    "client_exposure": {
        "client_roots": ["src/", "public/", "dist/"],
        "client_extensions": [".js", ".ts", ".jsx", ".tsx", ".html", ".vue", ".svelte"],
        # Names public by design: matched as substrings of a NEXT_PUBLIC_/VITE_/... name.
        "public_names": ["ANON_KEY", "PUBLISHABLE", "PUBLIC_KEY", "SITE_KEY",
                         "FIREBASE_API_KEY", "MAPS_API_KEY", "MAPBOX_TOKEN", "POSTHOG_KEY"],
        "auth_window": 15, "cors_window": 10, "max_evidence": 25, "include_tests": False,
    },
    "end_of_life": {"warn_months": 6, "max_data_age_days": 90},
}


SUPPORTED_SCHEMA_VERSION = 1


class UnsupportedSchemaVersion(ValueError):
    pass


class BackendCapabilities(BaseModel):
    json_schema: bool = True
    tool_calling: bool = True
    context_window: int = 200_000
    prompt_caching: bool = False
    # Newer OpenAI and Azure models take max_completion_tokens; switched automatically on the
    # 400 that names it, or set here.
    max_tokens_param: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"


ANTHROPIC_CONTEXT_WINDOW = 1_000_000


class BackendConfig(BaseModel):
    type: Literal["anthropic", "openai_compatible"]
    base_url: str | None = None
    api_key_env: str | None = None
    api_key_keychain: str | None = None
    unit_tokens: int | None = None
    timeout_s: float | None = None  # per request; None means the backend's default
    # Extra fields sent with every OpenAI-compatible request, e.g. OpenRouter's
    # {"provider": {"require_parameters": true}} or vLLM's guided-decoding options.
    extra_body: dict[str, Any] | None = None
    capabilities: BackendCapabilities = Field(default_factory=BackendCapabilities)

    @model_validator(mode="before")
    @classmethod
    def _anthropic_context(cls, data: Any) -> Any:
        """Current Claude models accept a 1M-token context; other servers keep 200k unless
        configured."""
        if isinstance(data, dict) and data.get("type") == "anthropic":
            caps = dict(data.get("capabilities") or {})
            caps.setdefault("context_window", ANTHROPIC_CONTEXT_WINDOW)
            data = {**data, "capabilities": caps}
        return data


class ModelRef(BaseModel):
    backend: str
    model: str
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None


class ModelsConfig(BaseModel):
    default: ModelRef | None = None
    phases: dict[str, ModelRef] = Field(default_factory=dict)
    # Used once when a request is refused twice (safety classifiers can refuse benign code).
    refusal_fallback: ModelRef | None = None


class PipelineConfig(BaseModel):
    unit_tokens: int = 8000
    concurrency: int = 8
    parallel_tools: int = 4  # tools run at once; concurrency still caps model calls
    rate_limit_retries: int = 8  # our own backoff on 429s, after the SDK's retries
    rollup_input_tokens: int = 40_000  # module digests per tool-rollup call before chunking
    # A module (file) with one unit is rolled up from that unit's extraction, with no model call;
    # true asks the model for every module, as the spec first described.
    rollup_single_unit_modules: bool = False
    # A lock whose holder is on another kernel (another machine, or the macOS host beside a
    # Docker container) counts as stale once its heartbeat is this old (unvarnish.lock).
    lock_stale_minutes: float = Field(default=10, gt=0)


class Prices(BaseModel):
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float | None = None   # None: billed as input (an upper bound)
    cache_write_per_mtok: float | None = None


class BudgetConfig(BaseModel):
    max_tokens: int | None = None
    prices: Prices | dict[str, Prices] | None = None  # one price, or per model id


class BrandingConfig(BaseModel):
    reference_docx: str | None = None
    html_css: str | None = None


class EffortDays(BaseModel):
    """Engineer-days at the top of each remediation-effort band (UNVAR-42). A band's range
    runs from the band below's figure to its own (S from 0)."""

    S: float = Field(gt=0)
    M: float = Field(gt=0)
    L: float = Field(gt=0)
    XL: float = Field(gt=0)

    @model_validator(mode="after")
    def _ascending(self) -> EffortDays:
        if not self.S <= self.M <= self.L <= self.XL:
            raise ValueError("report.effort_days must not shrink from S to XL")
        return self


class ReportConfig(BaseModel):
    tone: Literal["direct", "measured"] = "direct"
    # Findings at or above this severity get full sections; lower ones one table row each.
    detail_from: Literal["critical", "high", "medium", "low", "info"] = "medium"
    templates_dir: str | None = None
    # Document language for exports (BCP 47, e.g. "en", "en-GB", "de"): screen readers use it.
    lang: str = Field(default="en", pattern=r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")
    branding: BrandingConfig = Field(default_factory=BrandingConfig)
    # Day figures beside the effort bands; off until set, the bands always show (UNVAR-42).
    effort_days: EffortDays | None = None


class AskConfig(BaseModel):
    max_tool_calls: int = 12
    # Total time one grep_source call may spend matching: the pattern comes from the model,
    # which text in the analysed code can steer, so a catastrophic one must not hang `ask`.
    grep_timeout_s: float = Field(default=5.0, gt=0)


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class ConsolidationConstraints(BaseModel):
    """What the consultant already knows the consolidated tool must fit (spec §17)."""

    target_platform: str | None = None
    approved_stack: list[str] = Field(default_factory=list)
    must_keep: list[str] = Field(default_factory=list)   # systems or integrations to survive
    retire: list[str] = Field(default_factory=list)      # systems the client wants gone
    notes: str | None = None

    def is_empty(self) -> bool:
        return not (self.target_platform or self.approved_stack or self.must_keep
                    or self.retire or self.notes)


class BaselineConfig(BaseModel):
    """The re-audit delta (`run --baseline`, UNVAR-40)."""

    # Finding ids the client has accepted the risk of: shown as "Risk accepted", never resolved.
    accepted: list[str] = Field(default_factory=list)
    # A finding with the same title and path counts as the same finding (moved) within this
    # many lines of where the previous review saw it.
    line_drift: int = Field(default=50, ge=0)


class EngagementConfig(BaseModel):
    schema_version: int = 1
    client: str | None = None
    consultant: str | None = None
    tools: list[str] = Field(default_factory=list)
    backends: dict[str, BackendConfig] = Field(default_factory=dict)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scanners: dict[str, dict[str, Any]] = Field(
        default_factory=lambda: copy.deepcopy(DEFAULT_SCANNER_OPTIONS)
    )
    report: ReportConfig = Field(default_factory=ReportConfig)
    ask: AskConfig = Field(default_factory=AskConfig)
    consolidation: ConsolidationConstraints = Field(default_factory=ConsolidationConstraints)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)

    @field_validator("scanners", mode="before")
    @classmethod
    def _merge_scanner_defaults(cls, v: Any) -> dict[str, dict[str, Any]]:
        from unvarnish.scanners.effort import validate_effort_overrides  # import cycle

        return validate_effort_overrides(deep_merge(copy.deepcopy(DEFAULT_SCANNER_OPTIONS),
                                                    v or {}))


def user_config_path() -> Path:
    base = os.environ.get("UNVARNISH_CONFIG_DIR")
    root = Path(base) if base else Path.home() / ".config" / "unvarnish"
    return root / "config.yaml"


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping at top level")
    return data


def load_config(engagement_file: Path) -> EngagementConfig:
    merged = deep_merge(_load_yaml(user_config_path()), _load_yaml(engagement_file))
    raw = merged.get("schema_version", 1)
    try:  # compare as a number whatever YAML type it arrived as ("2", 2.0, 2)
        version = float(raw)
    except (TypeError, ValueError):
        version = None
    if version is not None and version > SUPPORTED_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"{engagement_file} has schema_version {raw}, written by a newer Unvarnish; "
            f"this version supports {SUPPORTED_SCHEMA_VERSION}. Upgrade Unvarnish to work on "
            "this engagement.")
    for key in unknown_keys(merged):
        log.warning("%s: unknown setting %r is ignored", engagement_file.name, key)
    return EngagementConfig.model_validate(merged)


FREE_FORM = {"scanners"}  # scanner options are each scanner's own


def unknown_keys(data: Any, model: type[BaseModel] | None = None, prefix: str = "") -> list[str]:
    """Dotted paths of keys the configuration model does not define (typos are otherwise
    silently ignored)."""
    model = model or EngagementConfig
    if not isinstance(data, dict):
        return []
    out: list[str] = []
    for key, value in data.items():
        field = model.model_fields.get(key)
        path = f"{prefix}{key}"
        if field is None:
            out.append(path)
            continue
        if key in FREE_FORM and not prefix:
            continue
        inner = _dict_value_model(field.annotation)
        if inner is not None:
            if isinstance(value, dict):
                for k, v in value.items():
                    out += unknown_keys(v, inner, f"{path}.{k}.")
            continue
        sub = _model_of(field.annotation)
        if sub is not None:
            out += unknown_keys(value, sub, path + ".")
    return out


def _model_of(annotation: Any) -> type[BaseModel] | None:
    import typing

    if typing.get_origin(annotation) is dict:
        return None
    for cand in (annotation, *typing.get_args(annotation)):
        if isinstance(cand, type) and issubclass(cand, BaseModel):
            return cand
    return None


def _dict_value_model(annotation: Any) -> type[BaseModel] | None:
    import typing

    for cand in (annotation, *typing.get_args(annotation)):
        if typing.get_origin(cand) is dict:  # dict[str, Model], possibly inside Optional
            args = typing.get_args(cand)
            if len(args) == 2:
                return _model_of(args[1])
    return None
