from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

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
    "hidden_text": {"long_run": 32, "max_evidence": 25, "include_tests": False},
    # Opengrep with a local rules directory only (UNVAR-89); empty: not checked.
    "sast": {"rules": "", "max_evidence": 25},
    "ai_usage": {"max_evidence": 25, "include_tests": False},
}


SUPPORTED_SCHEMA_VERSION = 1


class UnsupportedSchemaVersion(ValueError):
    pass


class ConfigError(ValueError):
    """A configuration file that cannot be read or holds invalid values: one problem per line,
    each naming the file and, for a bad value, the dotted key (UNVAR-50). Every line is
    redacted: a key pasted into the wrong place can turn up in the dotted key, a validator's
    message or the value shown."""

    def __init__(self, problems: list[str]) -> None:
        problems = [redact_secrets(p) for p in problems]
        super().__init__("\n".join(problems))
        self.problems = problems


def redact_secrets(text: str) -> str:
    """`text` with every secret the scanner rules recognise redacted: for any line that can
    quote configuration back to the user (error lines, unknown-setting warnings)."""
    from unvarnish.scanners.secrets import redact_text  # import cycle

    return redact_text(text)


def yaml_problem(label: str, exc: yaml.YAMLError) -> str:
    """A YAML syntax error as one line: the file, where, and what."""
    mark = getattr(exc, "problem_mark", None)
    what = getattr(exc, "problem", None) or str(exc)
    where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
    return f"{label}: invalid YAML{where}: {what}"


def validation_problems(err: ValidationError, label: Any) -> list[str]:
    """One line per invalid value: the file, the dotted key, the reason and the value given.
    `label` is the file's name, or a function of the dotted key that returns it."""
    out: list[str] = []
    for e in err.errors():
        key = ".".join(str(part) for part in e["loc"])
        name = label(key) if callable(label) else label
        line = f"{name}: {key}: {e['msg']}" if key else f"{name}: {e['msg']}"
        value = e.get("input")
        if isinstance(value, (str, int, float, bool)) and e["type"] != "missing":
            line += f" (got {shown_value(value)})"
        out.append(line)
    return out


def shown_value(value: Any) -> str:
    """A value as an error line shows it, cut to 60 characters. Redacted before the cut: the
    whole-line redaction could no longer recognise a key cut short."""
    shown = redact_secrets(repr(value))
    return shown if len(shown) <= 60 else shown[:57] + "..."


def read_yaml(path: Path, label: str) -> Any:
    """Parse a YAML file, turning a syntax error, a file that is not UTF-8 or one that cannot
    be read into a ConfigError naming `label`."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError([yaml_problem(label, exc)]) from exc
    except UnicodeDecodeError as exc:  # UTF-16 from Notepad or PowerShell, say
        raise ConfigError([f"{label}: not UTF-8 text (byte {exc.start}); save it as UTF-8"]) \
            from exc
    except OSError as exc:
        raise ConfigError([f"{label}: cannot be read ({exc.strerror or type(exc).__name__})"]) \
            from exc


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
    # Send the verify phase and the render prose calls through Anthropic's Message Batches
    # API: half the price, results within about an hour (UNVAR-94). Off by default.
    batch: bool = False

    @model_validator(mode="after")
    def _batch_is_anthropic(self) -> BackendConfig:
        if self.batch and self.type != "anthropic":
            raise ValueError("batch: true needs type: anthropic (the Message Batches API is "
                             f"Anthropic's; a {self.type} backend has none)")
        return self

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
    def _merge_scanner_defaults(cls, v: Any) -> Any:
        from unvarnish.scanners.effort import validate_effort_overrides  # import cycle

        if v is not None and not isinstance(v, dict):
            return v  # the field's own type check names scanners (UNVAR-50)
        return validate_effort_overrides(deep_merge(copy.deepcopy(DEFAULT_SCANNER_OPTIONS),
                                                    v or {}))


def user_config_path() -> Path:
    base = os.environ.get("UNVARNISH_CONFIG_DIR")
    root = Path(base) if base else Path.home() / ".config" / "unvarnish"
    return root / "config.yaml"


def _load_yaml(path: Path, label: str) -> dict:
    if not path.exists():
        return {}
    data = read_yaml(path, label) or {}
    if not isinstance(data, dict):
        raise ConfigError([f"{label}: must contain a mapping at top level"])
    return data


def has_key(data: Any, dotted: str) -> bool:
    """Whether a parsed YAML mapping sets the dotted key itself."""
    for part in dotted.split("."):
        if not isinstance(data, dict) or part not in data:
            return False
        data = data[part]
    return True


def load_config(engagement_file: Path) -> EngagementConfig:
    """The engagement's configuration: the user config with engagement.yaml over it. A file
    that cannot be parsed or a value that does not validate raises ConfigError."""
    user_file = user_config_path()
    user = _load_yaml(user_file, str(user_file))
    own = _load_yaml(engagement_file, engagement_file.name)
    merged = deep_merge(user, own)
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
        log.warning("%s: unknown setting %s is ignored", engagement_file.name,
                    redact_secrets(repr(key)))
    try:
        return EngagementConfig.model_validate(merged)
    except ValidationError as exc:
        def blame(key: str) -> str:  # the user config, when only it sets the key
            if key and not has_key(own, key) and has_key(user, key):
                return str(user_file)
            return engagement_file.name
        raise ConfigError(validation_problems(exc, blame)) from exc


FREE_FORM = {"scanners"}  # scanner options are each scanner's own


def _option_type(default: Any) -> tuple[str, Any] | None:
    """What a built-in scanner option must be, judged by its default: (description, check),
    or None for a default of another type, which is not checked."""
    if isinstance(default, bool):
        return "true or false", lambda v: isinstance(v, bool)
    if isinstance(default, int):
        return "a whole number", lambda v: isinstance(v, int) and not isinstance(v, bool)
    if isinstance(default, float):
        return "a number", lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
    if isinstance(default, list):
        return "a list of strings", lambda v: isinstance(v, list) and all(
            isinstance(x, str) for x in v)
    if isinstance(default, str):
        return "a string", lambda v: isinstance(v, str)
    return None


def scanner_option_problems(scanners: dict[str, Any]) -> list[tuple[str, str]]:
    """Built-in scanner options whose value is not of the default's type, as (dotted key,
    problem). Scanner options are free-form, so loading accepts them; a scanner given one then
    fails at run time (UNVAR-50)."""
    out: list[tuple[str, str]] = []
    for scanner, defaults in DEFAULT_SCANNER_OPTIONS.items():
        options = scanners.get(scanner)
        if not isinstance(options, dict):
            continue
        for key, default in defaults.items():
            if key not in options:
                continue
            kind = _option_type(default)
            if kind is None:
                continue
            what, ok = kind
            if not ok(options[key]):
                dotted = f"scanners.{scanner}.{key}"
                out.append((dotted, f"{dotted}: expected {what} "
                                    f"(got {shown_value(options[key])})"))
    return out


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
