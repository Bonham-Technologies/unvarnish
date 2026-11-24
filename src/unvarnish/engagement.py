from __future__ import annotations

import re
from pathlib import Path

import yaml

from unvarnish.config import EngagementConfig, load_config

TOOL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
CONFIG_NAME = "engagement.yaml"


class EngagementError(Exception):
    pass


class NotAnEngagement(EngagementError):
    pass


class EngagementExists(EngagementError):
    pass


class ToolPaths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.inventory = root / "inventory"
        self.analysis = root / "analysis"
        self.docs = root / "docs"
        self.meta_file = root / "tool.yaml"
        self.census = self.inventory / "census.json"
        self.metrics = self.inventory / "metrics.json"
        self.dependencies = self.inventory / "dependencies.json"
        self.git = self.inventory / "git.json"
        self.scanner_findings = self.inventory / "scanner-findings.json"
        self.ai_usage = self.inventory / "ai-usage.json"  # written by scan (UNVAR-91)
        self.failures = self.analysis / "failures.json"
        self.findings_doc = self.docs / "findings.md"
        self.render_state = self.docs / "render-state.json"
        self.run_record = self.analysis / "run-record.json"
        self.units_index = self.analysis / "units.json"
        self.unit_dir = self.analysis / "units"
        self.extract_state = self.analysis / "extract-state.json"
        self.module_dir = self.analysis / "modules"
        self.modules_index = self.analysis / "modules.json"
        self.tool_model = self.analysis / "tool.json"
        self.capabilities = self.analysis / "capabilities.json"
        self.model_findings = self.analysis / "findings.json"
        self.architecture_doc = self.docs / "architecture.md"
        self.requirements_doc = self.docs / "requirements.md"
        self.diagrams = self.docs / "diagrams.json"
        self.baseline = self.analysis / "baseline.json"  # run --baseline's snapshot (UNVAR-40)
        self.delta = self.analysis / "delta.json"

    def ensure_dirs(self) -> None:
        for d in (self.root, self.inventory, self.analysis, self.docs):
            d.mkdir(parents=True, exist_ok=True)


class Engagement:
    def __init__(self, root: Path, config: EngagementConfig) -> None:
        self.root = root.resolve()
        self.config = config

    # --- construction -----------------------------------------------------
    @classmethod
    def create(
        cls, root: Path, client: str | None = None, consultant: str | None = None
    ) -> Engagement:
        root = root.resolve()
        if (root / CONFIG_NAME).exists():
            raise EngagementExists(f"{root} already contains {CONFIG_NAME}")
        root.mkdir(parents=True, exist_ok=True)
        eng = cls(root, EngagementConfig(client=client, consultant=consultant))
        for d in (eng.tools_dir, eng.comparison_dir, eng.exports_dir, eng.cache_dir, eng.logs_dir,
                  eng.ask_sessions_dir):
            d.mkdir(exist_ok=True)
        eng.save_config()
        return eng

    @classmethod
    def load(cls, root: Path) -> Engagement:
        root = root.resolve()
        cfg_file = root / CONFIG_NAME
        if not cfg_file.exists():
            raise NotAnEngagement(f"{root} has no {CONFIG_NAME}")
        return cls(root, load_config(cfg_file))

    @classmethod
    def find(cls, start: Path) -> Engagement:
        for candidate in [start.resolve(), *start.resolve().parents]:
            if (candidate / CONFIG_NAME).exists():
                return cls.load(candidate)
        raise NotAnEngagement(f"no {CONFIG_NAME} found at or above {start}")

    # --- paths ------------------------------------------------------------
    @property
    def config_file(self) -> Path:
        return self.root / CONFIG_NAME

    @property
    def tools_dir(self) -> Path:
        return self.root / "tools"

    @property
    def comparison_dir(self) -> Path:
        return self.root / "comparison"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def cost_file(self) -> Path:
        return self.root / "cost.json"

    @property
    def lock_file(self) -> Path:
        """Held by run, compare and ask; see unvarnish.lock."""
        return self.root / ".unvarnish" / "run.lock"

    @property
    def comparison_file(self) -> Path:
        return self.comparison_dir / "comparison.json"

    @property
    def comparison_doc(self) -> Path:
        return self.comparison_dir / "comparison.md"

    @property
    def comparison_render_state(self) -> Path:
        return self.comparison_dir / "render-state.json"

    @property
    def comparison_failures(self) -> Path:
        return self.comparison_dir / "failures.json"

    @property
    def comparison_diagrams(self) -> Path:
        return self.comparison_dir / "diagrams.json"

    @property
    def index_dir(self) -> Path:
        return self.cache_dir / "index"

    @property
    def index_file(self) -> Path:
        return self.index_dir / "index.json"

    @property
    def ask_sessions_dir(self) -> Path:
        return self.root / "ask-sessions"

    def tool_paths(self, name: str) -> ToolPaths:
        return ToolPaths(self.tools_dir / name)

    # --- tools ------------------------------------------------------------
    def tool_names(self) -> list[str]:
        return list(self.config.tools)

    def register_tool(self, name: str) -> None:
        if not TOOL_NAME_RE.match(name):
            raise ValueError(
                f"tool name {name!r} must match {TOOL_NAME_RE.pattern} (lowercase, digits, - and _)"
            )
        if name not in self.config.tools:
            self.config.tools.append(name)
            self.save_config()

    # --- persistence ------------------------------------------------------
    def save_config(self) -> None:
        data = self.config.model_dump(mode="json")
        self.config_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
