from __future__ import annotations

import os

TRUE_VALUES = {"1", "true", "yes", "on"}


def env_flag(name: str) -> bool:
    """True only for 1/true/yes/on (any case); "0", "false", and empty are off."""
    return os.environ.get(name, "").strip().lower() in TRUE_VALUES
