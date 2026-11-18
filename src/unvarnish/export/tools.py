from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence

INSTALL_HINTS: dict[str, str] = {
    "pandoc": "brew install pandoc  |  https://pandoc.org/installing (apt's pandoc is often "
              "too old)",
    "dot": "brew install graphviz  |  apt install graphviz  |  https://graphviz.org/download",
    "weasyprint": "brew install weasyprint  |  apt install weasyprint  |  pip install weasyprint",
}
REQUIRED_BY_FORMAT: dict[str, tuple[str, ...]] = {
    "docx": ("pandoc", "dot"),
    "html": ("pandoc", "dot"),
    "pdf": ("pandoc", "dot", "weasyprint"),
}
MIN_PANDOC = (2, 19)  # --embed-resources
VERSION_RE = re.compile(r"pandoc(?:\.exe)?\s+(\d+(?:\.\d+)*)")


def missing_tools(formats: Sequence[str],
                  which: Callable[[str], str | None] = shutil.which) -> list[str]:
    needed: list[str] = []
    for fmt in formats:
        for tool in REQUIRED_BY_FORMAT[fmt]:
            if tool not in needed:
                needed.append(tool)
    return [t for t in needed if which(t) is None]


def installed_pandoc_version() -> tuple[int, ...] | None:
    """The pandoc on PATH as a version tuple, or None when it cannot be determined."""
    try:
        out = subprocess.run(["pandoc", "--version"], capture_output=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = VERSION_RE.search(out.decode("utf-8", errors="replace"))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


class ToolsMissing(Exception):
    def __init__(self, tools: Sequence[str], problems: Sequence[str] = ()) -> None:
        self.tools = list(tools)
        lines = []
        if self.tools:
            lines.append(f"export needs {', '.join(self.tools)} on PATH:")
            lines += [f"  {t}: {INSTALL_HINTS[t]}" for t in self.tools]
        lines += list(problems)
        lines.append("  or run Unvarnish from the Docker image, which bundles them.")
        super().__init__("\n".join(lines))


def check_toolchain(formats: Sequence[str], *,
                    which: Callable[[str], str | None] = shutil.which,
                    pandoc_version: Callable[[], tuple[int, ...] | None] = installed_pandoc_version,
                    ) -> None:
    """Raise ToolsMissing when a required tool is absent or pandoc is too old."""
    missing = missing_tools(formats, which=which)
    if missing:
        raise ToolsMissing(missing)
    version = pandoc_version()
    if version is not None and version < MIN_PANDOC:
        found = ".".join(str(x) for x in version)
        need = ".".join(str(x) for x in MIN_PANDOC)
        raise ToolsMissing([], [f"pandoc {found} is too old: export needs pandoc {need} or "
                                f"later ({INSTALL_HINTS['pandoc']})."])
