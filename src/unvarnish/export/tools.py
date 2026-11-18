from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence

INSTALL_HINTS: dict[str, str] = {
    "pandoc": "brew install pandoc  |  https://pandoc.org/installing (apt's pandoc is often "
              "too old)",
    "dot": "brew install graphviz  |  apt install graphviz  |  https://graphviz.org/download",
    "weasyprint": "brew install weasyprint  |  pip install 'weasyprint>=66'  |  apt install "
                  "weasyprint (apt's is often too old to tag PDFs)",
}
REQUIRED_BY_FORMAT: dict[str, tuple[str, ...]] = {
    "docx": ("pandoc", "dot"),
    "html": ("pandoc", "dot"),
    "pdf": ("pandoc", "dot", "weasyprint"),
}
MIN_PANDOC = (2, 19)  # --embed-resources
VERSION_RE = re.compile(r"pandoc(?:\.exe)?\s+(\d+(?:\.\d+)*)")
# The first weasyprint whose PDF/UA mode leaves link annotations alone: 61 to 65 set each one's
# Hidden flag, so a tagged PDF from them has no clickable links in Acrobat (UNVAR-22).
MIN_WEASYPRINT_TAGGED = (66, 0)
WEASYPRINT_VERSION_RE = re.compile(r"weasyprint\s+version\s+(\d+(?:\.\d+)*)", re.IGNORECASE)


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


def installed_weasyprint_version() -> tuple[int, ...] | None:
    """The weasyprint on PATH as a version tuple, or None when it cannot be determined."""
    try:
        out = subprocess.run(["weasyprint", "--version"], capture_output=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = WEASYPRINT_VERSION_RE.search(out.decode("utf-8", errors="replace"))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _dotted(version: Sequence[int]) -> str:
    return ".".join(str(x) for x in version)


def untagged_pdf_reason(version: tuple[int, ...] | None) -> str | None:
    """None when this weasyprint writes tagged PDFs whose links work; otherwise why PDFs are
    exported untagged instead, for the operator."""
    if version is not None and version >= MIN_WEASYPRINT_TAGGED:
        return None
    need = _dotted(MIN_WEASYPRINT_TAGGED)
    found = (f"weasyprint {_dotted(version)} is older than {need}"
             if version is not None else "could not tell which weasyprint is installed")
    return (f"{found}, so PDFs are exported untagged (no PDF/UA structure for screen "
            f"readers): before {need}, weasyprint's tagged PDFs hide every link. Install "
            f"weasyprint {need} or later (pip install 'weasyprint>={need}') or use the Docker "
            "image.")


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
        found = _dotted(version)
        need = _dotted(MIN_PANDOC)
        raise ToolsMissing([], [f"pandoc {found} is too old: export needs pandoc {need} or "
                                f"later ({INSTALL_HINTS['pandoc']})."])
