"""Which platforms Unvarnish runs on natively (UNVAR-35).

Native Windows is unsupported: the engagement lock uses `fcntl`, and the distributable is the
Docker image, which bundles the scanners, pandoc and fonts. The package checks this before it
imports anything else, so a Windows user gets one clear sentence instead of an ImportError.
"""

from __future__ import annotations

WINDOWS_MESSAGE = (
    "error: Unvarnish does not run natively on Windows. Run it with the Docker image "
    "instead (see \"Docker\" in the README): docker run --rm -v <engagement>:/engagement "
    "unvarnish run"
)


def unsupported_platform_message(platform: str) -> str | None:
    """The message to print and exit with on `platform` (a `sys.platform` value), or None."""
    if platform == "win32":
        return WINDOWS_MESSAGE
    return None
