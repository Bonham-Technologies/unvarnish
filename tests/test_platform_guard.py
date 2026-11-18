"""UNVAR-35: native Windows is unsupported, and says so instead of raising ImportError."""

from __future__ import annotations

import subprocess
import sys

from unvarnish._platform import unsupported_platform_message

# Pretend to be Windows before the package loads: no fcntl, and sys.platform says win32.
WINDOWS_IMPORT = """
import sys
sys.modules["fcntl"] = None
sys.platform = "win32"
import unvarnish.cli
"""


def test_windows_gets_a_clear_message_and_exit_2():
    proc = subprocess.run([sys.executable, "-c", WINDOWS_IMPORT], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    assert "ImportError" not in proc.stderr
    assert "does not run natively on Windows" in proc.stderr
    assert "Docker" in proc.stderr


def test_message_names_docker_only_on_windows():
    message = unsupported_platform_message("win32")
    assert message is not None
    assert "Docker" in message
    for platform in ("linux", "darwin", "cygwin"):
        assert unsupported_platform_message(platform) is None


def test_supported_platform_imports_normally():
    proc = subprocess.run([sys.executable, "-c", "import unvarnish.cli"], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0, proc.stderr
