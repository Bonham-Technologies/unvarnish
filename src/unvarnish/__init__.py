import sys

from unvarnish._platform import unsupported_platform_message

_unsupported = unsupported_platform_message(sys.platform)
if _unsupported is not None:  # before any import that needs a POSIX platform (fcntl)
    sys.stderr.write(_unsupported + "\n")
    raise SystemExit(2)

from importlib.metadata import PackageNotFoundError, version  # noqa: E402

try:
    __version__ = version("unvarnish")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "0.0.0"
