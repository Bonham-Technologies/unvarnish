"""End-of-life data: where the bundle lives, how it is read offline, and how
`unvarnish eol refresh` builds it from endoflife.date's API v1 (UNVAR-43).

The bundle is one JSON file, `endoflife.json`, in the data directory: `$UNVARNISH_EOL_DIR`
when set (an image or site kit sets it, as it sets the OSV database directory), else
`$XDG_DATA_HOME/unvarnish/eol`, else `~/.local/share/unvarnish/eol`."""

from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.request
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from unvarnish import __version__
from unvarnish.schemas.eol import EOL_BUNDLE_FORMAT, EolBundle, EolCycle, EolProduct

DIR_ENV = "UNVARNISH_EOL_DIR"
BUNDLE_NAME = "endoflife.json"
API = "https://endoflife.date/api/v1/products/"
# endoflife.date slugs. Java is Eclipse Temurin (there is no "java" product; Temurin is the
# OpenJDK build the deprecated `openjdk` Docker image points to); Alpine is "alpine-linux".
PRODUCTS: tuple[str, ...] = (
    "python", "nodejs", "go", "dotnet", "eclipse-temurin", "ruby", "php",
    "django", "rails", "spring-boot", "react", "angular", "vue", "nextjs",
    "postgresql", "mysql", "ubuntu", "debian", "alpine-linux",
)
FETCH_TIMEOUT = 30.0


class EolFetchError(RuntimeError):
    pass


def data_dir() -> Path:
    """Where the bundle is looked for, and where `eol refresh` writes it by default."""
    configured = os.environ.get(DIR_ENV)
    if configured:
        return Path(configured)
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "unvarnish" / "eol"


def bundle_path() -> Path:
    return data_dir() / BUNDLE_NAME


def load_bundle(path: Path | None = None) -> tuple[EolBundle | None, str | None]:
    """(bundle, None), or (None, why not). Never raises; the reason names no local path."""
    path = path or bundle_path()
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None, "no end-of-life data bundle"
    except OSError as exc:
        return None, f"end-of-life data bundle unreadable ({type(exc).__name__})"
    try:
        raw = json.loads(text)
    except ValueError:
        return None, "end-of-life data bundle unreadable (not JSON)"
    if isinstance(raw, dict) and raw.get("format", EOL_BUNDLE_FORMAT) != EOL_BUNDLE_FORMAT:
        return None, (f"end-of-life data bundle unreadable (format {raw.get('format')}; this "
                      f"version of Unvarnish reads format {EOL_BUNDLE_FORMAT})")
    try:
        return EolBundle.model_validate(raw), None
    except ValidationError:
        return None, f"end-of-life data bundle unreadable (not bundle format {EOL_BUNDLE_FORMAT})"


def bundle_date(path: Path | None = None) -> str | None:
    """The bundle's fetch date (YYYY-MM-DD), or None without a readable bundle."""
    bundle, _ = load_bundle(path)
    return bundle.fetched.isoformat() if bundle else None


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": f"unvarnish/{__version__}",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _product(raw: Any) -> EolProduct:
    result = raw["result"]
    releases = result["releases"]
    if not isinstance(releases, list):
        raise ValueError("response has no releases list")
    cycles = [EolCycle(cycle=str(r["name"]), codename=r.get("codename"),
                       eol_from=r.get("eolFrom"), is_eol=bool(r.get("isEol")),
                       is_maintained=bool(r.get("isMaintained", not r.get("isEol"))),
                       latest=(r.get("latest") or {}).get("name"))
              for r in releases]
    return EolProduct(label=str(result.get("label") or result.get("name")), cycles=cycles)


def build_bundle(*, fetch: Callable[[str], Any] | None = None, today: date | None = None,
                 products: Sequence[str] = PRODUCTS, attempts: int = 4, backoff: float = 2.0,
                 sleep: Callable[[float], None] = time.sleep) -> EolBundle:
    """Every product's cycles from the API, retrying each with exponential backoff. Raises
    EolFetchError naming the product when one still fails, so no partial bundle is made."""
    fetch = fetch or fetch_json
    out: dict[str, EolProduct] = {}
    for slug in products:
        for attempt in range(1, attempts + 1):
            try:
                out[slug] = _product(fetch(API + slug))
                break
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                if attempt >= attempts:
                    raise EolFetchError(f"{slug}: {exc}") from exc
                sleep(backoff * 2 ** (attempt - 1))
    return EolBundle(fetched=today or datetime.now(UTC).date(), products=out)


def ensure_writable(directory: Path | None = None) -> Path:
    """Create the folder if needed and prove a file can be written there; raises OSError."""
    target = directory or data_dir()
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=target):
        pass
    return target


def write_bundle(bundle: EolBundle, directory: Path | None = None) -> Path:
    """Write the bundle atomically, so a failed write leaves the previous one in place."""
    target = (directory or data_dir()) / BUNDLE_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(bundle.model_dump(mode="json"), indent=2, sort_keys=True,
                              ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(target)
    return target
