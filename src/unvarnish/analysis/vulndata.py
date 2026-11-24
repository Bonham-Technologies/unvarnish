"""Exploit data for dependency advisories (UNVAR-90): CISA's Known Exploited Vulnerabilities
(KEV) catalog and FIRST's Exploit Prediction Scoring System (EPSS) scores. `unvarnish
vulndata refresh` downloads both while online; the inventory reads them offline and marks
each advisory it found by its CVE aliases.

The bundle is one gzip file, `vulndata.gz`, beside the end-of-life bundle: in
`$UNVARNISH_VULNDATA_DIR` when set, else the end-of-life data directory (`analysis.eol`).
Its first line is a JSON header (`schemas.vulndata.VulnBundle`: the fetch date, the sources
and the KEV catalog as CVE -> dateAdded); every other line is one EPSS score,
`CVE-YYYY-NNNN,epss,percentile`. A run reads the header, then streams the scores and keeps
only the CVEs its advisories name, so the 300,000-odd scores are never all in memory."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import time
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from unvarnish import __version__
from unvarnish.analysis import eol
from unvarnish.schemas.vulndata import VULN_BUNDLE_FORMAT, VulnBundle

DIR_ENV = "UNVARNISH_VULNDATA_DIR"
BUNDLE_NAME = "vulndata.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Redirects to the day's dated file (epss_scores-YYYY-MM-DD.csv.gz); urllib follows it.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_HEADER = "cve,epss,percentile"
FETCH_TIMEOUT = 120.0
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
NO_BUNDLE = "no exploit data bundle"
Scores = dict[str, tuple[float, float]]


class VulnDataFetchError(RuntimeError):
    pass


def data_dir() -> Path:
    """Where the bundle is looked for, and where `vulndata refresh` writes it by default."""
    configured = os.environ.get(DIR_ENV)
    return Path(configured) if configured else eol.data_dir()


def bundle_path() -> Path:
    return data_dir() / BUNDLE_NAME


def _unreadable(why: str) -> str:
    return f"exploit data bundle unreadable ({why})"


def load_bundle(path: Path | None = None) -> tuple[VulnBundle | None, str | None]:
    """(header, None), or (None, why not). Never raises; the reason names no local path."""
    path = path or bundle_path()
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            first = fh.readline()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None, NO_BUNDLE
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        return None, _unreadable(type(exc).__name__)
    try:
        raw = json.loads(first)
    except ValueError:
        return None, _unreadable("not JSON")
    if isinstance(raw, dict) and raw.get("format", VULN_BUNDLE_FORMAT) != VULN_BUNDLE_FORMAT:
        return None, _unreadable(f"format {raw.get('format')}; this version of Unvarnish "
                                 f"reads format {VULN_BUNDLE_FORMAT}")
    try:
        return VulnBundle.model_validate(raw), None
    except ValidationError:
        return None, _unreadable(f"not bundle format {VULN_BUNDLE_FORMAT}")


def bundle_date(path: Path | None = None) -> str | None:
    """The bundle's fetch date (YYYY-MM-DD), or None without a readable bundle."""
    bundle, _ = load_bundle(path)
    return bundle.fetched.isoformat() if bundle else None


def epss_scores(path: Path, wanted: set[str]) -> tuple[Scores | None, str | None]:
    """The EPSS (score, percentile) of each wanted CVE the bundle holds, or (None, why). The
    whole file is read, so a truncated bundle is unreadable rather than partly used."""
    found: Scores = {}
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            fh.readline()  # the header
            for line in fh:
                cve, _, rest = line.partition(",")
                if cve in wanted:
                    score, _, pct = rest.partition(",")
                    found[cve] = (float(score), float(pct))
    except (OSError, EOFError, UnicodeDecodeError, ValueError) as exc:
        return None, _unreadable(type(exc).__name__)
    return found, None


def advisory_cves(advisory: dict) -> list[str]:
    """The CVE ids among an advisory's id and aliases, upper-cased, in order, once each."""
    ids = advisory.get("ids") or [advisory.get("id")]
    out: list[str] = []
    for i in ids:
        cve = str(i or "").strip().upper()
        if CVE_RE.fullmatch(cve) and cve not in out:
            out.append(cve)
    return out


def annotate(advisories: list[dict], path: Path | None = None
             ) -> tuple[list[dict], str | None, str | None]:
    """(advisories, data date, why not). With a readable bundle each advisory gains `kev`,
    `kev_date_added` (when listed), `epss` and `epss_percentile` (its CVEs' highest score, or
    None), and a KEV-listed one becomes critical; EPSS never changes a severity. Without one
    the advisories come back unchanged, with the reason."""
    path = path or bundle_path()
    bundle, why = load_bundle(path)
    if bundle is None:
        return advisories, None, why
    wanted = {c for a in advisories for c in advisory_cves(a)}
    scores: Scores | None = {}
    if wanted:
        scores, why = epss_scores(path, wanted)
        if scores is None:
            return advisories, None, why
    out = []
    for adv in advisories:
        a = dict(adv)
        cves = advisory_cves(a)
        listed = sorted(bundle.kev[c] for c in cves if c in bundle.kev)
        a["kev"] = bool(listed)
        if listed:
            a["kev_date_added"] = listed[0].isoformat()
            a["severity"] = "critical"
        best = max((scores[c] for c in cves if c in scores), default=None)
        a["epss"], a["epss_percentile"] = best if best else (None, None)
        out.append(a)
    return out, bundle.fetched.isoformat(), None


# --- vulndata refresh -----------------------------------------------------------------------

def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"unvarnish/{__version__}"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read()


def parse_kev(raw: bytes) -> tuple[dict[str, date], str | None]:
    data = json.loads(raw.decode("utf-8"))
    entries = data["vulnerabilities"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("no vulnerabilities list")
    kev: dict[str, date] = {}
    for e in entries:
        cve = str(e["cveID"]).strip().upper()
        if not CVE_RE.fullmatch(cve):
            raise ValueError(f"not a CVE id: {cve[:40]}")
        added = date.fromisoformat(str(e["dateAdded"]))
        kev[cve] = min(added, kev.get(cve, added))
    version = data.get("catalogVersion")
    return kev, str(version) if version else None


def parse_epss(raw: bytes) -> tuple[list[str], str | None, str | None]:
    """(score lines, model version, score date) from the gzipped CSV. Every line is checked,
    so a cut-off or reshaped file fails rather than giving a partial bundle."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    lines = io.StringIO(raw.decode("utf-8"))
    first = lines.readline().strip()
    model = score_date = None
    if first.startswith("#"):
        meta = dict(p.split(":", 1) for p in first[1:].split(",") if ":" in p)
        model = meta.get("model_version") or None
        score_date = (meta.get("score_date") or "")[:10] or None
        first = lines.readline().strip()
    if first != EPSS_HEADER:
        raise ValueError(f"expected the header {EPSS_HEADER!r}, got {first[:60]!r}")
    rows = []
    for n, line in enumerate(lines, start=3):
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        cve = parts[0].upper()
        if len(parts) != 3 or not CVE_RE.fullmatch(cve):
            raise ValueError(f"line {n} is not a score: {line[:60]!r}")
        try:
            values = [float(parts[1]), float(parts[2])]
        except ValueError as exc:
            raise ValueError(f"line {n} is not a score: {line[:60]!r}") from exc
        if not all(0.0 <= v <= 1.0 for v in values):
            raise ValueError(f"line {n} is out of range: {line[:60]!r}")
        rows.append(f"{cve},{parts[1]},{parts[2]}")
    if not rows:
        raise ValueError("no scores")
    return rows, model, score_date


def _fetch_one[T](name: str, url: str, parse: Callable[[bytes], T],
                  fetch: Callable[[str], bytes], attempts: int, backoff: float,
                  sleep: Callable[[float], None]) -> T:
    for attempt in range(1, attempts + 1):
        try:
            return parse(fetch(url))
        except (OSError, EOFError, ValueError, KeyError, TypeError, AttributeError) as exc:
            if attempt >= attempts:
                raise VulnDataFetchError(f"{name}: {exc}") from exc
            sleep(backoff * 2 ** (attempt - 1))
    raise AssertionError("unreachable")  # pragma: no cover


def build_bundle(*, fetch: Callable[[str], bytes] | None = None, today: date | None = None,
                 kev_url: str = KEV_URL, epss_url: str = EPSS_URL, attempts: int = 4,
                 backoff: float = 2.0, sleep: Callable[[float], None] = time.sleep,
                 ) -> tuple[VulnBundle, list[str]]:
    """(header, score lines) from both feeds, each retried with exponential backoff. Raises
    VulnDataFetchError naming the feed when one still fails, so no partial bundle is made."""
    fetch = fetch or fetch_bytes
    kev, catalog = _fetch_one("KEV", kev_url, parse_kev, fetch, attempts, backoff, sleep)
    rows, model, score_date = _fetch_one("EPSS", epss_url, parse_epss, fetch, attempts,
                                         backoff, sleep)
    bundle = VulnBundle(fetched=today or datetime.now(UTC).date(), kev_source=kev_url,
                        kev_catalog_version=catalog, epss_source=epss_url,
                        epss_model_version=model, epss_score_date=score_date,
                        epss_scores=len(rows), kev=kev)
    return bundle, rows


def ensure_writable(directory: Path | None = None) -> Path:
    """Create the folder if needed and prove a file can be written there; raises OSError."""
    return eol.ensure_writable(directory or data_dir())


def write_bundle(bundle: VulnBundle, scores: Iterable[str], directory: Path | None = None
                 ) -> Path:
    """Write the bundle atomically, so a failed write leaves the previous one in place."""
    target = (directory or data_dir()) / BUNDLE_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(BUNDLE_NAME + ".tmp")
    header: dict[str, Any] = bundle.model_dump(mode="json")
    try:
        with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            text = io.TextIOWrapper(gz, encoding="utf-8", newline="\n")
            text.write(json.dumps(header, sort_keys=True, ensure_ascii=False) + "\n")
            for line in scores:
                text.write(line + "\n")
            text.flush()
            text.detach()
        tmp.replace(target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target
