"""Known-exploited (CISA KEV) and likely-exploited (EPSS) dependency advisories, from an
offline bundle written by `unvarnish vulndata refresh` (UNVAR-90)."""

from __future__ import annotations

import copy
import csv
import gzip
import io
import json
import socket
import urllib.request
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.analysis import vulndata
from unvarnish.analysis.delta import match_findings
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.engagement import ToolPaths
from unvarnish.export import findings_data
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.render.findings import _delta_row
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.dependencies import DependenciesScanner
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings

runner = CliRunner()
FETCHED = date(2026, 11, 22)
KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.20",
    "dateReleased": "2026-11-20T17:48:39.1516Z", "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24"},
        {"cveID": "CVE-2023-0001", "vendorProject": "Other", "product": "Thing",
         "dateAdded": "2023-05-01", "dueDate": "2023-05-22"},
    ]}
EPSS = ("#model_version:v2026.06.15,score_date:2026-11-22T12:03:04Z\n"
        "cve,epss,percentile\n"
        "CVE-1999-0001,0.04753,0.92097\n"
        "CVE-2021-44228,0.94358,0.99971\n"
        "CVE-2022-1111,0.12,0.9\n"
        "CVE-2022-2222,0.00043,0.1\n"
        "CVE-2022-3333,0.5,0.95\n")
# What osv-scanner's advisories look like once parse_osv has read them: aliases in "ids".
ADVISORIES = [
    {"id": "GHSA-jfh8-c2jp-5v3q", "ids": ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"],
     "package": "log4j-core", "version": "2.14.1", "ecosystem": "Maven",
     "manifest": "pom.xml", "summary": "Remote code injection in Log4j", "severity": "high"},
    {"id": "GHSA-aaaa-aaaa-aaaa", "ids": ["GHSA-aaaa-aaaa-aaaa", "CVE-2022-2222"],
     "package": "requests", "version": "2.0.0", "ecosystem": "PyPI",
     "manifest": "requirements.txt", "summary": "Unlikely thing", "severity": "medium"},
    {"id": "GHSA-bbbb-bbbb-bbbb", "ids": ["GHSA-bbbb-bbbb-bbbb", "cve-2022-1111",
                                          "CVE-2022-3333"],
     "package": "requests", "version": "2.0.0", "ecosystem": "PyPI",
     "manifest": "requirements.txt", "summary": "Header leak", "severity": "medium"},
    {"id": "PYSEC-2020-1", "ids": ["PYSEC-2020-1"], "package": "requests", "version": "2.0.0",
     "ecosystem": "PyPI", "manifest": "requirements.txt", "summary": "No CVE",
     "severity": "low"},
]


def _fetch(kev: dict | None = None, epss: str = EPSS, seen: list[str] | None = None):
    def fetch(url: str) -> bytes:
        if seen is not None:
            seen.append(url)
        if url == vulndata.KEV_URL:
            return json.dumps(kev or KEV).encode("utf-8")
        if url == vulndata.EPSS_URL:
            return gzip.compress(epss.encode("utf-8"))
        raise AssertionError(f"unexpected URL {url}")
    return fetch


def _bundle(directory: Path, *, kev: dict | None = None, today: date = FETCHED) -> Path:
    bundle, scores = vulndata.build_bundle(fetch=_fetch(kev), today=today)
    return vulndata.write_bundle(bundle, scores, directory)


def _advisories() -> list[dict]:
    return copy.deepcopy(ADVISORIES)


def _ctx(deps: Dependencies, **options) -> ScanContext:
    return ScanContext(tool="t", source_root=Path("."),
                       census=Census(tool="t", files=[], totals=CensusTotals()),
                       metrics=Metrics(tool="t", files=[]),
                       git=GitStats(tool="t", available=False), dependencies=deps,
                       options=options)


def _deps(path: Path | None) -> Dependencies:
    advisories, dated, note = vulndata.annotate(_advisories(), path)
    return Dependencies(tool="t", dependencies=[], advisories_checked=True,
                        advisories=advisories, exploit_data_date=dated, exploit_data_note=note)


def _scan(deps: Dependencies, today: date = FETCHED, **options):
    scanner = DependenciesScanner(today=today)
    found = {f.title: f for f in scanner.run(_ctx(deps, **options))}
    # the licence note (UNVAR-93) is tested in test_sbom_licences.py; these count exploit notes
    scanner.notes = [n for n in scanner.notes if not n.startswith("dependencies: licences:")]
    return found, scanner


# --- acceptance 1: `vulndata refresh` writes a dated bundle, or nothing ---------------------

def test_build_bundle_reads_both_feeds():
    seen: list[str] = []
    bundle, scores = vulndata.build_bundle(fetch=_fetch(seen=seen), today=FETCHED)
    assert seen == [vulndata.KEV_URL, vulndata.EPSS_URL]
    assert vulndata.KEV_URL.startswith("https://www.cisa.gov/")
    assert vulndata.EPSS_URL.startswith("https://epss.empiricalsecurity.com/")
    assert bundle.fetched == FETCHED and bundle.format == 1
    assert bundle.kev == {"CVE-2021-44228": date(2021, 12, 10),
                          "CVE-2023-0001": date(2023, 5, 1)}
    assert bundle.kev_catalog_version == "2026.11.20"
    assert bundle.epss_model_version == "v2026.06.15"
    assert bundle.epss_score_date == "2026-11-22"
    assert bundle.epss_scores == len(scores) == 5
    assert "CISA" in bundle.attribution and "FIRST" in bundle.attribution


def test_written_bundle_reads_back_and_looks_up_only_what_is_asked(tmp_path: Path):
    path = _bundle(tmp_path / "data")
    assert path == tmp_path / "data" / vulndata.BUNDLE_NAME
    assert vulndata.bundle_date(path) == FETCHED.isoformat()
    scores, why = vulndata.epss_scores(path, {"CVE-2021-44228", "CVE-2099-0001"})
    assert why is None
    assert scores == {"CVE-2021-44228": (0.94358, 0.99971)}
    assert not list(path.parent.glob("*.tmp"))
    with gzip.open(path, "rt", encoding="utf-8") as fh:  # compact: one short line per score
        assert json.loads(fh.readline())["fetched"] == FETCHED.isoformat()
        assert fh.readline() == "CVE-1999-0001,0.04753,0.92097\n"


@pytest.mark.parametrize("kev,epss,named", [
    ({"vulnerabilities": "nope"}, EPSS, "KEV"),
    ({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, EPSS, "KEV"),  # no dateAdded
    ({"vulnerabilities": []}, EPSS, "KEV"),
    (None, "cve,epss,percentile\n", "EPSS"),
    (None, "#model_version:v1,score_date:2026-11-22T00:00:00Z\nnot,the,header\n", "EPSS"),
    (None, "#model_version:v1,score_date:2026-11-22T00:00:00Z\ncve,epss,percentile\n"
           "CVE-2021-44228,lots,0.9\n", "EPSS"),
])
def test_malformed_feed_fails_naming_it(kev, epss, named):
    with pytest.raises(vulndata.VulnDataFetchError, match=named):
        vulndata.build_bundle(fetch=_fetch(kev, epss), today=FETCHED, attempts=1)


def test_build_bundle_retries_with_backoff():
    calls: list[str] = []
    sleeps: list[float] = []
    good = _fetch()

    def flaky(url: str) -> bytes:
        calls.append(url)
        if url == vulndata.EPSS_URL and calls.count(url) == 1:
            raise TimeoutError("timed out")
        return good(url)

    bundle, _ = vulndata.build_bundle(fetch=flaky, today=FETCHED, attempts=2,
                                      sleep=sleeps.append)
    assert bundle.epss_scores == 5 and sleeps == [2.0]


def test_cli_refresh_writes_the_bundle(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vulndata, "fetch_bytes", _fetch())
    out = tmp_path / "data"
    result = runner.invoke(app, ["vulndata", "refresh", "--dir", str(out)],
                           env={"COLUMNS": "400"})
    assert result.exit_code == 0, result.output
    bundle, why = vulndata.load_bundle(out / vulndata.BUNDLE_NAME)
    assert why is None and bundle is not None
    assert f"data dated {bundle.fetched.isoformat()}" in result.output
    assert "2 known exploited CVEs" in result.output and "5 EPSS scores" in result.output
    assert [p.name for p in out.iterdir()] == [vulndata.BUNDLE_NAME]


def test_cli_refresh_default_dir_is_beside_the_end_of_life_bundle(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vulndata, "fetch_bytes", _fetch())
    monkeypatch.delenv(vulndata.DIR_ENV, raising=False)
    result = runner.invoke(app, ["vulndata", "refresh"],
                           env={"COLUMNS": "400", "UNVARNISH_EOL_DIR": str(tmp_path / "eol")})
    assert result.exit_code == 0, result.output
    assert (tmp_path / "eol" / vulndata.BUNDLE_NAME).is_file()
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "own"))
    assert vulndata.bundle_path() == tmp_path / "own" / vulndata.BUNDLE_NAME


def test_cli_refresh_failure_writes_nothing_and_keeps_the_old_bundle(monkeypatch,
                                                                     tmp_path: Path):
    out = tmp_path / "data"
    _bundle(out, today=date(2026, 1, 1))
    before = (out / vulndata.BUNDLE_NAME).read_bytes()
    good = _fetch()

    def epss_down(url: str) -> bytes:
        if url == vulndata.EPSS_URL:
            raise OSError("network unreachable")
        return good(url)

    monkeypatch.setattr(vulndata, "fetch_bytes", epss_down)
    result = runner.invoke(app, ["vulndata", "refresh", "--dir", str(out), "--attempts", "1"],
                           env={"COLUMNS": "400"})
    assert result.exit_code == 1
    assert "EPSS" in result.output and "network unreachable" in result.output
    assert (out / vulndata.BUNDLE_NAME).read_bytes() == before
    assert [p.name for p in out.iterdir()] == [vulndata.BUNDLE_NAME]

    fresh = tmp_path / "fresh"
    result = runner.invoke(app, ["vulndata", "refresh", "--dir", str(fresh), "--attempts", "1"],
                           env={"COLUMNS": "400"})
    assert result.exit_code == 1
    assert not fresh.exists() or list(fresh.iterdir()) == []


def test_cli_refresh_unwritable_dir_fails_before_downloading(monkeypatch, tmp_path: Path):
    def no_download(url: str) -> bytes:
        raise AssertionError("must not download into an unwritable folder")

    monkeypatch.setattr(vulndata, "fetch_bytes", no_download)
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder", encoding="utf-8")
    result = runner.invoke(app, ["vulndata", "refresh", "--dir", str(blocker / "d")],
                           env={"COLUMNS": "400"})
    assert result.exit_code == 1 and "--dir" in result.output
    assert "Traceback" not in result.output


def test_cli_refresh_takes_other_urls(monkeypatch, tmp_path: Path):
    seen: list[str] = []
    good = _fetch()

    def mirror(url: str) -> bytes:
        seen.append(url)
        return good(vulndata.KEV_URL if "kev" in url else vulndata.EPSS_URL)

    monkeypatch.setattr(vulndata, "fetch_bytes", mirror)
    result = runner.invoke(app, ["vulndata", "refresh", "--dir", str(tmp_path),
                                 "--kev-url", "https://mirror.example/kev.json",
                                 "--epss-url", "https://mirror.example/epss.csv.gz"],
                           env={"COLUMNS": "400"})
    assert result.exit_code == 0, result.output
    assert seen == ["https://mirror.example/kev.json", "https://mirror.example/epss.csv.gz"]


def test_fetch_bytes_uses_a_generic_agent(monkeypatch):
    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout):
        seen["url"], seen["agent"], seen["timeout"] = (req.full_url,
                                                       req.get_header("User-agent"), timeout)
        return Resp(b"data")

    monkeypatch.setattr(vulndata.urllib.request, "urlopen", urlopen)
    assert vulndata.fetch_bytes(vulndata.KEV_URL) == b"data"
    assert seen["url"] == vulndata.KEV_URL
    assert seen["agent"].startswith("unvarnish/") and seen["timeout"] > 0


# --- acceptance 2 and 3: KEV is critical and says so; EPSS per advisory --------------------

def test_annotate_marks_kev_and_epss_per_advisory(tmp_path: Path):
    path = _bundle(tmp_path)
    out, dated, note = vulndata.annotate(_advisories(), path)
    assert dated == FETCHED.isoformat() and note is None
    log4j, low, leak, nocve = out
    assert log4j["kev"] is True and log4j["kev_date_added"] == "2021-12-10"
    assert log4j["severity"] == "critical"
    assert (log4j["epss"], log4j["epss_percentile"]) == (0.94358, 0.99971)
    assert low["kev"] is False and "kev_date_added" not in low and low["severity"] == "medium"
    assert (low["epss"], low["epss_percentile"]) == (0.00043, 0.1)
    # several CVEs: the highest score, lower-case aliases included
    assert (leak["epss"], leak["epss_percentile"]) == (0.5, 0.95)
    assert nocve["kev"] is False and nocve["epss"] is None and nocve["epss_percentile"] is None


def test_kev_advisory_is_critical_and_shows_known_exploited(tmp_path: Path):
    findings, scanner = _scan(_deps(_bundle(tmp_path)))
    log4j = findings["Known vulnerabilities in log4j-core 2.14.1"]
    assert log4j.severity == Severity.critical
    assert "Known exploited (CISA KEV, added 2021-12-10)" in log4j.summary
    assert "EPSS 94.36%, percentile 99.97" in log4j.summary
    assert "known-exploited" in log4j.tags
    assert "CISA" in log4j.impact
    assert log4j.exploits is not None and log4j.exploits[0].kev
    assert log4j.exploits[0].kev_date_added == date(2021, 12, 10)
    assert scanner.notes == []


def test_epss_orders_advisories_but_never_changes_severity(tmp_path: Path):
    findings, _ = _scan(_deps(_bundle(tmp_path)))
    req = findings["Known vulnerabilities in requests 2.0.0"]
    assert req.severity == Severity.medium  # EPSS 0.5 is shown, not a severity
    s = req.summary
    assert s.index("GHSA-bbbb") < s.index("GHSA-aaaa") < s.index("PYSEC-2020-1")
    assert "Header leak [EPSS 50%, percentile 95]" in s
    assert "Unlikely thing [EPSS 0.04%, percentile 10]" in s
    assert "No CVE [no EPSS score]" in s
    assert [e.advisory for e in req.exploits] == ["GHSA-bbbb-bbbb-bbbb", "GHSA-aaaa-aaaa-aaaa",
                                                 "PYSEC-2020-1"]
    assert req.exploits[0].epss == 0.5 and req.exploits[0].epss_percentile == 0.95
    assert req.exploits[0].cves == ["CVE-2022-1111", "CVE-2022-3333"]


# --- acceptance 4: without a bundle, one note and nothing else -----------------------------

def test_without_a_bundle_findings_are_unchanged_and_one_note(tmp_path: Path):
    plain = Dependencies(tool="t", dependencies=[], advisories_checked=True,
                         advisories=_advisories())
    missing = _deps(tmp_path / "nowhere" / vulndata.BUNDLE_NAME)
    assert missing.advisories == plain.advisories and missing.exploit_data_date is None
    before, _ = _scan(plain)
    after, scanner = _scan(missing)
    assert [f.model_dump() for f in after.values()] == [f.model_dump() for f in before.values()]
    assert all(f.exploits is None for f in after.values())
    assert "exploits" not in next(iter(after.values())).model_dump(mode="json")
    assert len(scanner.notes) == 1
    assert scanner.notes[0].startswith("dependencies: exploit data: not checked (no exploit "
                                       "data bundle)")
    assert "unvarnish vulndata refresh" in scanner.notes[0]
    assert str(tmp_path) not in scanner.notes[0]


@pytest.mark.parametrize("body", [b"not gzip", gzip.compress(b"not json\n"),
                                  gzip.compress(b'{"format": 99, "fetched": "2026-01-01"}\n'),
                                  gzip.compress(b'{"format": 1}\n')])
def test_unreadable_bundle_is_one_note(tmp_path: Path, body: bytes):
    bad = tmp_path / vulndata.BUNDLE_NAME
    bad.write_bytes(body)
    deps = _deps(bad)
    assert deps.exploit_data_date is None and "unreadable" in deps.exploit_data_note
    assert vulndata.bundle_date(bad) is None
    _, scanner = _scan(deps)
    assert len(scanner.notes) == 1 and "unreadable" in scanner.notes[0]


def test_truncated_scores_are_unreadable_not_partial(tmp_path: Path):
    path = _bundle(tmp_path)
    data = path.read_bytes()
    path.write_bytes(data[:len(data) - 20])
    advisories, dated, note = vulndata.annotate(_advisories(), path)
    assert dated is None and "unreadable" in note
    assert advisories == ADVISORIES


# --- acceptance 5: an old bundle is flagged --------------------------------------------------

def test_old_bundle_adds_a_note_and_still_marks(tmp_path: Path):
    deps = _deps(_bundle(tmp_path))
    findings, scanner = _scan(deps, today=FETCHED + timedelta(days=45))
    assert findings["Known vulnerabilities in log4j-core 2.14.1"].severity == Severity.critical
    assert len(scanner.notes) == 1
    assert scanner.notes[0].startswith(
        f"dependencies: exploit data dated {FETCHED.isoformat()} is 45 days old, older than "
        "the 30-day limit (max_data_age_days)")
    assert vulndata_age(scanner.notes) == "45 days old, older than the 30-day limit"


def vulndata_age(notes: list[str]) -> str | None:
    from unvarnish.scanners.dependencies import exploit_data_age_warning

    return exploit_data_age_warning(notes)


def test_configured_data_age_is_honoured(tmp_path: Path):
    deps = _deps(_bundle(tmp_path))
    _, fresh = _scan(deps, today=FETCHED + timedelta(days=45), max_data_age_days=60)
    assert fresh.notes == []
    _, bad = _scan(deps, today=FETCHED + timedelta(days=45), max_data_age_days="soon")
    assert len(bad.notes) == 1 and "30-day limit" in bad.notes[0]


# --- acceptance 7: a severity change from a refreshed bundle is "changed" -------------------

def test_refreshed_bundle_rerates_without_a_new_identity(tmp_path: Path):
    no_kev = {**KEV, "vulnerabilities": KEV["vulnerabilities"][1:]}
    before, _ = _scan(_deps(_bundle(tmp_path / "old", kev=no_kev)))
    after, _ = _scan(_deps(_bundle(tmp_path / "new")))
    title = "Known vulnerabilities in log4j-core 2.14.1"
    assert before[title].severity == Severity.high and after[title].severity == Severity.critical
    assert before[title].id == after[title].id
    entries = match_findings(list(before.values()), list(after.values()), drift=50)
    statuses = {e.finding.title: e.status.value for e in entries}
    assert statuses == {title: "changed", "Known vulnerabilities in requests 2.0.0":
                        "persistent"}
    changed = next(e for e in entries if e.status.value == "changed")
    assert _delta_row(changed)["change"] == "re-rated from high"


# --- the inventory, the document, CSV and SARIF ---------------------------------------------

def _engagement_run(engagement, monkeypatch, tmp_path: Path, today: date = FETCHED):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.ingest import ingest_tool
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.scanners import builtin_scanners

    monkeypatch.setattr("unvarnish.phases.inventory.lookup_dependencies",
                        lambda root, options: (True, _advisories(), None, None))
    src = tmp_path / "client-src"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    ingest_tool(engagement, "svc", str(src), "files")
    ctx = build_context(engagement, "svc")
    scanners = [DependenciesScanner(today=today) if s.name == "dependencies" else s
                for s in builtin_scanners()]
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(scanners=scanners),
                           RenderPhase()]).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    return ctx


def test_exploit_data_reaches_every_output(engagement, monkeypatch, tmp_path: Path):
    _bundle(tmp_path / "vulndata")
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "vulndata"))
    ctx = _engagement_run(engagement, monkeypatch, tmp_path)

    raw = json.loads(ctx.paths.dependencies.read_text(encoding="utf-8"))["data"]
    assert raw["exploit_data_date"] == FETCHED.isoformat()
    by_id = {a["id"]: a for a in raw["advisories"]}
    assert by_id["GHSA-jfh8-c2jp-5v3q"]["kev"] is True
    assert by_id["GHSA-jfh8-c2jp-5v3q"]["kev_date_added"] == "2021-12-10"
    assert by_id["GHSA-bbbb-bbbb-bbbb"]["epss"] == 0.5
    assert by_id["GHSA-bbbb-bbbb-bbbb"]["epss_percentile"] == 0.95

    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert ("| Known exploited | 1 of 4 advisories in the CISA KEV catalog; exploit data "
            f"dated {FETCHED.isoformat()} |") in doc
    assert "| Dependency vulnerabilities | 4 (1 critical, 2 medium, 1 low) |" in doc
    assert "Known exploited (CISA KEV, added 2021-12-10)" in doc
    assert "EPSS 50%, percentile 95" in doc
    assert "exploit data: not checked" not in doc

    paths = ToolPaths(ctx.paths.root)
    findings = findings_data.load_findings(paths)
    rows = list(csv.DictReader(io.StringIO(findings_data.csv_text(findings))))
    req = next(r for r in rows if "requests" in r["Summary"])
    assert "EPSS 50%, percentile 95" in req["Description"]
    assert "EPSS 0.04%, percentile 10" in req["Description"]
    sarif = findings_data.sarif_documents("svc", findings)[0]
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    props = {rules[r["ruleIndex"]]["shortDescription"]["text"].split(" ")[3]: r["properties"]
             for r in sarif["runs"][0]["results"] if "exploits" in r["properties"]}
    log4j = props["log4j-core"]["exploits"][0]
    assert log4j == {"advisory": "GHSA-jfh8-c2jp-5v3q", "cves": ["CVE-2021-44228"],
                     "kev": True, "kev_date_added": "2021-12-10", "epss": 0.94358,
                     "epss_percentile": 0.99971}
    assert [e["epss"] for e in props["requests"]["exploits"]] == [0.5, 0.00043, None]


def test_findings_sort_kev_first_then_by_epss():
    from unvarnish.render.findings import merged_findings
    from unvarnish.schemas.finding import AdvisoryExploit, Evidence, Finding

    def f(title: str, path: str, exploits=None, severity="medium") -> Finding:
        return Finding(tool="t", category="dependency", severity=severity, title=title,
                       summary="s", impact="i", remediation="r", source="scanner",
                       scanner="dependencies", evidence=[Evidence(path=path)],
                       exploits=exploits)

    def ex(epss=None, kev=None) -> list[AdvisoryExploit]:
        return [AdvisoryExploit(advisory="X", cves=["CVE-1"], kev=kev is not None,
                                kev_date_added=kev, epss=epss, epss_percentile=epss)]

    found = merged_findings([
        f("plain", "a.txt"), f("low epss", "b.txt", ex(0.01)), f("high epss", "c.txt", ex(0.9)),
        f("kev", "d.txt", ex(0.001, date(2024, 1, 1)), severity="critical"),
        f("kev2", "e.txt", ex(0.5, date(2024, 1, 1)), severity="critical"),
        f("crit", "a.txt", severity="critical")], [])
    assert [x.title for x in found] == ["kev2", "kev", "crit", "high epss", "low epss",
                                        "plain"]


def test_report_without_a_bundle_has_one_more_line(engagement, monkeypatch, tmp_path: Path):
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "empty"))
    ctx = _engagement_run(engagement, monkeypatch, tmp_path)
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    notes = [n for n in scan.notes if "exploit data" in n]
    assert len(notes) == 1 and notes[0] in doc.split("## Not analysed", 1)[1]
    rest = doc.replace(notes[0], "")
    assert "Known exploited" not in rest and "EPSS" not in rest and "KEV" not in rest


def test_old_bundle_in_the_report(engagement, monkeypatch, tmp_path: Path):
    _bundle(tmp_path / "vulndata")
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "vulndata"))
    ctx = _engagement_run(engagement, monkeypatch, tmp_path,
                          today=FETCHED + timedelta(days=100))
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert (f"exploit data dated {FETCHED.isoformat()} (100 days old, older than the 30-day "
            "limit: refresh it) |") in doc
    assert f"dependencies: exploit data dated {FETCHED.isoformat()} is 100 days old" in (
        doc.split("## Not analysed", 1)[1])


def test_inventory_hash_includes_the_bundle_date(engagement, monkeypatch, tmp_path: Path):
    from unvarnish.phases.ingest import ingest_tool

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("x\n", encoding="utf-8")
    ingest_tool(engagement, "svc", str(src), "files")
    ctx = build_context(engagement, "svc")
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "kit"))
    without = InventoryPhase().inputs_hash(ctx)
    _bundle(tmp_path / "kit")
    dated = InventoryPhase().inputs_hash(ctx)
    _bundle(tmp_path / "kit", today=FETCHED + timedelta(days=1))
    refreshed = InventoryPhase().inputs_hash(ctx)
    assert len({without, dated, refreshed}) == 3


# --- acceptance 6: no network during `run` -------------------------------------------------

def test_run_makes_no_network_access(monkeypatch, tmp_path: Path):
    _bundle(tmp_path / "vulndata", today=date.today())
    monkeypatch.setenv(vulndata.DIR_ENV, str(tmp_path / "vulndata"))
    monkeypatch.setattr("unvarnish.phases.inventory.lookup_dependencies",
                        lambda root, options: (True, _advisories(), None, None))
    attempts: list[str] = []

    def refuse(*args, **kwargs):
        attempts.append(repr(args)[:200])
        raise AssertionError("network access during run")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(vulndata, "fetch_bytes", refuse)

    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    eng = tmp_path / "eng"
    assert runner.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = runner.invoke(app, ["add", "tool", "--files", str(src), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    assert attempts == []
    doc = (eng / "tools" / "tool" / "docs" / "findings.md").read_text(encoding="utf-8")
    assert "Known exploited (CISA KEV, added 2021-12-10)" in doc


def test_kev_join_reads_aliases_of_a_report_without_groups(tmp_path: Path):
    """osv-scanner output without `groups` still carries each vulnerability's aliases; a
    GHSA advisory whose only CVE is an alias must still match KEV and EPSS."""
    from unvarnish.analysis.advisories import parse_osv

    report = {"results": [{"source": {"path": str(tmp_path / "pom.xml")}, "packages": [{
        "package": {"name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven"},
        "vulnerabilities": [{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"],
                             "summary": "Remote code injection in Log4j"}]}]}]}
    advisories = parse_osv(report, tmp_path)
    assert advisories[0]["ids"] == ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"]
    out, _, _ = vulndata.annotate(advisories, _bundle(tmp_path / "data"))
    assert out[0]["kev"] is True and out[0]["severity"] == "critical"
    assert out[0]["epss"] == 0.94358
