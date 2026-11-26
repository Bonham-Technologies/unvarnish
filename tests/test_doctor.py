"""`unvarnish doctor`: one offline check of the data sets and tools a run needs, with the
exact command that refreshes or installs each (UNVAR-101)."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
import tree_sitter_language_pack as pack
import yaml
from typer.testing import CliRunner

from unvarnish.analysis import advisories, eol, treesitter, vulndata
from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.schemas.vulndata import VulnBundle

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
TODAY = datetime.now(UTC).date()
# The rows, in order: four data sets, then six tools.
DATA = ("tree-sitter grammars", "end-of-life data", "exploit data", "OSV databases")
TOOLS = ("pandoc", "Graphviz (dot)", "weasyprint", "git", "gitleaks", "osv-scanner")
FAKE_TOOLS = {
    "pandoc": "echo 'pandoc 3.6.1'",
    "dot": "echo 'dot - graphviz version 12.2.1 (20241206.2353)' >&2",
    "weasyprint": "echo 'WeasyPrint version 70.0'",
    "git": "echo 'git version 2.47.3'",
    "gitleaks": "echo '8.30.1'",
    "osv-scanner": "echo 'osv-scanner version: 2.7.1'",
}


def _eol_bundle(directory: Path, fetched: date) -> None:
    raw = json.loads((ROOT / "tests/data/eol/endoflife.json").read_text(encoding="utf-8"))
    raw["fetched"] = fetched.isoformat()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / eol.BUNDLE_NAME).write_text(json.dumps(raw), encoding="utf-8")


def _exploit_bundle(directory: Path, fetched: date) -> None:
    bundle = VulnBundle(fetched=fetched, kev_source=vulndata.KEV_URL,
                        epss_source=vulndata.EPSS_URL, epss_scores=1,
                        kev={"CVE-2021-44228": date(2021, 12, 10)})
    vulndata.write_bundle(bundle, ["CVE-2021-44228,0.94358,0.99971"], directory)


def _osv_databases(root: Path, fetched: date, ecosystems=("PyPI", "npm")) -> None:
    for eco in ecosystems:
        db = root / "osv-scalibr" / eco
        db.mkdir(parents=True, exist_ok=True)
        (db / "all.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    (root / "DATE").write_text(fetched.isoformat() + "\n", encoding="utf-8")


class FakeEnv:
    """Every data set in a temporary folder and every tool a stand-in script on PATH."""

    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp, self.mp = tmp, monkeypatch
        self.eol_dir = tmp / "eol"
        self.vuln_dir = tmp / "vulndata"
        self.osv_dir = tmp / "osv"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for var in ("UNVARNISH_DISABLE_OSV", "UNVARNISH_DISABLE_GITLEAKS",
                    "UNVARNISH_IN_DOCKER"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv(eol.DIR_ENV, str(self.eol_dir))
        monkeypatch.setenv(vulndata.DIR_ENV, str(self.vuln_dir))
        monkeypatch.setenv(advisories.LOCAL_DB_ENV, str(self.osv_dir))
        monkeypatch.setenv("PATH", str(self.bin))
        self.grammars("present")
        _eol_bundle(self.eol_dir, TODAY - timedelta(days=3))
        _exploit_bundle(self.vuln_dir, TODAY - timedelta(days=3))
        _osv_databases(self.osv_dir, TODAY - timedelta(days=3))
        for name, body in FAKE_TOOLS.items():
            self.tool(name, body)

    def tool(self, name: str, body: str | None) -> None:
        path = self.bin / name
        if body is None:
            path.unlink(missing_ok=True)
            return
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def grammars(self, state: str) -> None:
        names = treesitter.grammar_languages()
        have = {"present": names, "partial": names[:3], "absent": []}[state]
        self.mp.setattr(pack, "downloaded_languages", lambda: list(have))

    def data(self, name: str, state: str) -> None:
        """Make one data set present (3 days old), stale (400 days old) or absent."""
        if name == "tree-sitter grammars":
            self.grammars(state if state != "stale" else "present")
            return
        fetched = TODAY - timedelta(days=400 if state == "stale" else 3)
        target = {"end-of-life data": self.eol_dir, "exploit data": self.vuln_dir,
                  "OSV databases": self.osv_dir}[name]
        if state == "absent":
            for f in target.rglob("*"):
                if f.is_file():
                    f.unlink()
            return
        {"end-of-life data": _eol_bundle, "exploit data": _exploit_bundle,
         "OSV databases": _osv_databases}[name](target, fetched)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeEnv:
    work = tmp_path / "work"  # not an engagement: doctor checks a new engagement's defaults
    work.mkdir()
    monkeypatch.chdir(work)
    return FakeEnv(tmp_path, monkeypatch)


def _doctor(*args: str) -> tuple[int, dict]:
    out = runner.invoke(app, ["doctor", "--json", *args])
    assert out.exit_code in (0, 1), out.output
    return out.exit_code, json.loads(out.stdout)


def _rows(report: dict) -> dict[str, dict]:
    return {c["name"]: c for c in report["checks"]}


def _engagement(tmp_path: Path, scanners: dict | None = None,
                backends: dict | None = None, models: dict | None = None) -> Path:
    eng = Engagement.create(tmp_path / "eng")
    raw = yaml.safe_load(eng.config_file.read_text(encoding="utf-8")) or {}
    if scanners:
        raw["scanners"] = scanners
    if backends:
        raw["backends"] = backends
    if models:
        raw["models"] = models
    eng.config_file.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return eng.root


# --- acceptance 1: present, absent and stale rows and the exit code ------------------------

def test_everything_present_is_ready(env: FakeEnv):
    code, report = _doctor()
    assert code == 0
    assert report["ready"] is True
    assert [c["name"] for c in report["checks"]] == [*DATA, *TOOLS]
    rows = _rows(report)
    for name in (*DATA, *TOOLS):
        assert rows[name]["status"] == "present", rows[name]
        assert rows[name]["needed"] is True, name
        assert rows[name]["refresh"], name
    dated = (TODAY - timedelta(days=3)).isoformat()
    for name in ("end-of-life data", "exploit data", "OSV databases"):
        assert rows[name]["date"] == dated and rows[name]["age_days"] == 3, rows[name]
    assert rows["end-of-life data"]["max_age_days"] == 90
    assert rows["exploit data"]["max_age_days"] == 30
    assert rows["OSV databases"]["max_age_days"] == 30
    assert "PyPI" in rows["OSV databases"]["detail"] and "npm" in rows["OSV databases"]["detail"]
    assert rows["pandoc"]["version"] == "3.6.1"
    assert rows["Graphviz (dot)"]["version"] == "12.2.1"
    assert rows["weasyprint"]["version"] == "70.0"
    assert rows["git"]["version"] == "2.47.3"
    assert rows["gitleaks"]["version"] == "8.30.1"
    assert rows["osv-scanner"]["version"] == "2.7.1"
    assert report["backends"] is None  # not probed


REFRESH = {
    "tree-sitter grammars": "unvarnish grammars fetch",
    "end-of-life data": "unvarnish eol refresh",
    "exploit data": "unvarnish vulndata refresh",
    "OSV databases": "osv-scanner scan source --offline-vulnerabilities "
                     "--download-offline-databases",
}


@pytest.mark.parametrize("name", DATA)
@pytest.mark.parametrize("state", ["absent", "stale"])
def test_each_data_set_absent_or_stale(env: FakeEnv, name: str, state: str):
    if name == "tree-sitter grammars" and state == "stale":
        pytest.skip("grammars carry no date: they belong to the installed language pack")
    env.data(name, state)
    code, report = _doctor()
    row = _rows(report)[name]
    assert row["status"] == state, row
    assert REFRESH[name] in row["refresh"]
    # Missing data a run needs fails the check; old data is still used, with a note.
    assert code == (1 if state == "absent" else 0)
    assert report["ready"] is (state == "stale")
    others = [c for c in report["checks"] if c["name"] != name]
    assert all(c["status"] == "present" for c in others), others
    if state == "stale":
        assert row["age_days"] == 400 and row["age_days"] > row["max_age_days"]


def test_some_grammars_missing_is_partial_and_names_them(env: FakeEnv):
    env.grammars("partial")
    code, report = _doctor()
    row = _rows(report)["tree-sitter grammars"]
    assert code == 1 and row["status"] == "partial"
    missing = treesitter.grammar_languages()[3]
    assert missing in row["detail"]


@pytest.mark.parametrize("bundle", [eol.BUNDLE_NAME, vulndata.BUNDLE_NAME])
def test_an_unreadable_bundle_is_not_ready(env: FakeEnv, bundle: str):
    folder = env.eol_dir if bundle == eol.BUNDLE_NAME else env.vuln_dir
    (folder / bundle).write_bytes(b"not a bundle")
    code, report = _doctor()
    row = next(c for c in report["checks"] if c["status"] == "unreadable")
    assert code == 1 and "unreadable" in row["detail"]


@pytest.mark.parametrize("tool,binary", [("pandoc", "pandoc"), ("Graphviz (dot)", "dot"),
                                         ("weasyprint", "weasyprint"), ("git", "git"),
                                         ("gitleaks", "gitleaks"),
                                         ("osv-scanner", "osv-scanner")])
def test_each_tool_absent_fails_with_its_install_hint(env: FakeEnv, tool: str, binary: str):
    env.tool(binary, None)
    code, report = _doctor()
    row = _rows(report)[tool]
    assert code == 1 and row["status"] == "absent" and row["needed"] is True
    assert row["refresh"]


@pytest.mark.parametrize("binary,body", [("pandoc", "echo 'pandoc 2.17.1'"),
                                         ("git", "echo 'git version 2.30.9'")])
def test_a_tool_older_than_unvarnish_needs_is_too_old(env: FakeEnv, binary: str, body: str):
    env.tool(binary, body)
    code, report = _doctor()
    row = next(c for c in report["checks"] if c["status"] == "too old")
    assert code == 1 and row["version"] in body


def test_an_old_weasyprint_still_exports_untagged(env: FakeEnv):
    env.tool("weasyprint", "echo 'WeasyPrint version 62.3'")
    code, report = _doctor()
    row = _rows(report)["weasyprint"]
    assert code == 0 and row["status"] == "present" and "untagged" in row["note"]
    out = runner.invoke(app, ["doctor"], env={"COLUMNS": "200"})
    assert "weasyprint: 62.3 is older than 66.0, so PDFs are exported untagged" in out.output


def test_the_engagement_decides_what_is_needed(env: FakeEnv, tmp_path: Path):
    # Online advisories need no offline database, and gitleaks switched off is not needed.
    env.data("OSV databases", "absent")
    env.tool("gitleaks", None)
    eng = _engagement(tmp_path, scanners={"dependencies": {"offline": False},
                                          "secrets": {"use_gitleaks": False}})
    code, report = _doctor("-e", str(eng))
    rows = _rows(report)
    assert code == 0, rows
    assert rows["OSV databases"]["status"] == "absent" and not rows["OSV databases"]["needed"]
    assert rows["gitleaks"]["status"] == "absent" and not rows["gitleaks"]["needed"]
    assert report["engagement"] == str(eng)


def test_the_engagement_age_limits_are_used(env: FakeEnv, tmp_path: Path):
    env.data("end-of-life data", "stale")
    env.data("exploit data", "stale")
    eng = _engagement(tmp_path, scanners={"end_of_life": {"max_data_age_days": 500},
                                          "dependencies": {"max_data_age_days": 450}})
    _, report = _doctor("-e", str(eng))
    rows = _rows(report)
    assert rows["end-of-life data"]["status"] == "present"
    assert rows["end-of-life data"]["max_age_days"] == 500
    assert rows["exploit data"]["status"] == "present"
    assert rows["exploit data"]["max_age_days"] == 450


def test_disabled_scanners_are_not_needed(env: FakeEnv, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("UNVARNISH_DISABLE_OSV", "1")
    monkeypatch.setenv("UNVARNISH_DISABLE_GITLEAKS", "1")
    for name in ("exploit data", "OSV databases"):
        env.data(name, "absent")
    env.tool("osv-scanner", None)
    env.tool("gitleaks", None)
    code, report = _doctor()
    rows = _rows(report)
    assert code == 0
    for name in ("exploit data", "OSV databases", "osv-scanner", "gitleaks"):
        assert not rows[name]["needed"], name


def test_without_an_engagement_it_checks_the_defaults(env: FakeEnv):
    out = runner.invoke(app, ["doctor"], env={"COLUMNS": "200"})
    assert out.exit_code == 0, out.output
    assert "no engagement" in out.output.lower()
    for name in (*DATA, *TOOLS):
        assert name in out.output, name


def test_the_table_names_what_is_missing_and_how_to_get_it(env: FakeEnv):
    env.data("exploit data", "absent")
    out = runner.invoke(app, ["doctor"], env={"COLUMNS": "250"})
    assert out.exit_code == 1
    assert "absent" in out.output and "unvarnish vulndata refresh" in out.output
    narrow = runner.invoke(app, ["doctor"], env={"COLUMNS": "80"})
    assert "…" not in narrow.output  # commands fold, never cut
    assert "not ready" in out.output.lower() and "exploit data" in out.output


def test_an_explicit_folder_that_is_not_an_engagement_is_an_error(env: FakeEnv,
                                                                    tmp_path: Path):
    out = runner.invoke(app, ["doctor", "-e", str(tmp_path / "nowhere")])
    assert out.exit_code == 2


def test_in_the_image_the_refresh_is_a_rebuild_or_a_mount(env: FakeEnv,
                                                          monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("UNVARNISH_IN_DOCKER", "1")
    _, report = _doctor()
    rows = _rows(report)
    assert "scripts/site-kit.sh" in rows["OSV databases"]["refresh"]
    assert "scripts/site-kit.sh" in rows["tree-sitter grammars"]["refresh"]
    assert "--dir" in rows["end-of-life data"]["refresh"]
    assert "--dir" in rows["exploit data"]["refresh"]


def test_osv_date_falls_back_to_the_newest_database(env: FakeEnv):
    (env.osv_dir / "DATE").unlink()
    stamp = datetime(2026, 1, 2, 12, tzinfo=UTC).timestamp()
    for z in env.osv_dir.rglob("all.zip"):
        os.utime(z, (stamp, stamp))
    _, report = _doctor()
    assert _rows(report)["OSV databases"]["date"] == "2026-01-02"


def test_osv_database_folder_defaults_to_the_user_cache(monkeypatch: pytest.MonkeyPatch,
                                                         tmp_path: Path):
    monkeypatch.delenv(advisories.LOCAL_DB_ENV, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(advisories.sys, "platform", "linux")
    assert advisories.local_db_dir() == tmp_path
    _osv_databases(tmp_path, TODAY, ecosystems=("Go",))
    assert advisories.local_db_ecosystems() == ["Go"]


# --- acceptance 2: no network unless --probe-backend -----------------------------------------

def _refuse_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def refuse(*args, **kwargs):
        attempts.append(repr(args)[:200])
        raise OSError("network access refused by the test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    return attempts


BACKENDS = {"local": {"type": "openai_compatible", "base_url": "http://llm.example:8000/v1"}}
MODELS = {"default": {"backend": "local", "model": "qwen"}}


def test_doctor_makes_no_network_call(env: FakeEnv, tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch):
    eng = _engagement(tmp_path, backends=BACKENDS, models=MODELS)
    attempts = _refuse_network(monkeypatch)
    code, report = _doctor("-e", str(eng))
    assert code == 0 and attempts == []
    assert report["backends"] is None


def test_probe_backend_reports_an_unreachable_server(env: FakeEnv, tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch):
    eng = _engagement(tmp_path, backends=BACKENDS, models=MODELS)
    attempts = _refuse_network(monkeypatch)
    code, report = _doctor("-e", str(eng), "--probe-backend")
    assert attempts, "the probe should have tried the network"
    assert code == 1 and report["ready"] is False
    [probe] = report["backends"]
    assert probe["backend"] == "local" and probe["reachable"] is False
    assert probe["url"] == "http://llm.example:8000/v1/models"


def test_probe_backend_counts_any_http_answer_as_reachable(env: FakeEnv, tmp_path: Path,
                                                           monkeypatch: pytest.MonkeyPatch):
    backends = {**BACKENDS, "claude": {"type": "anthropic"}}
    models = {**MODELS, "phases": {"verify": {"backend": "claude", "model": "claude-x"}}}
    eng = _engagement(tmp_path, backends=backends, models=models)
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    seen: list[tuple[str, dict]] = []

    def answer(req, timeout=None):
        seen.append((req.full_url, dict(req.header_items())))
        # No key is sent, so a real server answers 401: it is there all the same.
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", answer)
    code, report = _doctor("-e", str(eng), "--probe-backend")
    assert code == 0, report
    assert {b["backend"]: b["reachable"] for b in report["backends"]} == {"local": True,
                                                                         "claude": True}
    assert sorted(u for u, _ in seen) == ["http://llm.example:8000/v1/models",
                                          "https://api.anthropic.com/v1/models"]
    for _, headers in seen:  # never a key
        assert not {k.lower() for k in headers} & {"authorization", "x-api-key"}


def test_probe_backend_without_a_model_says_so(env: FakeEnv):
    code, report = _doctor("--probe-backend")
    assert code == 0 and report["backends"] == []


def test_probe_backend_never_sends_user_info_from_the_url(env: FakeEnv, tmp_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch):
    backends = {"local": {"type": "openai_compatible",
                          "base_url": "http://op:s3cret-pw@llm.example:8000/v1"}}
    eng = _engagement(tmp_path, backends=backends, models=MODELS)
    seen: list[tuple[str, dict]] = []

    def answer(req, timeout=None):
        seen.append((req.full_url, dict(req.header_items())))
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", answer)
    code, report = _doctor("-e", str(eng), "--probe-backend")
    assert code == 0, report
    assert [u for u, _ in seen] == ["http://llm.example:8000/v1/models"]
    assert not {k.lower() for k in seen[0][1]} & {"authorization", "x-api-key"}
    assert "s3cret" not in json.dumps(report)


def test_probe_backend_survives_a_malformed_http_answer(env: FakeEnv, tmp_path: Path,
                                                        monkeypatch: pytest.MonkeyPatch):
    import http.client

    eng = _engagement(tmp_path, backends=BACKENDS, models=MODELS)

    def answer(req, timeout=None):
        raise http.client.BadStatusLine("garbage")

    monkeypatch.setattr(urllib.request, "urlopen", answer)
    code, report = _doctor("-e", str(eng), "--probe-backend")
    assert code == 1 and report["ready"] is False
    [probe] = report["backends"]
    assert probe["reachable"] is False and "BadStatusLine" in probe["detail"]
