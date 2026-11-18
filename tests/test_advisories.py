import json
import os
import stat
from pathlib import Path

import pytest

from unvarnish.analysis.advisories import (
    lookup_advisories,
    osv_command,
    parse_osv,
    severity_from_osv,
)
from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import build_context
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.schemas.inventory import Dependencies


@pytest.fixture(autouse=True)
def _enable_osv(monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)


def report(root: Path) -> dict:
    return {"results": [{"source": {"path": str(root / "requirements.txt"), "type": "lockfile"},
                         "packages": [{
                             "package": {"name": "flask", "version": "2.3.2",
                                         "ecosystem": "PyPI"},
                             "vulnerabilities": [
                                 {"id": "GHSA-aaaa", "aliases": ["CVE-2023-1"],
                                  "summary": "Cookie leak",
                                  "database_specific": {"severity": "HIGH"}},
                                 {"id": "PYSEC-1", "summary": "Same issue"}],
                             "groups": [{"ids": ["GHSA-aaaa", "PYSEC-1"],
                                         "aliases": ["CVE-2023-1"], "max_severity": "7.5"}]}]}]}


def fake_osv(tmp_path: Path, body: str, code: int = 1) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    payload = tmp_path / "osv-out.txt"
    payload.write_text(body)
    script = bindir / "osv-scanner"
    script.write_text(f"#!/bin/sh\necho \"$@\" > {tmp_path / 'osv-args.txt'}\n"
                      "echo 'Loaded PyPI local db from /opt/osv/PyPI/all.zip' >&2\n"
                      f"cat {payload}\nexit {code}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return bindir


def test_osv_command_offline_by_default(tmp_path):
    cmd = osv_command(tmp_path, {})
    assert cmd[:6] == ["osv-scanner", "scan", "source", "--format", "json", "--recursive"]
    assert "--offline" in cmd and cmd[-1] == str(tmp_path)
    assert "--offline" not in osv_command(tmp_path, {"offline": False})
    assert osv_command(tmp_path, {"osv_args": ["--format", "json", "-r"]})[1:4] == [
        "--format", "json", "-r"]


def test_severity_mapping():
    assert severity_from_osv("9.8", []) == "critical"
    assert severity_from_osv("7.5", []) == "high"
    assert severity_from_osv("5.0", []) == "medium"
    assert severity_from_osv("2.0", []) == "low"
    assert severity_from_osv(None, ["MODERATE"]) == "medium"
    assert severity_from_osv("", ["HIGH", "LOW"]) == "high"
    assert severity_from_osv(None, []) == "medium"


def test_parse_osv_groups_and_relativises(tmp_path):
    out = parse_osv(report(tmp_path), tmp_path)
    assert out == [{"id": "GHSA-aaaa", "ids": ["GHSA-aaaa", "PYSEC-1", "CVE-2023-1"],
                    "package": "flask", "version": "2.3.2", "ecosystem": "PyPI",
                    "manifest": "requirements.txt", "summary": "Cookie leak",
                    "severity": "high"}]
    assert parse_osv({}, tmp_path) == [] and parse_osv({"results": None}, tmp_path) == []


def test_lookup_runs_the_binary(tmp_path, monkeypatch):
    bindir = fake_osv(tmp_path, json.dumps(report(tmp_path)), code=1)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    checked, advisories, note = lookup_advisories(tmp_path, {})
    assert checked and note is None and advisories[0]["id"] == "GHSA-aaaa"
    assert "--offline" in (tmp_path / "osv-args.txt").read_text().split()


def test_lookup_records_failure_note(tmp_path, monkeypatch):
    assert lookup_advisories(tmp_path, {}, which=lambda t: None) == (
        False, [], "osv-scanner not installed")
    assert lookup_advisories(tmp_path, {"enabled": False}) == (
        False, [], "disabled in engagement.yaml")
    monkeypatch.setenv("UNVARNISH_DISABLE_OSV", "1")
    assert lookup_advisories(tmp_path, {})[2] == "disabled by UNVARNISH_DISABLE_OSV"
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV")
    bindir = fake_osv(tmp_path, "no database found", code=127)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    checked, advisories, note = lookup_advisories(tmp_path, {})
    assert not checked and advisories == [] and note.startswith("osv-scanner failed")
    fake_osv(tmp_path, "not json", code=0)
    checked, _, note = lookup_advisories(tmp_path, {})
    assert not checked and "unreadable" in note


def test_inventory_stores_advisories_and_note(ingested, monkeypatch, tmp_path):
    eng, tool = ingested
    monkeypatch.setenv("PATH", "/usr/bin:/bin")  # no osv-scanner here
    ctx = build_context(eng, tool)
    InventoryPhase().run(ctx)
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    assert not deps.advisories_checked and deps.advisories_note == "osv-scanner not installed"
    bindir = fake_osv(tmp_path, json.dumps(report(ctx.source_root)), code=1)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}/usr/bin:/bin")
    InventoryPhase().run(ctx)
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    assert deps.advisories_checked and deps.advisories[0]["package"] == "flask"
    assert deps.advisories_note is None
