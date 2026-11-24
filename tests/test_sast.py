"""The optional Opengrep `sast` scanner (UNVAR-89)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from tests.conftest import LEAKED_DB_URL
from unvarnish.analysis.delta import group_of, match_findings
from unvarnish.cli import app
from unvarnish.scanners.opengrep import opengrep_command, run_opengrep
from unvarnish.schemas.scan import ScannerFindings

runner = CliRunner()

APP_PY = (
    "from flask import request\n"
    "\n"
    "\n"
    "def find_user(db):\n"
    "    name = request.args.get('name')\n"
    "    return db.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    "\n"
    "\n"
    "def calc():\n"
    "    return eval(request.args.get('expr'))  # nosemgrep: rules.eval-request-input\n"
)
DB_PY = (
    "import psycopg\n"
    "\n"
    f"conn = psycopg.connect(\"{LEAKED_DB_URL}\"); conn.execute(\"DELETE FROM t WHERE id=\" + q)\n"
)
SQL_RULE = "rules.tainted-sql-string"
EVAL_RULE = "rules.eval-request-input"


def _result(rule: str, path: str, line: int, text: str, severity: str,
            ignored: bool = False) -> dict:
    return {
        "check_id": rule, "path": f"__ROOT__/{path}",
        "start": {"line": line, "col": 5, "offset": 0},
        "end": {"line": line, "col": 40, "offset": 0},
        "extra": {"message": f"{rule} matched: untrusted input reaches a dangerous call",
                  "severity": severity, "lines": text,
                  "metadata": {"category": "security", "cwe": ["CWE-89"]},
                  "is_ignored": ignored, "fingerprint": "requires login"},
    }


CANNED = {
    "version": "2.0.0",
    "results": [
        _result(SQL_RULE, "app.py", 6, APP_PY.splitlines()[5], "ERROR"),
        _result(SQL_RULE, "db.py", 3, DB_PY.splitlines()[2], "ERROR"),
        _result(EVAL_RULE, "app.py", 10, APP_PY.splitlines()[9], "WARNING", ignored=True),
        _result(SQL_RULE, "node_modules/x/index.js", 1, "q('x' + y)", "ERROR"),
    ],
    "errors": [],
    "paths": {"scanned": []},
}


def fake_opengrep(tmp_path: Path, output: dict | None = None, code: int = 0) -> Path:
    """An `opengrep` on PATH that logs its argv, working directory and environment and prints
    canned Opengrep JSON with the scan root (its last argument) in place of __ROOT__."""
    bindir = tmp_path / "ogbin"
    bindir.mkdir(exist_ok=True)
    (tmp_path / "og-output.json").write_text(json.dumps(output or CANNED), encoding="utf-8")
    script = bindir / "opengrep"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"log = {str(tmp_path / 'og-calls.jsonl')!r}\n"
        "with open(log, 'a', encoding='utf-8') as fh:\n"
        "    fh.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),\n"
        "                         'cwd_files': sorted(os.listdir('.')),\n"
        "                         'env': sorted(k for k in os.environ\n"
        "                                       if k.startswith(('SEMGREP', 'OPENGREP')))})\n"
        "             + '\\n')\n"
        f"text = open({str(tmp_path / 'og-output.json')!r}, encoding='utf-8').read()\n"
        "root = sys.argv[-1].rstrip('/')\n"
        "sys.stdout.write(text.replace('__ROOT__', root))\n"
        f"sys.exit({code})\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return bindir


def _calls(tmp_path: Path) -> list[dict]:
    log = tmp_path / "og-calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "python.yml").write_text(
        "rules:\n  - id: tainted-sql-string\n    languages: [python]\n    severity: ERROR\n"
        "    message: SQL built from input\n    pattern: $DB.execute($X + $Y)\n",
        encoding="utf-8")
    return rules


def _engagement(tmp_path: Path, sast: dict | None) -> Path:
    src = tmp_path / "vuln"
    (src / "node_modules" / "x").mkdir(parents=True)
    (src / "app.py").write_text(APP_PY, encoding="utf-8")
    (src / "db.py").write_text(DB_PY, encoding="utf-8")
    (src / ".semgrepignore").write_text("app.py\n", encoding="utf-8")
    (src / "node_modules" / "x" / "index.js").write_text("q('x' + y)\n", encoding="utf-8")
    eng = tmp_path / "acme"
    assert runner.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = runner.invoke(app, ["add", "vuln", "--files", str(src), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    if sast is not None:
        cfg_file = eng / "engagement.yaml"
        cfg = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        cfg.setdefault("scanners", {})["sast"] = sast
        cfg_file.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return eng


def _scan(eng: Path, *extra: str) -> ScannerFindings:
    for phase in ("inventory", "git"):
        r = runner.invoke(app, ["run", "--phase", phase, "-e", str(eng)])
        assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["run", "--phase", "scan", *extra, "-e", str(eng)])
    assert r.exit_code == 0, r.output
    path = eng / "tools" / "vuln" / "inventory" / "scanner-findings.json"
    return ScannerFindings.model_validate(json.loads(path.read_text(encoding="utf-8"))["data"])


def _sast(scan: ScannerFindings) -> list:
    return [f for f in scan.findings if f.scanner == "sast"]


# --- criterion 1: findings with path and line -----------------------------------------------

def test_scan_reports_planted_sql_injection_and_eval(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    scan = _scan(eng)
    found = {f.tags[1]: f for f in _sast(scan) if "opengrep" in f.tags}
    assert set(found) == {f"group:{SQL_RULE}", f"group:{EVAL_RULE}"}
    sql = found[f"group:{SQL_RULE}"]
    assert sql.source == "scanner" and sql.scanner == "sast"
    assert sql.severity == "high" and sql.category == "security"
    assert "Tainted SQL string" in sql.title
    # node_modules is vendored in the census: its result is dropped
    assert [(e.path, e.line_start, e.line_end) for e in sql.evidence] == [
        ("app.py", 6, 6), ("db.py", 3, 3)]
    assert "count:2" in sql.tags and sql.effort and sql.effort_note
    ev = found[f"group:{EVAL_RULE}"]
    assert ev.severity == "medium"
    assert [(e.path, e.line_start) for e in ev.evidence] == [("app.py", 10)]
    assert "nosem" in (ev.evidence[0].note or "")
    assert not any(n.startswith("sast:") for n in scan.notes)


def test_excerpts_are_redacted(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    scan = _scan(eng)
    dumped = json.dumps([f.model_dump(mode="json") for f in _sast(scan)])
    assert "hunter2" not in dumped
    db = next(e for f in _sast(scan) for e in f.evidence if e.path == "db.py")
    assert db.excerpt and "redacted" in db.excerpt


# --- criterion 2: not checked without the binary or the rules -------------------------------

def _findings_doc(eng: Path) -> str:
    r = runner.invoke(app, ["run", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    return (eng / "tools" / "vuln" / "docs" / "findings.md").read_text(encoding="utf-8")


def test_without_rules_the_run_succeeds_and_says_not_checked(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, None)
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    doc = _findings_doc(eng)
    not_analysed = doc.split("## Not analysed", 1)[1]
    assert "sast: not checked (no rules directory configured" in not_analysed
    assert "scanners.sast.rules" in not_analysed
    assert _calls(tmp_path) == []  # never run without rules


def test_without_the_binary_the_run_succeeds_and_says_not_checked(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    monkeypatch.setenv("PATH", "/usr/bin:/bin")  # no opengrep here
    doc = _findings_doc(eng)
    assert "sast: not checked (opengrep not installed" in doc.split("## Not analysed", 1)[1]


def test_missing_rules_directory_is_not_checked(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(tmp_path / "nowhere")})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    scan = _scan(eng)
    assert any(n.startswith("sast: not checked (rules directory not found") for n in scan.notes)
    assert _calls(tmp_path) == []


def test_relative_rules_resolve_against_the_engagement(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": "rules"})
    rules = eng / "rules"
    rules.mkdir()
    (rules / "r.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    _scan(eng)
    argv = _calls(tmp_path)[0]["argv"]
    assert argv[argv.index("--config") + 1] == str(rules.resolve())


def test_failed_or_garbled_opengrep_is_a_note(tmp_path, monkeypatch):
    rules = _rules(tmp_path)
    bad = subprocess.CompletedProcess([], 2, b'{"results": [], "errors": [{"message": "bad '
                                             b'rule"}]}', b"")
    _, _, note = run_opengrep(tmp_path, rules, which=lambda t: t, run=lambda *a, **k: bad)
    assert note == "opengrep failed: bad rule"
    garbled = subprocess.CompletedProcess([], 0, b"not json", b"")
    _, _, note = run_opengrep(tmp_path, rules, which=lambda t: t, run=lambda *a, **k: garbled)
    assert note and note.startswith("opengrep output unreadable")


# --- criterion 3: no network ----------------------------------------------------------------

def test_command_uses_only_the_local_rules_and_stays_offline(tmp_path):
    rules = _rules(tmp_path)
    cmd = opengrep_command(tmp_path / "src", rules)
    assert cmd[:2] == ["opengrep", "scan"] and cmd[-1] == str(tmp_path / "src")
    assert cmd.count("--config") == 1 and cmd[cmd.index("--config") + 1] == str(rules)
    assert "--disable-version-check" in cmd and "--json" in cmd
    joined = " ".join(cmd)
    for registry in ("auto", "p/", "r/", "s/", "://", "git+", "--metrics", "--pro"):
        assert registry not in joined.replace(str(tmp_path), "")


@pytest.mark.parametrize("value", ["auto", "p/python", "r/python.lang.security", "s/x",
                                   "https://example.com/rules.yml", "git+https://x.io/r.git",
                                   "http://intranet/rules"])
def test_registry_and_url_rules_are_rejected(tmp_path, monkeypatch, value):
    monkeypatch.chdir(tmp_path)  # a local folder named like the value must not count either
    Path(value.split(":", 1)[0]).mkdir(parents=True, exist_ok=True)
    calls = []
    findings, _, note = run_opengrep(tmp_path, value, which=lambda t: t,
                                  run=lambda *a, **k: calls.append(a))
    assert findings == [] and calls == []
    assert note and "not a local rules directory" in note


def test_opengrep_runs_in_its_own_empty_directory_without_rule_variables(tmp_path,
                                                                         monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    here = tmp_path / "consultant"
    here.mkdir()
    (here / ".semgrepignore").write_text("*\n", encoding="utf-8")
    monkeypatch.chdir(here)
    monkeypatch.setenv("SEMGREP_RULES", "p/default")
    monkeypatch.setenv("OPENGREP_APP_TOKEN", "x")
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    _scan(eng)
    (call,) = _calls(tmp_path)
    assert Path(call["cwd"]).resolve() != here.resolve() and call["cwd_files"] == []
    assert not Path(call["cwd"]).exists()
    assert call["env"] == []


# --- criterion 4: ignore files and nosem comments are suppressions --------------------------

def test_ignore_files_and_nosem_comments_are_reported_and_disregarded(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    scan = _scan(eng)
    (sup,) = [f for f in _sast(scan) if "suppression" in f.tags]
    places = {(e.path, e.line_start) for e in sup.evidence}
    assert places == {(".semgrepignore", None), ("app.py", 10)}
    assert "nosemgrep" in next(e.excerpt for e in sup.evidence if e.path == "app.py")
    argv = _calls(tmp_path)[0]["argv"]
    for flag in ("--disable-nosem", "--x-ignore-semgrepignore-files", "--no-git-ignore"):
        assert flag in argv


def test_suppressions_are_reported_even_when_opengrep_did_not_run(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, None)
    scan = _scan(eng)
    assert [f.title for f in _sast(scan)] == ["Opengrep suppressions in the source"]


# --- criterion 5: grouped, capped, matched by scanner and rule ------------------------------

def test_results_are_capped_by_max_evidence(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path)), "max_evidence": 1})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    scan = _scan(eng)
    sql = next(f for f in _sast(scan) if f"group:{SQL_RULE}" in f.tags)
    assert len(sql.evidence) == 1 and "count:2" in sql.tags
    assert "first 1 of 2" in sql.summary


def test_reaudit_matches_by_scanner_and_rule(tmp_path, monkeypatch):
    eng = _engagement(tmp_path, {"rules": str(_rules(tmp_path))})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    before = next(f for f in _sast(_scan(eng)) if f"group:{SQL_RULE}" in f.tags)
    assert group_of(before) == f"sast.{SQL_RULE}"
    moved = {**CANNED, "results": [_result(SQL_RULE, "db.py", 3, "x", "ERROR")]}
    fake_opengrep(tmp_path, moved)
    after = next(f for f in _sast(_scan(eng, "--force"))
                 if f"group:{SQL_RULE}" in f.tags)
    (entry,) = match_findings([before], [after], drift=5)
    assert entry.matched_by in ("id", "group") and entry.group == f"sast.{SQL_RULE}"
    assert entry.previous_count == 2 and entry.count == 1


def test_changed_rules_rescan(tmp_path, monkeypatch):
    rules = _rules(tmp_path)
    eng = _engagement(tmp_path, {"rules": str(rules)})
    monkeypatch.setenv("PATH", f"{fake_opengrep(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    _scan(eng)
    _scan(eng)
    assert len(_calls(tmp_path)) == 1  # fresh: not rerun
    (rules / "python.yml").write_text("rules: []\n", encoding="utf-8")
    _scan(eng)
    assert len(_calls(tmp_path)) == 2


# --- criterion 6: scanners list -------------------------------------------------------------

def test_scanners_list_shows_sast_and_its_options():
    r = runner.invoke(app, ["scanners", "list"], env={"COLUMNS": "400"})
    assert r.exit_code == 0, r.output
    line = next(line for line in r.output.splitlines() if " sast " in line)
    assert "rules=" in line and "max_evidence=25" in line


# --- review fixes ----------------------------------------------------------------------------

def test_noopengrep_comments_are_suppressions_too(tmp_path):
    """Opengrep 1.15 added `noopengrep` to its default nosem markers (`nosem`, `nosemgrep`)."""
    eng = _engagement(tmp_path, None)
    src = eng / "tools" / "vuln" / "source"  # `add --files` copied the source here
    (src / "db.py").write_text(DB_PY + "x = eval(q)  # noopengrep: rules.eval\n",
                               encoding="utf-8")
    scan = _scan(eng)
    (sup,) = [f for f in _sast(scan) if "suppression" in f.tags]
    assert any("noopengrep" in (e.excerpt or "") for e in sup.evidence)


@pytest.mark.parametrize("errors", [5, "boom", {"message": "x"}, None])
def test_malformed_errors_never_raise(tmp_path, errors):
    rules = _rules(tmp_path)
    out = json.dumps({"results": [], "errors": errors}).encode()
    proc = subprocess.CompletedProcess([], 1, out, b"")
    results, errs, note = run_opengrep(tmp_path, rules, which=lambda t: t,
                                       run=lambda *a, **k: proc)
    assert results == [] and note is None and isinstance(errs, list)


def test_unreadable_rule_file_does_not_break_the_inputs_hash(tmp_path, monkeypatch):
    from unvarnish.scanners.opengrep import rules_digest

    rules = _rules(tmp_path)
    good = rules_digest(str(rules), None)

    def boom(self):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_bytes", boom)
    bad = rules_digest(str(rules), None)
    assert bad and bad != good
