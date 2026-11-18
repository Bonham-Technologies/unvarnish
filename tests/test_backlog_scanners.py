"""Known-issues burn-down, task 2: scanners."""
import time
from pathlib import Path, PurePosixPath

import pytest

from tests.test_scanner_dependencies import ctx_with, dep  # noqa: F401  (fixtures reused)
from unvarnish.analysis.languages import Excluder, detect_language


def test_hygiene_line_numbers_ignore_form_feeds(tmp_path):
    from unvarnish.scanners.hygiene import todo_lines

    text = "a = 1\x0c\nb = 2 c\n# TODO fix\n"
    assert [n for n, _ in todo_lines(text)] == [3]


def test_private_keys_get_distinct_fingerprints():
    from unvarnish.scanners.secrets import fingerprint_of, scan_text

    a = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + "a" * 48 + "\n"
    b = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA" + "b" * 48 + "\n"
    fa = {fingerprint_of(m) for m in scan_text("a.pem", a) if m.rule == "private_key"}
    fb = {fingerprint_of(m) for m in scan_text("b.pem", b) if m.rule == "private_key"}
    assert fa and fb and fa != fb


def test_history_private_keys_get_distinct_fingerprints():
    from unvarnish.scanners.secrets import fingerprint_of, scan_history_lines

    header = "+-----BEGIN RSA " + "PRIVATE KEY-----"
    lines = ["\x1eaaa", "+++ b/k.pem", header, "+MIIEowIBAAKCAQEA" + "a" * 48,
             "\x1ebbb", "+++ b/k.pem", header, "+MIIEpAIBAAKCAQEA" + "b" * 48]
    fps = {fingerprint_of(m) for m in scan_history_lines(lines)}
    assert len(fps) == 2


def test_rules_skip_lines_without_their_literal_hint():
    from unvarnish.scanners.secrets import RULES, line_may_match

    plain = "def add(a, b): return a + b"
    assert not any(line_may_match(r, plain) for r in RULES)
    assert line_may_match(next(r for r in RULES if r.name == "aws_access_key"),
                          'k = "AKIA' + 'ABCDEFGHIJKLMNOP"')
    assert line_may_match(next(r for r in RULES if r.name == "generic_assignment"),
                          'PASSWORD = "x"')


def test_history_note_does_not_claim_removal_for_files_still_present(tmp_path):
    from unvarnish.scanners.secrets import history_note

    assert "removed from the working tree" in history_note("abc", "old.py", None)
    note = history_note("abc", "vendor/lib.py", "vendored")
    assert "removed" not in note and "still in the working tree" in note


def test_history_findings_are_tagged():
    from unvarnish.render.findings import is_history
    from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source

    f = Finding(tool="t", category=Category.security, severity=Severity.high,
                title="AWS key (renamed title)", summary="s", impact="i", remediation="r",
                evidence=[Evidence(path="a")], source=Source.scanner, scanner="secrets",
                tags=["history"])
    assert is_history(f)


@pytest.mark.parametrize("value,disabled", [("1", True), ("true", True), ("yes", True),
                                            ("0", False), ("false", False), ("", False)])
def test_disable_switches_parse_booleans(monkeypatch, value, disabled):
    from unvarnish.util.env import env_flag

    monkeypatch.setenv("UNVARNISH_DISABLE_OSV", value)
    assert env_flag("UNVARNISH_DISABLE_OSV") is disabled


def test_inventory_goes_stale_when_osv_scanner_appears(tmp_path, monkeypatch):
    import unvarnish.phases.inventory as inv
    from unvarnish.phases.inventory import InventoryPhase

    class Cfg:
        scanners = {"dependencies": {"offline": True}}

    class Meta:
        origin_kind = "files"

    class Ctx:
        source_root = tmp_path
        config = Cfg()
        meta = Meta()

    monkeypatch.setattr(inv.shutil, "which", lambda t: None)
    before = InventoryPhase().inputs_hash(Ctx())
    monkeypatch.setattr(inv.shutil, "which", lambda t: "/usr/bin/" + t)
    assert InventoryPhase().inputs_hash(Ctx()) != before
    Cfg.scanners = {"dependencies": {"offline": False}}
    assert InventoryPhase().inputs_hash(Ctx()) != before


def test_hostname_search_is_linear_on_dotted_lines():
    from unvarnish.scanners.hardcoded_infra import find_infra

    line = ("a." * 2000) + "x"
    start = time.perf_counter()
    find_infra(line * 1)
    assert time.perf_counter() - start < 0.05
    assert [v for k, v, _ in find_infra('DB = "db.internal"') if k == "host"] == ["db.internal"]
    assert [v for k, v, _ in find_infra("x = api.corp:8443/y") if k == "host"] == [
        "api.corp:8443"]


def test_gitleaks_history_duplicates_collapse():
    from unvarnish.scanners.secrets import dedupe_gitleaks_history

    items = [{"RuleID": "generic-api-key", "File": "a.py", "Commit": "c1", "StartLine": 3},
             {"RuleID": "generic-api-key", "File": "a.py", "Commit": "c1", "StartLine": 9},
             {"RuleID": "generic-api-key", "File": "a.py", "Commit": "c2", "StartLine": 3}]
    assert len(dedupe_gitleaks_history(items)) == 2


def test_generated_bulk_counts_added_lines_only():
    from unvarnish.phases.git import is_bulk_commit

    assert is_bulk_commit(added=2500, deleted=0, threshold=2000)
    assert not is_bulk_commit(added=100, deleted=5000, threshold=2000)


def test_vulnerabilities_by_severity_text():
    from unvarnish.render.findings import vulnerability_text

    advs = [{"severity": "high"}, {"severity": "medium"}, {"severity": "medium"}]
    assert vulnerability_text(advs) == "3 (1 high, 2 medium)"
    assert vulnerability_text([]) == "0"


@pytest.mark.parametrize("path,reason", [
    ("tests/build/fixture.py", None), ("src/test/out/x.ts", None),
    ("build/app.js", "build_output:build"), ("bin/run.sh", None),
])
def test_build_dirs_inside_tests_and_bin_are_not_build_output(tmp_path, path, reason):
    assert Excluder(tmp_path).reason(PurePosixPath(path)) == reason


def test_extensions_are_case_insensitive_and_notebooks_are_known():
    assert detect_language(PurePosixPath("APP.PY"), b"") == "python"
    assert detect_language(PurePosixPath("Index.HTML"), b"") == "html"
    assert detect_language(PurePosixPath("analysis.ipynb"), b"") == "jupyter"


def test_urls_on_comment_lines_are_not_hardcoded_endpoints():
    from unvarnish.scanners.hardcoded_infra import find_infra

    for line in ("# see https://github.com/acme/tool/issues/12",
                 "  // https://aka.ms/dotnet/aspire", " * https://example.org/spec",
                 "<!-- https://acme.com/x -->", "-- https://wiki.acme.com/page"):
        assert find_infra(line) == [], line
    assert find_infra('API = "https://api.acme-corp.com/v1"  # prod')


def test_url_redaction_keeps_commit_hashes_and_file_names():
    from unvarnish.scanners.hardcoded_infra import safe_url

    sha = "3f2c1a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a"
    assert safe_url(f"https://github.com/acme/x/blob/{sha}/src/main.py") == \
        f"https://github.com/acme/x/blob/{sha}/src/main.py"
    assert safe_url("https://acme.com/dl/release-notes-2026-10-19-final.pdf").endswith(
        "release-notes-2026-10-19-final.pdf")
    assert "[redacted]" in safe_url("https://acme.com/hook/AbCdEfGhIjKlMnOpQrStUv0123456789")


def test_scanner_notes_reach_not_analysed(ingested, monkeypatch):
    from tests.test_render import _render

    eng, tool = ingested
    monkeypatch.setenv("UNVARNISH_DISABLE_GITLEAKS", "1")
    doc, _ = _render(eng, tool)
    section = doc.split("## Not analysed", 1)[1]
    assert "gitleaks" in section and "disabled" in section


def test_too_large_paragraph_is_accurate():
    text = Path(__file__).resolve().parents[1].joinpath(
        "src/unvarnish/render/templates/findings.md.j2").read_text(encoding="utf-8")
    para = next(ln for ln in text.splitlines() if ln.startswith("Files too large"))
    assert "metrics" not in para and "hardcoded" in para and "4,000" in text
