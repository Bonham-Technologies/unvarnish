from pathlib import Path

from tests.conftest import LEAKED_DB_URL, LEAKED_KEY
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners import secrets as secrets_mod
from unvarnish.scanners.secrets import (
    SecretsScanner,
    fingerprint,
    is_placeholder,
    redact,
    scan_history_lines,
    scan_text,
)
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.scan import ScannerFindings

# A second real-shaped AWS key ID, built from fragments like every credential-shaped fixture.
FAKE_AWS = "AKIA" + "ZZZZZZZZZZZZZZZ9"


def _scan(eng: Engagement, name: str) -> ScannerFindings:
    ctx = build_context(eng, name)
    assert InventoryPhase().run(ctx).status == PhaseStatus.ok
    assert GitPhase().run(ctx).status == PhaseStatus.ok
    assert ScanPhase(scanners=[SecretsScanner()]).run(ctx).status == PhaseStatus.ok
    return read_artifact(ctx.paths.scanner_findings, ScannerFindings).data


def test_history_only_secrets_are_high_and_redacted(ingested):
    out = _scan(*ingested)
    assert len(out.findings) == 2
    titles = sorted(f.title for f in out.findings)
    assert titles == [
        "AWS access key ID in git history",
        "Database connection string with embedded password in git history",
    ]
    for f in out.findings:
        assert f.severity == Severity.high
        ev = f.evidence[0]
        assert ev.path == "app.py"
        assert ev.fingerprint and len(ev.fingerprint) == 12
        assert LEAKED_KEY not in (ev.excerpt or "")
        assert "hunter2" not in (ev.excerpt or "")
        assert ev.note and "commit" in ev.note
        assert f.scanner == "secrets"


def test_current_secrets_are_critical(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "settings.py").write_text(
        'API_KEY = "sk-ant-' + 'api03-abcdefghijklmnopqrstuvwxyz0123456789"\n'
        'PASSWORD = "changeme"\n'
        'db = "mysql://root:S3cret!@10.0.0.5/app"\n'
    )
    (pile / "id_rsa").write_text(
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    (pile / "safe.py").write_text(
        'token = os.environ["TOKEN"]\nplaceholder = "<your-api-key>"\n'
    )
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    by_title = {f.title: f for f in out.findings}
    assert "Anthropic API key" in by_title
    assert "Database connection string with embedded password" in by_title
    assert "Private key material" in by_title
    assert all(f.severity == Severity.critical for f in out.findings)
    assert not any("changeme" in (f.evidence[0].excerpt or "") for f in out.findings)
    assert not any(f.evidence[0].path == "safe.py" for f in out.findings)
    key_finding = by_title["Anthropic API key"]
    assert key_finding.evidence[0].line_start == 1
    excerpt = key_finding.evidence[0].excerpt or ""
    assert "sk-a" in excerpt and "abcdefghijklmnop" not in excerpt


def test_scan_text_rules_and_redaction():
    text = f'x = "{LEAKED_KEY}"\ny = "{LEAKED_DB_URL}"\nz = "ghp_" + "a" * 36\n'
    matches = scan_text("f.py", text)
    rules = {m.rule for m in matches}
    assert {"aws_access_key", "connection_string"} <= rules
    m = next(m for m in matches if m.rule == "aws_access_key")
    assert m.line == 1 and m.raw == LEAKED_KEY
    red = redact(m.line_text, m.raw)
    assert LEAKED_KEY not in red and "AKIA" in red and "redacted" in red
    assert fingerprint(LEAKED_KEY) == fingerprint(LEAKED_KEY)
    assert len(fingerprint(LEAKED_KEY)) == 12


def test_placeholders_ignored():
    assert is_placeholder("changeme")
    assert is_placeholder("<your-api-key>")
    assert is_placeholder("${SECRET}")
    assert is_placeholder("xxxxxxxxxxxx")
    assert not is_placeholder("S3cret!Value99")
    assert scan_text("f.py", 'password = "changeme"\n') == []


def test_scan_history_lines_tracks_commit_and_path():
    lines = iter([
        "\x1e" + "c" * 40,
        "diff --git a/app.py b/app.py",
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -0,0 +1 @@",
        f'+KEY = "{LEAKED_KEY}"',
        "\x1e" + "d" * 40,
        "diff --git a/other.py b/other.py",
        "+++ b/other.py",
        "-removed line with nothing",
        "+clean = 1",
    ])
    matches = scan_history_lines(lines)
    assert len(matches) == 1
    assert matches[0].commit == "c" * 40
    assert matches[0].path == "app.py"
    assert matches[0].raw == LEAKED_KEY


def test_history_scan_uses_streaming(ingested, monkeypatch):
    eng, name = ingested
    calls: list[list[str]] = []
    real = secrets_mod.git_lines

    def spy(args, cwd):
        calls.append(list(args))
        return real(args, cwd)

    monkeypatch.setattr(secrets_mod, "git_lines", spy)
    _scan(eng, name)
    assert calls and calls[0][:2] == ["log", "-p"]


# --- fixes from the whole-branch review -------------------------------------
from tests.conftest import _commit, _git  # noqa: E402
from unvarnish.scanners.secrets import redact_line  # noqa: E402


def _scan_pile(engagement: Engagement, tmp_path: Path, files: dict[str, str]) -> ScannerFindings:
    pile = tmp_path / "pile"
    pile.mkdir()
    for name, text in files.items():
        (pile / name).write_text(text)
    ingest_tool(engagement, "pile", str(pile), "files")
    return _scan(engagement, "pile")


def test_two_secrets_on_one_line_are_both_redacted(engagement: Engagement, tmp_path: Path):
    key = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz0123456789"
    pw = "Tr0ub4dor&3xyz"
    out = _scan_pile(engagement, tmp_path, {
        "config.json": f'{{"apiKey": "{key}", "password": "{pw}"}}\n',
    })
    assert out.findings, "expected at least one finding"
    raw_json = (engagement.tool_paths("pile").scanner_findings).read_text()
    assert key not in raw_json and pw not in raw_json
    for f in out.findings:
        assert "Tr0u" not in (f.evidence[0].excerpt or "")


def test_value_group_matches_are_fully_redacted():
    text = 'password = "Tr0ub4dor&3xyz"\n'
    matches = scan_text("f.py", text)
    assert len(matches) == 1
    excerpt = redact_line(matches[0].line_text, matches)
    assert "Tr0u" not in excerpt and "redacted 14 chars" in excerpt
    aws = scan_text("f.py", f'k = "{LEAKED_KEY}"\n')
    assert "AKIA" in redact_line(aws[0].line_text, aws)  # prefix-rule keeps its public prefix


def test_json_and_yaml_quoted_keys_are_matched():
    assert scan_text("c.json", '"password": "hunter2hunter2"\n')
    assert scan_text("c.json", '"client_secret": "Tr0ub4dor&3xyz"\n')
    assert scan_text("c.yaml", "api_key: 'Tr0ub4dor&3xyz'\n")


def test_low_signal_values_are_not_flagged():
    assert scan_text("a.js", 'token: "undefined"\n') == []
    assert scan_text("a.js", 'const sk_class = "sk-circle-bounce-animation-x"\n') == []
    assert scan_text("a.py", 'password = "mysecretpassword"\n')  # lowercase but real-looking
    assert scan_text("a.py", 'api_key = "Tr0ub4dor&3xyz"\n')


def _history_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "hist"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    _commit(root, "leak", "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")
    for name in files:
        (root / name).write_text("clean = 1\n")
    _commit(root, "scrub", "Alice", "alice@example.com", "2026-01-06T10:00:00+00:00")
    return root


def test_history_findings_with_same_rule_and_file_have_distinct_ids(
    engagement: Engagement, tmp_path: Path
):
    repo = _history_repo(tmp_path, {
        "app.py": f'a = "{LEAKED_KEY}"\nb = "{FAKE_AWS}"\n',
    })
    ingest_tool(engagement, "hist", str(repo), "repo")
    out = _scan(engagement, "hist")
    ids = [f.id for f in out.findings if f.title == "AWS access key ID in git history"]
    assert len(ids) == 2 and len(set(ids)) == 2


def test_history_scan_survives_noprefix_gitconfig_and_nonascii_paths(
    engagement: Engagement, tmp_path: Path, monkeypatch
):
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[diff]\n\tnoprefix = true\n\tmnemonicPrefix = true\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    repo = _history_repo(tmp_path, {"données/clé.py": f'k = "{LEAKED_KEY}"\n'})
    ingest_tool(engagement, "hist", str(repo), "repo")
    out = _scan(engagement, "hist")
    hist = [f for f in out.findings if f.title.endswith("in git history")]
    assert len(hist) == 1
    assert hist[0].evidence[0].path == "données/clé.py"


# --- fixes from the first real-repo run (ESCAPESUITE) -----------------------
def test_vendored_files_skipped_even_when_gitignored(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "node_modules" / "lib").mkdir(parents=True)
    (pile / ".gitignore").write_text("node_modules/\n.env\n")
    (pile / "node_modules" / "lib" / "index.js").write_text(f'const k = "{FAKE_AWS}";\n')
    (pile / ".env").write_text("DB_PASSWORD=Tr0ub4dor&3xyz\n" f'AWS_KEY="{LEAKED_KEY}"\n')
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    paths = sorted({f.evidence[0].path for f in out.findings})
    assert paths == [".env"], paths  # gitignored but not vendored: still scanned


def test_test_fixture_and_env_reference_values_not_flagged():
    assert scan_text("c.toml", 'openai_api_key = "env(OPENAI_API_KEY)"\n') == []
    tsx = "autoComplete={isSignUp ? 'new-password' : 'current-password'}\n"
    assert scan_text("a.tsx", tsx) == []
    assert scan_text("t.ts", "access_token: 'test-token-abc123',\n") == []
    assert scan_text("t.ts", "token: 'mock-jwt-token-12345',\n") == []
    assert scan_text("t.ts", "apikey: 'fake-anon-key-9',\n") == []
    # A real-looking value stays a finding.
    assert scan_text("t.ts", "apikey: 'eyJ" + "hbGciOiJIUzI1NiJ9.e30.Zm9v',\n")


DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
REAL_PEM_BODY = "MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"


def test_documented_example_keys_are_not_findings():
    text = (f'LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            f'aws_secret_access_key = "{DOC_SECRET}"\n'
            f'token = "ghp_EXAMPLE{"a" * 29}"\n'
            f'KEY = "{PEM}\\nMIIE...\\n-----END RSA PRIVATE KEY-----"\n'
            f'{PEM}\n...\n-----END RSA PRIVATE KEY-----\n'
            f'{PEM}\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----\n')
    assert scan_text("f.py", text) == []
    history = scan_history_lines(iter(["\x1e" + "c" * 40, "+++ b/app.py"]
                                      + ["+" + line for line in text.splitlines()]))
    assert history == []


def test_real_shaped_aws_key_still_found():
    text = (f'k = "{LEAKED_KEY}"\n{PEM}\n{REAL_PEM_BODY}\n'
            f'one = "{PEM}\\n{REAL_PEM_BODY}\\n"\n'
            f'{PEM}\nProc-Type: 4,ENCRYPTED\n'
            f"const k = '{PEM}\\n' +\n  '{REAL_PEM_BODY}\\n' +\n"
            f'k := "{PEM}\\n" +\n\t"{REAL_PEM_BODY}"\n'
            f'lines = ["{PEM}",\n  "{REAL_PEM_BODY}",\n]\n')
    rules = sorted(m.rule for m in scan_text("f.py", text))
    assert rules == ["aws_access_key"] + ["private_key"] * 6
    history = scan_history_lines(iter(["\x1e" + "c" * 40, "+++ b/app.py"]
                                      + ["+" + line for line in text.splitlines()]))
    assert sorted(m.rule for m in history) == rules


# --- UNVAR-18: tool caches are not leaks; gitignored hits say so --------------
GITIGNORED_NOTE = "gitignored: present in the ingested copy, not in the repository"
IGNORE_RULE_NOTE = "matches a .gitignore rule: may be absent from the repository"


def test_caches_skipped_and_gitignored_hits_say_so(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    cache = pile / ".pytest_cache" / "v" / "cache"
    cache.mkdir(parents=True)
    # pytest writes its own .gitignore ("*") into the cache, so gitignore wins over BUILD_DIRS
    (pile / ".pytest_cache" / ".gitignore").write_text("# Created by pytest automatically.\n*\n")
    token = "ghp_" + "Zq7Xw2Vr9Ts4Up6Ny8Mk3Lj5Hg1Fd0Sa7Pb2"
    (cache / "nodeids").write_text(
        f'[\n  "tests/test_x.py::test_token[{token}]"\n]\n')
    (pile / ".gitignore").write_text(".env\n")
    (pile / ".env").write_text(f'AWS_KEY="{LEAKED_KEY}"\n')
    (pile / "app.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    paths = sorted({e.path for f in out.findings for e in f.evidence})
    assert paths == [".env"], paths
    (finding,) = out.findings
    assert finding.severity == Severity.critical
    # a copy without git: whether the file is tracked is unknown, so the note says only that
    note = finding.evidence[0].note or ""
    assert IGNORE_RULE_NOTE in note and GITIGNORED_NOTE not in note


def _ignored_env_repo(tmp_path: Path, *, commit_env: bool) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("x = 1\n")
    (root / ".env").write_text(f'AWS_KEY="{LEAKED_KEY}"\n')
    if commit_env:  # committed first, ignored afterwards: still tracked, still in the repo
        _commit(root, "add env", "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")
    (root / ".gitignore").write_text(".env\n")
    _commit(root, "ignore env", "Alice", "alice@example.com", "2026-01-06T10:00:00+00:00")
    return root


def test_untracked_gitignored_secret_says_not_in_repository(engagement: Engagement,
                                                            tmp_path: Path):
    ingest_tool(engagement, "repo", str(_ignored_env_repo(tmp_path, commit_env=False)), "repo")
    out = _scan(engagement, "repo")
    (finding,) = [f for f in out.findings if f.evidence[0].path == ".env"]
    assert finding.severity == Severity.critical
    assert GITIGNORED_NOTE in (finding.evidence[0].note or "")


def test_tracked_file_matching_ignore_rule_is_not_called_gitignored(engagement: Engagement,
                                                                    tmp_path: Path):
    ingest_tool(engagement, "repo", str(_ignored_env_repo(tmp_path, commit_env=True)), "repo")
    out = _scan(engagement, "repo")
    (finding,) = [f for f in out.findings if f.evidence[0].path == ".env"]
    assert finding.severity == Severity.critical
    note = finding.evidence[0].note or ""
    assert "gitignored" not in note and "may be absent" not in note


def test_tool_caches_skipped_whatever_the_exclusion_reason():
    from unvarnish.analysis.languages import Classification
    from unvarnish.schemas.inventory import FileRecord

    def rec(path: str, reason: str | None) -> FileRecord:
        return FileRecord(path=path, bytes=10, lines=1, language=None,
                          classification=Classification.config, excluded=reason is not None,
                          exclusion_reason=reason)

    skip = secrets_mod.tree_skip_reason
    assert skip(rec(".pytest_cache/v/cache/nodeids", "gitignore"))
    assert skip(rec("pkg/__pycache__/x.txt", "gitignore"))
    assert skip(rec(".mypy_cache/3.12/app.data.json", "build_output:.mypy_cache"))
    assert skip(rec("tests/.pytest_cache/v/cache/lastfailed", "gitignore"))
    assert skip(rec(".env", "gitignore")) is None
    assert skip(rec("config/local.yaml", "gitignore")) is None
    # build output is shipped code: a key baked into a bundle is a live leak, so it is read
    assert skip(rec("dist/main.js", "build_output:dist")) is None
    assert skip(rec("dist-prod/main.js", "build_output:dist-prod")) is None
    assert skip(rec("web/.next/server/app.js", "gitignore")) is None
    assert skip(rec(".vercel/.env.production.local", "gitignore")) is None
    assert skip(rec("tests/build/fixture.env", "gitignore")) is None


def test_committed_build_output_secret_is_critical(engagement: Engagement, tmp_path: Path):
    root = tmp_path / "hist"
    (root / "dist").mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    (root / "dist" / "bundle.js").write_text(f'const k = "{LEAKED_KEY}";\n')
    (root / "app.py").write_text("x = 1\n")
    _commit(root, "ship", "Alice", "alice@example.com", "2026-01-05T10:00:00+00:00")
    ingest_tool(engagement, "hist", str(root), "repo")
    out = _scan(engagement, "hist")
    hits = [f for f in out.findings if f.evidence[0].path == "dist/bundle.js"]
    assert hits and all(f.severity == Severity.critical for f in hits)
    assert "gitignored" not in (hits[0].evidence[0].note or "")


def test_build_output_secret_found_without_git_history(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "dist").mkdir(parents=True)
    (pile / "dist" / "bundle.js").write_text(f'const k = "{LEAKED_KEY}";\n')
    (pile / "app.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    out = _scan(engagement, "pile")
    hits = [f for f in out.findings if f.evidence[0].path == "dist/bundle.js"]
    assert hits and all(f.severity == Severity.critical for f in hits)
