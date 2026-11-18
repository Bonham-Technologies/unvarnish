"""Regression tests for the slice 7 final review: secrets in scanner output, offline advisory
lookups, scanner suppression files, hardcoded-infrastructure noise, git environment, evidence
layout, and dependency pinning."""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests.test_render import _render
from tests.test_scanner_dependencies import ctx_with, dep
from tests.test_scanner_hardcoded_infra import _scan
from unvarnish.analysis.advisories import lookup_advisories, osv_command
from unvarnish.analysis.dependencies import _parse_cargo, _parse_pom, _parse_pyproject
from unvarnish.scanners.dependencies import DependenciesScanner, is_pinned
from unvarnish.scanners.gitleaks import gitleaks_commands
from unvarnish.scanners.hardcoded_infra import find_infra
from unvarnish.schemas.inventory import Dependencies
from unvarnish.util.gitcmd import git_env

# ---------------------------------------------------------------- C1: secrets in scanner output

GHP = "ghp_" + "Q7rT2xW9kL4mN8vB3cZ6yH1jF5dS0aPeUiOq"
GLPAT = "glpat-" + "xY7zQ2wR9tB4nM6kL1pV"
SLACK_HOOK = "https://hooks.slack.com/" + "services/T0AAAAAAA/B0BBBBBBB/xYzAbC123dEf456GhI789jKl"
# (source line, fragments that must never appear in any finding, note, summary, or excerpt)
SECRET_CASES = [
    (f'HOOK = "{SLACK_HOOK}"',
     ["xYzAbC123dEf456GhI789jKl"]),
    ('W = "https://discord.com/api/webhooks/123456789012345678/'
     'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"', ["AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"]),
    ('BLOB = "https://acct.blob.core.windows.net/c/f.csv?sv=2022-11-02&sr=b'
     '&sig=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA%3D%3D"', ["Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA"]),
    (f'API = "https://api.acme-corp.com/v1/items?access_token={GHP}"', [GHP[4:]]),
    ('DB = "postgres://admin:ab/cd@db.internal:5432/app"', ["ab/cd", "admin:ab"]),
    (f'REPO = "git+https://deploy:{GLPAT}@gitlab.acme.internal/x.git"',
     [GLPAT, "deploy:"]),
    ('DB = "mysql://admin:p@ss@db.internal/app"', ["p@ss", "admin:p"]),
    ('DB = "redis://admin:pa)ss@cache.internal:6379"', ["pa)ss", ")ss@", "admin:pa"]),
]


@pytest.mark.parametrize("line,secrets", SECRET_CASES)
def test_find_infra_values_never_carry_secrets(line, secrets):
    values = " ".join(v for _, v, _ in find_infra(line))
    assert values, "the endpoint itself is still reported"
    for s in secrets:
        assert s not in values


@pytest.mark.parametrize("line,secrets", SECRET_CASES)
def test_scrub_text_removes_secrets_from_excerpts(line, secrets):
    from unvarnish.scanners.hardcoded_infra import scrub_text

    out = scrub_text(line)
    for s in secrets:
        assert s not in out


def test_hardcoded_findings_never_carry_secrets(engagement, synthetic_repo):
    body = "\n".join(line for line, _ in SECRET_CASES) + "\n"
    _, findings = _scan(engagement, synthetic_repo, {"settings.py": body})
    assert findings
    blob = json.dumps([f.model_dump(mode="json") for f in findings])
    for _, secrets in SECRET_CASES:
        for s in secrets:
            assert s not in blob, s
    assert "hooks.slack.com" in blob  # the endpoint is still named


def test_unpinned_notes_never_carry_secrets():
    deps = Dependencies(tool="t", dependencies=[
        dep("npm", "x", f"git+https://deploy:{GLPAT}@gitlab.acme.internal/x.git",
            manifest="package.json"),
        dep("npm", "y", "https://registry.acme.internal/y.tgz?token=s3cr3tT0kenValue99",
            manifest="package.json"),
    ])
    blob = json.dumps([f.model_dump(mode="json")
                       for f in DependenciesScanner().run(ctx_with(deps))])
    assert GLPAT not in blob and "deploy:" not in blob
    assert "s3cr3tT0kenValue99" not in blob


# ---------------------------------------------------------------- C2, I3, I4, I5: osv-scanner

def test_offline_mode_disables_all_network_features(tmp_path):
    cmd = osv_command(tmp_path, {})
    assert "--offline" in cmd  # also disables deps.dev transitive resolution
    online = osv_command(tmp_path, {"offline": False})
    assert "--offline" not in online and "--offline-vulnerabilities" not in online


def test_osv_ignores_the_vetted_repos_config(tmp_path):
    cmd = osv_command(tmp_path, {}, config=tmp_path / "empty.toml")
    assert cmd[cmd.index("--config") + 1] == str(tmp_path / "empty.toml")


def _fake_run(stdout: str, stderr: str, code: int, seen: list | None = None):
    def run(cmd, **kwargs):
        if seen is not None:
            seen.append(cmd)
            cfg = cmd[cmd.index("--config") + 1]
            seen.append(Path(cfg).read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(cmd, code, stdout.encode(), stderr.encode())
    return run


PROGRESS = ("Scanning dir /src\nStarting filesystem walk for root: /\n"
            "Scanned /src/requirements.txt file and found 1 package\n"
            "End status: 1 dirs visited, 2 inodes visited, 1 Extract calls\n")


def _lookup(tmp_path, stdout="", stderr="", code=0, seen=None):
    return lookup_advisories(tmp_path, {}, which=lambda t: "/bin/osv-scanner",
                             run=_fake_run(stdout, stderr, code, seen))


def test_no_package_sources_is_checked_with_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    stderr = ("Scanning dir /src\nStarting filesystem walk for root: /\n"
              "No package sources found, --help for usage information.\n")
    assert _lookup(tmp_path, stderr=stderr, code=128) == (True, [], None)


def test_failure_note_names_the_cause_not_the_progress(tmp_path, monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    stderr = PROGRESS + (
        "could not load db for PyPI ecosystem: unable to fetch OSV database: no offline "
        "version of the OSV database is available\n"
        "Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch OSV "
        "database: no offline version of the OSV database is available\n")
    checked, advisories, note = _lookup(tmp_path, stderr=stderr, code=127)
    assert not checked and advisories == []
    assert note.startswith("osv-scanner failed: could not load db for PyPI ecosystem")


def _all_packages(*pkgs: tuple[str, str, list]) -> str:
    return json.dumps({"results": [{"source": {"path": "/src/x", "type": "lockfile"},
                                    "packages": [{"package": {"name": n, "version": "1.0",
                                                              "ecosystem": e},
                                                  "vulnerabilities": [{"id": i} for i in v],
                                                  "groups": [{"ids": [i]} for i in v]}
                                                 for n, e, v in pkgs]}]})


def test_unloaded_ecosystem_is_reported_not_silently_clean(tmp_path, monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    out = _all_packages(("flask", "PyPI", ["PYSEC-1"]), ("lodash", "npm", []))
    stderr = PROGRESS + "Loaded PyPI local db from /opt/osv/osv-scalibr/PyPI/all.zip\n"
    seen: list = []
    checked, advisories, note = _lookup(tmp_path, stdout=out, stderr=stderr, code=1, seen=seen)
    assert "--all-packages" in seen[0]
    assert checked and [a["id"] for a in advisories] == ["PYSEC-1"]
    assert note == "npm not checked: no offline database"


def test_could_not_load_line_is_reported(tmp_path, monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    out = _all_packages(("flask", "PyPI", []), ("lodash", "npm", []))
    stderr = (PROGRESS + "Loaded PyPI local db from /opt/osv/osv-scalibr/PyPI/all.zip\n"
              "could not load db for npm ecosystem: unable to fetch OSV database: corrupt\n")
    checked, _, note = _lookup(tmp_path, stdout=out, stderr=stderr, code=0)
    assert checked and note.startswith("npm not checked")


def test_lookup_passes_an_empty_config(tmp_path, monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    seen: list = []
    _lookup(tmp_path, stdout=_all_packages(), stderr="", code=0, seen=seen)
    assert seen[1].strip() == ""


def test_partial_check_renders_beside_the_count(engagement, tmp_path, monkeypatch):
    from unvarnish.phases.ingest import ingest_tool

    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    bindir = tmp_path / "osvbin"
    bindir.mkdir()
    (tmp_path / "out.json").write_text(_all_packages(("flask", "PyPI", ["PYSEC-1"]),
                                                     ("lodash", "npm", [])))
    (tmp_path / "err.txt").write_text("Loaded PyPI local db from /x/all.zip\n")
    script = bindir / "osv-scanner"
    script.write_text(f"#!/bin/sh\ncat {tmp_path / 'out.json'}\n"
                      f"cat {tmp_path / 'err.txt'} >&2\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "requirements.txt").write_text("flask==2.2.0\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    assert ("| Dependency vulnerabilities | 1 (1 medium); npm not checked: no offline database |"
            in doc)


def test_dockerfile_seeding_fails_the_build_on_a_bad_download():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    if not dockerfile.exists():
        pytest.skip("no Dockerfile (running inside the image)")
    text = dockerfile.read_text(encoding="utf-8")
    seeding = text[text.index("for eco in $OSV_ECOSYSTEMS"):]
    seeding = seeding[:seeding.index("done")]
    assert "|| exit 1" in seeding


# ---------------------------------------------------------------- I5: gitleaks suppression

def test_gitleaks_uses_its_default_rules_and_ignores_allow_comments(tmp_path):
    for cmd in gitleaks_commands(tmp_path, history=True, config=tmp_path / "gl.toml"):
        assert cmd[cmd.index("--config") + 1] == str(tmp_path / "gl.toml")
        assert "--ignore-gitleaks-allow" in cmd


def test_gitleaks_config_extends_the_default_rules():
    from unvarnish.scanners.gitleaks import GITLEAKS_CONFIG

    assert "useDefault = true" in GITLEAKS_CONFIG and "allowlist" not in GITLEAKS_CONFIG


def test_suppression_files_are_reported(engagement, synthetic_repo):
    from unvarnish.artifacts import read_artifact
    from unvarnish.schemas.scan import ScannerFindings

    ctx, _ = _scan(engagement, synthetic_repo, {
        ".gitleaksignore": "abc:app.py:stripe-access-token:1\n",
        "osv-scanner.toml": '[[IgnoredVulns]]\nid = "PYSEC-1"\n'})
    findings = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings
    f = next(f for f in findings if f.title == "Scanner suppression files in the source")
    assert {e.path for e in f.evidence} == {".gitleaksignore", "osv-scanner.toml"}
    assert ".gitleaksignore" in f.summary


# ---------------------------------------------------------------- I6: hardcoded_infra noise

FALSE_POSITIVES = [
    ("src/A.java", "java", "import com.acme.internal.util.Strings;"),
    ("src/A.java", "java", "package com.acme.internal;"),
    ("src/A.cs", "c_sharp", "namespace Acme.Corp.Internal"),
    ("src/A.cs", "c_sharp", "using Acme.Billing.Internal;"),
    ("app.py", "python", "_state = threading.local()"),
    ("app.py", "python", "from app.settings.local import DEBUG"),
    ("package.json", "json", '"packageManager": "pnpm@9.15.4"'),
    ("index.html", "html", '<img src="img/logo@2x.png">'),
    ("net.py", "python", 'MASK = "255.255.255.0"'),
    ("ua.py", "python", 'UA = "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36"'),
    ("api.py", "python", 'url = f"https://{host}/api"'),
    ("run.sh", "bash", 'curl "http://${HOST}:8080/health"'),
    ("tsconfig.json", "json", '"$schema": "https://json.schemastore.org/tsconfig"'),
    ("turbo.json", "json", '"$schema": "https://turbo.build/schema.json",'),
    ("sitemap.xml", "xml", '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'),
    ("pom.xml", "xml", 'xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 '
     'https://maven.acme-corp.com/xsd/maven-4.0.0.xsd"'),
    ("a.py", "python", "# see https://docs.python.org/3/library/os.html"),
    ("a.ts", "typescript", "// https://developer.mozilla.org/en-US/docs/Web/API"),
    ("src/app.js", "javascript", 'fetch("/data/users.json")'),
    ("Dockerfile", "dockerfile", "WORKDIR /srv/app"),
    ("Dockerfile", "dockerfile", "RUN rm -rf /var/lib/apt/lists/*"),
    (".gitignore", None, "env.local"),
    (".dockerignore", None, "settings.local"),
]


@pytest.mark.parametrize("path,language,line", FALSE_POSITIVES)
def test_false_positive_corpus(path, language, line):
    assert find_infra(line, path=path, language=language) == []


TRUE_POSITIVES = [
    ("app.py", "python", 'DB_HOST = "db.internal"', "host"),
    ("app.py", "python", 'OPS = "ops@acme-corp.com"', "email"),
    ("app.py", "python", 'SVC = "http://10.0.0.5:8080/x"', "url"),
    ("app.py", "python", 'PROXY = "10.0.12.7:3128"', "ip"),
    ("src/app.js", "javascript", 'const p = "/home/deploy/data.json"', "path"),
    ("app.py", "python", 'DATA = "/srv/app/data"', "path"),
]


@pytest.mark.parametrize("path,language,line,kind", TRUE_POSITIVES)
def test_true_positives_survive_the_filters(path, language, line, kind):
    assert [k for k, _, _ in find_infra(line, path=path, language=language)] == [kind]


# ---------------------------------------------------------------- I7: git environment

def test_git_env_keeps_the_users_ssh_command(monkeypatch):
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /keys/deploy")
    assert git_env()["GIT_SSH_COMMAND"] == "ssh -i /keys/deploy -o BatchMode=yes"


def test_git_env_leaves_git_ssh_alone(monkeypatch):
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.setenv("GIT_SSH", "/usr/local/bin/my-ssh")
    assert "GIT_SSH_COMMAND" not in git_env()


def test_git_env_extends_core_sshcommand(monkeypatch, tmp_path):
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.delenv("GIT_SSH", raising=False)
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[core]\n\tsshCommand = ssh -i /keys/ci\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    assert git_env()["GIT_SSH_COMMAND"] == "ssh -i /keys/ci -o BatchMode=yes"


def test_git_env_keeps_a_users_askpass_helper(monkeypatch):
    monkeypatch.setenv("GIT_ASKPASS", "/usr/local/bin/token-helper")
    env = git_env()
    assert env["GIT_ASKPASS"] == "/usr/local/bin/token-helper"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


# ---------------------------------------------------------------- I8: evidence layout

def test_evidence_bullets_render_one_per_line(engagement, tmp_path):
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "hosts.py").write_text('A = "10.1.0.1"\nB = "10.1.0.2"\nC = "10.1.0.3"\n')
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    section = doc.split("Hardcoded IP addresses", 1)[1].split("**Evidence.**", 1)[1]
    lines = [ln for ln in section.splitlines() if ln.startswith("- `hosts.py")]
    assert len(lines) == 3, section[:600]
    assert all(ln.count("- `hosts.py") == 1 for ln in lines)


# ---------------------------------------------------------------- I9: pinning

@pytest.mark.parametrize("rec,pinned", [
    (dep("pypi", "a", "2.2.0"), True),            # Poetry: a bare version is exact
    (dep("pypi", "a", "^2.2"), False),
    (dep("pypi", "a", "path:../lib"), True),      # local path dependency
    (dep("pypi", "a", "git:https://x/y.git#rev=abc1234"), True),
    (dep("pypi", "a", "git:https://x/y.git"), False),
    (dep("npm", "a", "=1.2.3"), True), (dep("npm", "a", "v1.2.3"), True),
    (dep("npm", "a", "npm:other@1.2.3"), True), (dep("npm", "a", "npm:other@^1.2.3"), False),
    (dep("npm", "a", "github:acme/x#3f2c1a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a"), True),
    (dep("npm", "a", "github:acme/x"), False),
    (dep("npm", "a", "workspace:*"), True), (dep("npm", "a", "file:../lib"), True),
    (dep("npm", "a", "link:../lib"), True),
    (dep("cargo", "a", "path:../lib"), True), (dep("cargo", "a", "workspace"), True),
    (dep("cargo", "a", "git:https://x/y.git#rev=abc1234"), True),
    (dep("maven", "a", None), True),               # version managed by a BOM or parent
])
def test_is_pinned_more_forms(rec, pinned):
    assert is_pinned(rec) is pinned


PARSERS = {"Cargo.toml": _parse_cargo, "pyproject.toml": _parse_pyproject, "pom.xml": _parse_pom}


def _manifest(tmp_path: Path, name: str, body: str):
    return {r.name: r.constraint for r in PARSERS[name](body, name)}


def test_cargo_and_poetry_tables_record_local_and_git_sources(tmp_path):
    cargo = _manifest(tmp_path, "Cargo.toml", '[dependencies]\nserde = "1"\n'
                      'core = { path = "../core" }\nshared = { workspace = true }\n'
                      'tool = { git = "https://x/y.git", rev = "abc1234" }\n')
    assert cargo == {"serde": "1", "core": "path:../core", "shared": "workspace",
                     "tool": "git:https://x/y.git#rev=abc1234"}
    poetry = _manifest(tmp_path, "pyproject.toml",
                       '[tool.poetry.dependencies]\npython = "^3.12"\nflask = "2.2.0"\n'
                       'lib = { path = "../lib" }\n'
                       'x = { git = "https://x/y.git", branch = "main" }\n')
    assert poetry == {"flask": "2.2.0", "lib": "path:../lib", "x": "git:https://x/y.git"}


def test_pom_dependencies_are_parsed_one_block_at_a_time(tmp_path):
    pom = """<project><dependencies>
      <dependency><groupId>org.a</groupId><artifactId>managed</artifactId></dependency>
      <dependency><groupId>org.b</groupId><artifactId>pinned</artifactId>
        <version>1.2.3</version>
        <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion>
        </exclusions></dependency>
    </dependencies></project>"""
    assert _manifest(tmp_path, "pom.xml", pom) == {"org.a:managed": None,
                                                   "org.b:pinned": "1.2.3"}


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_ignores_the_repos_allowlist_and_allow_comments(tmp_path, monkeypatch):
    from tests.test_gitleaks import STRIPE
    from unvarnish.scanners.gitleaks import run_gitleaks

    monkeypatch.delenv("UNVARNISH_DISABLE_GITLEAKS", raising=False)
    (tmp_path / "pay.py").write_text(f'A = "{STRIPE}"\nB = "{STRIPE}"  # gitleaks:allow\n')
    (tmp_path / ".gitleaks.toml").write_text('[allowlist]\npaths = ["pay.py"]\n')
    tree, _, note = run_gitleaks(tmp_path, history=False)
    assert note is None
    assert sorted(e["StartLine"] for e in tree if e["File"] == "pay.py") == [1, 2]


def test_comparison_risk_table_has_one_row_per_line(engagement, synthetic_repo):
    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.phases.compare import run_comparison

    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    doc = engagement.comparison_doc.read_text()
    table = doc.split("## 4. Risk comparison", 1)[1].split("## 5.", 1)[0]
    rows = [ln for ln in table.splitlines() if ln.startswith("|")]
    assert rows[0] == "| Measure | alpha | beta | "
    assert rows[1] == "|---|---:|---:|"
    assert len(rows) > 5 and all(ln.count("| ") <= 4 for ln in rows), table[:400]


def test_no_template_line_loses_its_newline():
    """With trim_blocks, a content line ending in a block tag joins the next line unless an
    expression follows the tag or a {{ "" }} line restores the break."""
    templates = Path(__file__).resolve().parents[1] / "src/unvarnish/render/templates"
    bad = []
    for path in sorted(templates.glob("*.j2")):
        rows = path.read_text(encoding="utf-8").split("\n")
        for i, row in enumerate(rows):
            if row.lstrip().startswith("{%") or not row.rstrip().endswith("%}"):
                continue
            if '{{ "" }}' not in "\n".join(rows[i + 1:i + 3]):
                bad.append(f"{path.name}:{i + 1}")
    assert bad == []
