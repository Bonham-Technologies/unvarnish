import json
from pathlib import Path

import pytest

from tests.conftest import LEAKED_DB_URL
from unvarnish.artifacts import read_artifact
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.hardcoded_infra import HardcodedInfraScanner, find_infra, mask_userinfo
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings

SAMPLE = """API = "https://api.acme-corp.com/v1/users"
DB_HOST = "db.internal:5432"
PROXY = "10.0.12.7:3128"
CONFIG = "/home/deploy/app/config.yaml"
OPS = "ops@acme-corp.com"
"""


def test_find_infra_kinds_and_lines():
    found = find_infra(SAMPLE)
    assert ("url", "https://api.acme-corp.com/v1/users", 1) in found
    assert ("host", "db.internal:5432", 2) in found
    assert ("ip", "10.0.12.7:3128", 3) in found
    assert ("path", "/home/deploy/app/config.yaml", 4) in found
    assert ("email", "ops@acme-corp.com", 5) in found
    assert len(found) == 5  # the host inside the URL is not counted twice


def test_benign_values_are_ignored():
    text = "\n".join([
        'a = "http://localhost:8080/x"', 'b = "127.0.0.1"', 'c = "0.0.0.0"',
        '<svg xmlns="http://www.w3.org/2000/svg">', 'd = "https://example.com/docs"',
        '"$schema": "https://json-schema.org/draft/2020-12/schema"',
        'version = "1.2.3.4"', 'e = "someone@example.org"', 'f = "/usr/bin/env"',
        'g = "https://pypi.org/project/x"', 'remote = "git@github.com:acme/x.git"',
    ])
    assert find_infra(text) == []


def test_mask_userinfo():
    assert mask_userinfo(LEAKED_DB_URL) == "postgres://***@db.internal:5432/expenses"
    assert mask_userinfo("https://api.acme.com/x") == "https://api.acme.com/x"


def _scan(engagement, synthetic_repo, files: dict[str, str]):
    from unvarnish.phases.ingest import ingest_tool

    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha")
    for rel, body in files.items():
        path = ctx.paths.source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    assert all(r.status == PhaseStatus.ok
               for r in PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase()]).run(ctx))
    findings = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data.findings
    return ctx, [f for f in findings if f.scanner == "hardcoded_infra"]


def test_url_credentials_are_masked(engagement, synthetic_repo):
    ctx, findings = _scan(engagement, synthetic_repo, {"settings.py": f'DB = "{LEAKED_DB_URL}"\n'})
    blob = json.dumps([f.model_dump(mode="json") for f in findings])
    assert "hunter2" not in blob
    assert "postgres://***@db.internal:5432/expenses" in blob


def test_findings_group_by_kind_and_cap_evidence(engagement, synthetic_repo):
    ips = "".join(f'H{i} = "10.1.0.{i}"\n' for i in range(1, 31))
    ctx, findings = _scan(engagement, synthetic_repo, {"hosts.py": ips})
    f = next(f for f in findings if f.title == "Hardcoded IP addresses")
    assert len(f.evidence) == 25 and "distinct:30" in f.tags and "hardcoded:ip" in f.tags
    assert "30 distinct" in f.summary and "first 25" in f.summary
    assert f.evidence[0].note.startswith("value: 10.1.0.")


def test_tests_are_skipped_unless_enabled(engagement, synthetic_repo):
    ctx, findings = _scan(engagement, synthetic_repo,
                          {"tests/test_api.py": 'URL = "https://api.acme-corp.com"\n'})
    assert findings == []
    census = read_artifact(ctx.paths.census, Census).data
    sctx = ScanContext(tool="alpha", source_root=ctx.source_root, census=census,
                       metrics=Metrics(tool="alpha", files=[]),
                       git=GitStats(tool="alpha", available=False),
                       dependencies=Dependencies(tool="alpha", dependencies=[]),
                       options={"include_tests": True})
    assert [f.title for f in HardcodedInfraScanner().run(sctx)] == ["Hardcoded URLs"]


def test_documents_show_hardcoded_infrastructure(engagement, synthetic_repo):
    from tests.test_render_documents import _stub
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.ingest import ingest_tool
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.rollup_modules import RollupModulesPhase
    from unvarnish.phases.rollup_tool import RollupToolPhase
    from unvarnish.phases.split import SplitPhase
    from unvarnish.phases.verify import VerifyPhase

    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    (ctx.paths.source / "settings.py").write_text(f'DB = "{LEAKED_DB_URL}"\n')
    stub = _stub()
    phases = [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(backend=stub),
              RollupModulesPhase(backend=stub), RollupToolPhase(backend=stub),
              VerifyPhase(backend=stub), RenderPhase(backend=stub)]
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(phases).run(ctx))
    findings_md = ctx.paths.findings_doc.read_text()
    assert "| Hardcoded infrastructure | 1 URL" in findings_md
    arch = ctx.paths.architecture_doc.read_text()
    assert "**Hardcoded in source (scanner)**" in arch
    assert "postgres://***@db.internal:5432/expenses" in arch and "hunter2" not in arch


def test_registered():
    assert "hardcoded_infra" in {s.name for s in builtin_scanners()}


def test_scanner_reads_with_utf8(tmp_path: Path):
    (tmp_path / "x.py").write_bytes('U = "https://café.acme-corp.com/x"\n'.encode())
    assert find_infra((tmp_path / "x.py").read_text(encoding="utf-8"))[0][0] == "url"


PYPROJECT = """[project]
name = "acme-tool"
dependencies = ["requests"]

[project.urls]
"Bug Tracker" = "https://github.com/acme/tool/issues"
Homepage = "https://github.com/acme/tool"
Repository = "https://github.com/acme/tool.git"

[[tool.uv.index]]
name = "corp"
url = "https://nexus.acme-corp.com/simple"

[tool.poetry]
homepage = "https://acme-tool.dev"
repository = "https://gitlab.acme-corp.com/acme/tool"
documentation = "https://acme-tool.dev/docs"
"api url" = "https://api2.acme-corp.com"

[tool.acme]
endpoint = "https://api.acme-corp.com/v1"
"""

PACKAGE_JSON = """{
  "name": "acme-tool",
  "homepage": "https://acme-tool.dev",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/acme/tool.git"
  },
  "bugs": {"url": "https://github.com/acme/tool/issues"},
  "funding": [
    "https://github.com/sponsors/acme"
  ],
  "config": {"repository": "https://api.acme-corp.com/v1"}
}
"""

CARGO = """[package]
name = "acme-tool"
homepage = "https://acme-tool.dev"
repository = "https://github.com/acme/tool"
documentation = "https://docs.rs/acme-tool"

[package.metadata.acme]
endpoint = "https://api.acme-corp.com/v1"
"""

SETUP_CFG = """[metadata]
name = acme-tool
url = https://github.com/acme/tool
project_urls =
    Bug Tracker = https://github.com/acme/tool/issues
    Source = https://github.com/acme/tool

[options.entry_points]
acme.endpoint = https://api.acme-corp.com/v1
"""

ISSUE_CONFIG = """blank_issues_enabled: false
contact_links:
  - name: Questions
    url: https://github.com/acme/tool/discussions
"""


def test_package_metadata_urls_are_not_infrastructure():
    def urls(text: str, path: str) -> list[str]:
        return [value for kind, value, _ in find_infra(text, path) if kind == "url"]

    assert urls(PYPROJECT, "pyproject.toml") == ["https://nexus.acme-corp.com/simple",
                                                 "https://api2.acme-corp.com",
                                                 "https://api.acme-corp.com/v1"]
    assert urls(PACKAGE_JSON, "web/package.json") == ["https://api.acme-corp.com/v1"]
    minified = ('\ufeff{"name":"x","homepage":"https://x.dev","repository":{"type":"git"},'
                '"x":{"vcs":"git","api":"https://api.acme-corp.com/v1"}}')
    assert urls(minified, "package.json") == ["https://api.acme-corp.com/v1"]
    assert urls(CARGO, "Cargo.toml") == ["https://api.acme-corp.com/v1"]
    assert urls(SETUP_CFG, "setup.cfg") == ["https://api.acme-corp.com/v1"]
    assert find_infra(ISSUE_CONFIG, ".github/ISSUE_TEMPLATE/config.yml") == []
    # the same lines anywhere else are still reported
    assert len(urls(PYPROJECT, "notes.toml")) == 9
    assert len(urls(ISSUE_CONFIG, "deploy/config.yml")) == 1
    assert len(urls(ISSUE_CONFIG, "foo.github/ISSUE_TEMPLATE/config.yml")) == 1
    assert len(urls(ISSUE_CONFIG, ".github/ISSUE_TEMPLATE/fetch.py")) == 1


ATTRIBUTE_ACCESS_LINES = [
    ("tool.py", "python", "if g.internal:"),
    ("tool.py", "python", "    return [n for n in g.nodes if n.local]"),
    ("tool.py", "python", "pair = (cfg.internal, cfg.corp)"),
    ("tool.py", "python", "ok = user.private and opts.local"),
    ("tool.ts", "typescript", "const x = net.lan;"),
    ("tool.ts", "typescript", "if (a.internal || b.corp) { go(c.local) }"),
    ("tool.go", "go", "return cfg.private == nil"),
]


@pytest.mark.parametrize(("path", "language", "line"), ATTRIBUTE_ACCESS_LINES)
def test_attribute_access_in_code_is_not_a_hostname(path, language, line):
    """UNVAR-75: `if g.internal:` is code, not a hardcoded internal hostname."""
    assert [f for f in find_infra(line, path, language) if f[0] == "host"] == []


def test_attribute_access_lines_together_yield_no_hosts():
    py = "\n".join(line for _, lang, line in ATTRIBUTE_ACCESS_LINES if lang == "python")
    assert find_infra(py, "tool.py", "python") == []
    assert find_infra("export const v = net.lan;\n", "tool.ts", "typescript") == []


@pytest.mark.parametrize(("path", "language", "text", "expected"), [
    ("tool.py", "python", 'host = "db.acme.internal"', "db.acme.internal"),
    ("tool.py", "python", "host = 'db.acme.internal'", "db.acme.internal"),
    ("tool.ts", "typescript", "const h = `db.acme.internal`;", "db.acme.internal"),
    ("tool.py", "python", '"""Talks to\nbuild.corp, the CI box."""', "build.corp"),
    ("tool.py", "python", "x = 1  # the old box was db.acme.internal", "db.acme.internal"),
    ("tool.ts", "typescript", "go(); // see build.corp", "build.corp"),
    ("deploy.yaml", "yaml", "host: db.acme.internal", "db.acme.internal"),
    ("settings.ini", "ini", "host = db.acme.internal", "db.acme.internal"),
    (".env", "dotenv", "DB_HOST=db.acme.internal", "db.acme.internal"),
    ("run.sh", "bash", "ssh build.corp", "build.corp"),
])
def test_hostnames_in_strings_comments_and_config_are_still_reported(path, language, text,
                                                                     expected):
    hosts = [f[1] for f in find_infra(text, path, language) if f[0] == "host"]
    assert hosts == [expected]


@pytest.mark.parametrize(("path", "language", "text", "expected"), [
    ("Config.kt", "kotlin", 'val cfg = """\n  host: db.acme.internal\n"""', "db.acme.internal"),
    ("Config.java", "java", 'String s = """\n    db.acme.internal,\n    """;',
     "db.acme.internal"),
    ("Jenkinsfile", "groovy", "sh '''\n  ssh build.corp\n'''", "build.corp"),
    ("tool.c", "c", "/*/ the old box\nbuild.corp;\n*/", "build.corp"),
    ("config.rb", "ruby", "cfg = <<~EOS\n  host: db.acme.internal\nEOS", "db.acme.internal"),
    ("hosts.rb", "ruby", "HOSTS = %w[build.corp]", "build.corp"),
    ("hosts.lua", "lua", "--[[ hosts\n db.acme.internal,\n]]", "db.acme.internal"),
    ("page.php", "php", "<?php ?>\n<a>db.acme.internal</a>", "db.acme.internal"),
    ("App.jsx", "javascript", "return <p>Use db.acme.internal</p>", "db.acme.internal"),
])
def test_multiline_strings_heredocs_and_markup_still_report_hosts(path, language, text,
                                                                  expected):
    """UNVAR-75 review: text the lexer would misread as code still reports its hostname."""
    hosts = [f[1] for f in find_infra(text, path, language) if f[0] == "host"]
    assert hosts == [expected]


def test_the_same_value_twice_on_one_line_is_one_location(engagement, synthetic_repo):
    # UNVAR-82: a value repeated on one line (an href and its link text, say) gave two
    # identical evidence rows, used up the evidence cap and inflated the location count.
    body = 'p = "/opt/app/data /opt/app/data"\nq = "/srv/a /srv/b"\n'
    _, findings = _scan(engagement, synthetic_repo, {"m.py": body})
    f = next(f for f in findings if f.title == "Hardcoded absolute file paths")
    rows = [(e.path, e.line_start, e.note) for e in f.evidence]
    assert len(rows) == len(set(rows)) == 3, rows
    assert ("m.py", 1, "value: /opt/app/data") in rows
    # Three distinct values, on two distinct lines.
    assert f.summary.startswith("3 distinct absolute paths hardcoded at 2 locations,"), f.summary


def test_a_value_once_per_line_keeps_its_finding_id(engagement, synthetic_repo):
    # Deduplicating evidence must not move the id of a finding it does not change.
    from unvarnish.schemas.finding import compute_finding_id

    _, findings = _scan(engagement, synthetic_repo, {"m.py": 'p = "/opt/app/data"\n'})
    f = next(f for f in findings if f.title == "Hardcoded absolute file paths")
    assert f.id == compute_finding_id("alpha", f.category, f.title, f.evidence[0])
    assert f.summary.startswith("1 distinct absolute path hardcoded at 1 location,")
