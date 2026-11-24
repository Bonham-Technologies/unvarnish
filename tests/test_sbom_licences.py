"""CycloneDX SBOM export and dependency licences (UNVAR-93).

`export --format cyclonedx` writes one CycloneDX 1.6 document per tool from dependencies.json
and its advisories, without running osv-scanner. Licences come from osv-scanner's deps.dev data
in online mode only; offline, nothing is invented and the documents say they were not checked.
Every osv-scanner call here is stubbed: no test touches the network."""

import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from typer.testing import CliRunner

from unvarnish.analysis.advisories import (
    lookup_advisories,
    lookup_dependencies,
    osv_command,
    parse_licences,
)
from unvarnish.analysis.licences import attach_licences, satisfied
from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.cli import app
from unvarnish.export.exporter import DATA_FORMATS, FORMATS, export_engagement
from unvarnish.phases.base import build_context
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.dependencies import DependenciesScanner
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    DependencyRecord,
    Metrics,
    PackageLicences,
)

runner = CliRunner()
HERE = Path(__file__).parent
STAMP = "20261124-120000"


def _schema_validator() -> Draft7Validator:
    """The CycloneDX 1.6 JSON schema, with the SPDX and JSF schemas it references."""
    resources = []
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((HERE / "cyclonedx" / name).read_text(encoding="utf-8"))
        resources.append((doc["$id"], Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)
    bom = json.loads((HERE / "cyclonedx" / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    return Draft7Validator(bom, registry=registry)


VALIDATOR = _schema_validator()


def schema_errors(doc: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}"
            for e in VALIDATOR.iter_errors(doc)]


# --- osv-scanner stubs --------------------------------------------------------------------------

def osv_report(root: Path, licences: dict[str, list[str]] | None = None) -> dict:
    """flask 2.3.2 with one advisory and requests 2.31.0 without, both from requirements.txt;
    `licences` adds deps.dev's licences per package name, as `--licenses` does."""
    licences = licences or {}

    def pkg(name: str, version: str, **extra) -> dict:
        out = {"package": {"name": name, "version": version, "ecosystem": "PyPI"}, **extra}
        if name in licences:
            out["licenses"] = licences[name]
        return out

    return {"results": [{"source": {"path": str(root / "requirements.txt"),
                                    "type": "lockfile"},
                         "packages": [
                             pkg("flask", "2.3.2", vulnerabilities=[
                                 {"id": "GHSA-m2qf-hxjv-5gpq", "aliases": ["CVE-2023-30861"],
                                  "summary": "Flask session cookie disclosure",
                                  "database_specific": {"severity": "HIGH"}}],
                                 groups=[{"ids": ["GHSA-m2qf-hxjv-5gpq"],
                                          "aliases": ["CVE-2023-30861"],
                                          "max_severity": "7.5"}]),
                             # osv-scanner's own verdict is ignored: Unvarnish applies its
                             # allowlist itself, so a config the repo ships cannot clear it
                             pkg("requests", "2.31.0", license_violations=[]),
                         ]}]}


def fake_run(report: dict, seen: list[list[str]] | None = None, configs: list[str] | None = None):
    def run(cmd, **kw):
        if seen is not None:
            seen.append(list(cmd))
        if configs is not None and "--config" in cmd:
            configs.append(Path(cmd[cmd.index("--config") + 1]).read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(cmd, 1, json.dumps(report).encode(), b"")
    return run


def _which(tool: str) -> str:
    return "/bin/" + tool


@pytest.fixture
def osv_enabled(monkeypatch):
    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)


# --- osv-scanner: licences only online ----------------------------------------------------------

def test_online_asks_osv_scanner_for_licences_and_every_package(tmp_path):
    online = osv_command(tmp_path, {"offline": False}, config=tmp_path / "c.toml")
    assert "--licenses" in online and "--all-packages" in online
    # the allowlist is never handed to osv-scanner: Unvarnish applies it itself
    allow = osv_command(tmp_path, {"offline": False, "licences": ["MIT"]})
    assert not [a for a in allow if a.startswith("--licenses=") or a == "MIT"]
    offline = osv_command(tmp_path, {})
    assert "--licenses" not in offline and "--offline" in offline


def test_parse_licences_lists_every_package_with_its_licences(tmp_path):
    report = osv_report(tmp_path, {"flask": ["BSD-3-Clause"], "requests": []})
    assert parse_licences(report, tmp_path) == [
        {"ecosystem": "PyPI", "name": "flask", "version": "2.3.2",
         "manifest": "requirements.txt", "licences": ["BSD-3-Clause"]},
        {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
         "manifest": "requirements.txt", "licences": []},
    ]


def test_lookup_returns_licences_online_and_none_offline(tmp_path, osv_enabled):
    report = osv_report(tmp_path, {"flask": ["BSD-3-Clause"], "requests": ["Apache-2.0"]})
    online = lookup_dependencies(tmp_path, {"offline": False}, which=_which,
                                 run=fake_run(report))
    assert online.checked and online.advisories[0]["id"] == "GHSA-m2qf-hxjv-5gpq"
    assert [p["licences"] for p in online.packages] == [["BSD-3-Clause"], ["Apache-2.0"]]
    offline = lookup_dependencies(tmp_path, {}, which=_which, run=fake_run(report))
    assert offline.checked and offline.packages is None
    # the three-value form callers already use is unchanged
    assert lookup_advisories(tmp_path, {}, which=_which, run=fake_run(report))[0] is True


def test_repo_osv_config_cannot_override_licences(tmp_path, osv_enabled):
    """The vetted repo's osv-scanner.toml can override or ignore a package's licence; osv-scanner
    is always given Unvarnish's own empty config instead (as for advisories, UNVAR-66)."""
    (tmp_path / "osv-scanner.toml").write_text(
        '[[PackageOverrides]]\nname = "requests"\nlicense.override = ["MIT"]\n'
        '[[PackageOverrides]]\nname = "flask"\nlicense.ignore = true\n', encoding="utf-8")
    seen: list[list[str]] = []
    configs: list[str] = []
    report = osv_report(tmp_path, {"requests": ["GPL-3.0"]})
    lookup_dependencies(tmp_path, {"offline": False}, which=_which,
                        run=fake_run(report, seen, configs))
    cmd = seen[0]
    config = Path(cmd[cmd.index("--config") + 1])
    assert config.parent != tmp_path and configs == [""]
    assert cmd.count("--config") == 1


# --- joining licences to the declared dependencies ----------------------------------------------

def test_attach_licences_joins_by_ecosystem_name_and_folder():
    records = [DependencyRecord(ecosystem="pypi", name="flask", constraint="==2.3.2",
                                manifest="requirements.txt"),
               DependencyRecord(ecosystem="pypi", name="typing_extensions", constraint=None,
                                manifest="svc/pyproject.toml"),
               DependencyRecord(ecosystem="npm", name="left-pad", constraint="^1",
                                manifest="web/package.json")]
    packages = [{"ecosystem": "PyPI", "name": "Flask", "version": "2.3.2",
                 "manifest": "requirements.txt", "licences": ["BSD-3-Clause"]},
                {"ecosystem": "PyPI", "name": "typing-extensions", "version": "4.0",
                 "manifest": "svc/poetry.lock", "licences": ["PSF-2.0"]},
                {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0",
                 "manifest": "other/package-lock.json", "licences": ["WTFPL"]}]
    out = attach_licences(records, packages)
    assert [r.licences for r in out] == [["BSD-3-Clause"], ["PSF-2.0"], None]


@pytest.mark.parametrize(("expr", "ok"), [
    ("MIT", True), ("mit", True), ("GPL-3.0", False), ("MIT OR GPL-3.0", True),
    ("MIT AND GPL-3.0", False), ("(MIT OR GPL-3.0) AND Apache-2.0", True),
    ("GPL-2.0 WITH Classpath-exception-2.0", False), ("Apache-2.0 WITH LLVM-exception", True),
    ("MIT OR", False), ("((MIT)", False),
])
def test_licence_expressions_are_evaluated_against_the_allowlist(expr, ok):
    allow = {"mit", "apache-2.0"}
    assert satisfied(expr, lambda i: i.lower() in allow) is ok


# --- the inventory stores licences online and nothing offline -----------------------------------

def _inventory(eng, tool, monkeypatch, report_for, options: dict | None = None) -> Dependencies:
    if options is not None:
        eng.config.scanners["dependencies"].update(options)
    ctx = build_context(eng, tool)
    run = fake_run(report_for(ctx.source_root))
    monkeypatch.setattr("unvarnish.phases.inventory.lookup_dependencies",
                        lambda root, options: lookup_dependencies(root, options, which=_which,
                                                                  run=run))
    InventoryPhase().run(ctx)
    return read_artifact(ctx.paths.dependencies, Dependencies).data


def test_inventory_online_records_licences(ingested, monkeypatch, osv_enabled):
    eng, tool = ingested
    deps = _inventory(eng, tool, monkeypatch,
                      lambda root: osv_report(root, {"flask": ["BSD-3-Clause"],
                                                     "requests": ["Apache-2.0"]}),
                      {"offline": False})
    assert deps.licences_checked and deps.licences_note is None
    by_name = {r.name: r.licences for r in deps.dependencies}
    assert by_name == {"flask": ["BSD-3-Clause"], "requests": ["Apache-2.0"]}
    assert {p.name for p in deps.packages} == {"flask", "requests"}


def test_inventory_offline_invents_no_licence(ingested, monkeypatch, osv_enabled):
    eng, tool = ingested
    deps = _inventory(eng, tool, monkeypatch,
                      lambda root: osv_report(root, {"flask": ["BSD-3-Clause"]}))
    assert not deps.licences_checked and deps.licences_note is None
    assert all(r.licences is None for r in deps.dependencies) and deps.packages == []
    raw = build_context(eng, tool).paths.dependencies.read_text(encoding="utf-8")
    assert "licence" not in raw and "BSD-3-Clause" not in raw


def test_inventory_hash_changes_online_only(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    offline = InventoryPhase().inputs_hash(ctx)
    eng.config.scanners["dependencies"]["offline"] = False
    online = InventoryPhase().inputs_hash(ctx)
    assert offline != online


# --- the compliance finding ---------------------------------------------------------------------

def _scan_ctx(deps: Dependencies, options: dict) -> ScanContext:
    return ScanContext(tool="svc", source_root=Path("/nonexistent"),
                       census=Census(tool="svc", files=[], totals=CensusTotals()),
                       metrics=Metrics(tool="svc", files=[]),
                       git=GitStats(tool="svc", available=False, reason="test"),
                       dependencies=deps, options=options)


def _online_deps(licences: dict[str, list[str]]) -> Dependencies:
    packages = [{"ecosystem": "PyPI", "name": n, "version": "1.0",
                 "manifest": "requirements.txt", "licences": lic}
                for n, lic in licences.items()]
    records = [DependencyRecord(ecosystem="pypi", name=n, constraint="==1.0",
                                manifest="requirements.txt") for n in licences]
    return Dependencies(tool="svc", dependencies=attach_licences(records, packages),
                        advisories_checked=True, licences_checked=True, packages=packages)


def _licence_findings(deps: Dependencies, options: dict):
    scanner = DependenciesScanner()
    found = [f for f in scanner.run(_scan_ctx(deps, options)) if "licence" in f.tags]
    return found, scanner.notes


def test_gpl_dependency_outside_the_allowlist_is_a_compliance_finding():
    deps = _online_deps({"flask": ["BSD-3-Clause"], "gplthing": ["GPL-3.0"],
                         "mystery": [], "odd": ["Zlib"]})
    found, notes = _licence_findings(
        deps, {"offline": False, "licences": ["MIT", "BSD-3-Clause", "Apache-2.0"]})
    gpl = next(f for f in found if "GPL-3.0" in f.title)
    assert gpl.category == Category.compliance and gpl.severity == Severity.medium
    assert "gplthing" in gpl.summary and "requirements.txt" in gpl.summary
    assert gpl.evidence[0].path == "requirements.txt"
    assert gpl.effort is not None
    others = {f.title: f.severity for f in found if f is not gpl}
    assert set(others.values()) == {Severity.low} and len(others) == 2  # Zlib, unknown
    assert not any("flask" in f.summary for f in found)
    assert not [n for n in notes if "licences" in n]


def test_no_allowlist_flags_nothing_and_says_so():
    found, notes = _licence_findings(_online_deps({"gplthing": ["GPL-3.0"]}),
                                     {"offline": False})
    assert found == []
    assert [n for n in notes if "licences: checked" in n and "allowlist" in n]


def test_a_bad_allowlist_is_a_note_not_a_crash():
    found, notes = _licence_findings(_online_deps({"gplthing": ["GPL-3.0"]}),
                                     {"offline": False, "licences": "MIT"})
    assert found == [] and [n for n in notes if "scanners.dependencies.licences" in n]


def test_offline_says_licences_not_checked():
    deps = Dependencies(tool="svc", dependencies=[DependencyRecord(
        ecosystem="pypi", name="flask", constraint="==2.3.2", manifest="requirements.txt")],
    )
    found, notes = _licence_findings(deps, {"offline": True, "licences": ["MIT"]})
    assert found == []
    [note] = [n for n in notes if "licences" in n]
    assert note.startswith("dependencies: licences: not checked (offline mode)")


def test_no_dependencies_no_licence_note():
    _, notes = _licence_findings(Dependencies(tool="svc", dependencies=[]), {})
    assert not [n for n in notes if "licences" in n]


def test_findings_document_says_licences_not_checked(ingested, monkeypatch):
    from unvarnish.phases.base import PhaseRunner
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    eng, tool = ingested
    ctx = build_context(eng, tool)
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "dependencies: licences: not checked (offline mode)" in doc.split(
        "## Not analysed", 1)[1]


# --- the SBOM ----------------------------------------------------------------------------------

@pytest.fixture
def sbom_tool(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    ctx = build_context(engagement, "alpha")
    deps = Dependencies(
        tool="alpha",
        dependencies=[
            DependencyRecord(ecosystem="pypi", name="flask", constraint="==2.3.2",
                             manifest="requirements.txt"),
            DependencyRecord(ecosystem="pypi", name="requests", constraint=">=2.31",
                             manifest="requirements.txt"),
            DependencyRecord(ecosystem="npm", name="@scope/ui", constraint="1.2.3",
                             manifest="web/package.json", dev=True),
            DependencyRecord(ecosystem="go", name="github.com/gin-gonic/gin",
                             constraint="v1.9.1", manifest="go.mod"),
            DependencyRecord(ecosystem="maven", name="org.apache.logging.log4j:log4j-core",
                             constraint="2.14.1", manifest="pom.xml"),
            DependencyRecord(ecosystem="cargo", name="serde", constraint="1",
                             manifest="Cargo.toml"),
        ],
        advisories_checked=True,
        advisories=[
            {"id": "GHSA-m2qf-hxjv-5gpq", "ids": ["GHSA-m2qf-hxjv-5gpq", "CVE-2023-30861"],
             "package": "flask", "version": "2.3.2", "ecosystem": "PyPI",
             "manifest": "requirements.txt", "summary": "Flask session cookie disclosure",
             "severity": "high"},
            {"id": "GHSA-jfh8-c2jp-5v3q", "ids": ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"],
             "package": "org.apache.logging.log4j:log4j-core", "version": "2.14.1",
             "ecosystem": "Maven", "manifest": "pom.xml", "summary": "Log4Shell",
             "severity": "critical", "kev": True, "kev_date_added": "2021-12-10",
             "epss": 0.94358, "epss_percentile": 0.99971},
            # a transitive package from a lockfile, not declared in any manifest
            {"id": "GHSA-xxxx-yyyy-zzzz", "ids": ["GHSA-xxxx-yyyy-zzzz"],
             "package": "urllib3", "version": "1.26.0", "ecosystem": "PyPI",
             "manifest": "requirements.txt", "summary": "", "severity": "medium"},
        ])
    write_artifact(ctx.paths.dependencies, deps, produced_by="inventory", inputs_hash="x")
    return engagement


def _sbom(eng) -> dict:
    [path] = eng.exports_dir.glob("sbom-alpha-*.cdx.json")
    return json.loads(path.read_text(encoding="utf-8"))


def test_validator_is_not_vacuous():
    assert schema_errors({"bomFormat": "CycloneDX", "specVersion": "1.6"}) == []
    assert schema_errors({"bomFormat": "CycloneDX"})  # specVersion is required
    assert schema_errors({"bomFormat": "CycloneDX", "specVersion": "1.6",
                          "components": [{"type": "library"}]})  # name is required
    assert schema_errors({"bomFormat": "CycloneDX", "specVersion": "1.6",
                          "components": [{"type": "library", "name": "x",
                                          "licenses": [{"license": {"id": "NOT-SPDX"}}]}]})


def test_cyclonedx_export_writes_a_valid_sbom(sbom_tool):
    out = runner.invoke(app, ["export", "--format", "cyclonedx", "-e", str(sbom_tool.root)])
    assert out.exit_code == 0, out.output
    [path] = sbom_tool.exports_dir.glob("sbom-alpha-*.cdx.json")
    assert path.name.startswith("sbom-alpha-2") and path.name.endswith(".cdx.json")
    doc = _sbom(sbom_tool)
    assert schema_errors(doc) == []
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["name"] == "alpha"


def test_components_carry_purl_version_or_constraint_and_manifest(sbom_tool):
    report = export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                               template=None, timestamp=STAMP)
    assert [(i.doc, i.fmt, i.status) for i in report.items] == [("sbom", "cyclonedx", "ok")]
    assert report.items[0].path == f"exports/sbom-alpha-{STAMP}.cdx.json"
    doc = _sbom(sbom_tool)
    comps = {c["name"]: c for c in doc["components"]}
    props = {n: {p["name"]: p["value"] for p in c.get("properties", [])}
             for n, c in comps.items()}
    assert comps["flask"]["purl"] == "pkg:pypi/flask@2.3.2"
    assert comps["flask"]["version"] == "2.3.2"
    assert props["flask"]["unvarnish:manifest"] == "requirements.txt"
    assert comps["requests"]["purl"] == "pkg:pypi/requests" and "version" not in comps["requests"]
    assert props["requests"]["unvarnish:constraint"] == ">=2.31"
    assert comps["ui"]["group"] == "@scope" and comps["ui"]["purl"] == "pkg:npm/%40scope/ui@1.2.3"
    assert comps["ui"]["scope"] == "optional" and comps["flask"]["scope"] == "required"
    assert comps["github.com/gin-gonic/gin"]["purl"] == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
    assert comps["log4j-core"]["purl"] == (
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert comps["serde"]["purl"] == "pkg:cargo/serde" and "version" not in comps["serde"]
    assert props["serde"]["unvarnish:manifest"] == "Cargo.toml"
    # the undeclared package an advisory names is listed too, at its resolved version
    assert comps["urllib3"]["purl"] == "pkg:pypi/urllib3@1.26.0"
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))


def test_advisories_are_vulnerabilities_affecting_their_component(sbom_tool):
    export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                      template=None, timestamp=STAMP)
    doc = _sbom(sbom_tool)
    ref = {c["name"]: c["bom-ref"] for c in doc["components"]}
    vulns = {v["id"]: v for v in doc["vulnerabilities"]}
    flask = vulns["GHSA-m2qf-hxjv-5gpq"]
    assert flask["source"]["name"] == "OSV"
    assert flask["ratings"][0]["severity"] == "high"
    assert flask["affects"] == [{"ref": ref["flask"],
                                 "versions": [{"version": "2.3.2", "status": "affected"}]}]
    assert {r["id"] for r in flask["references"]} == {"CVE-2023-30861"}
    assert flask["description"] == "Flask session cookie disclosure"
    log4j = vulns["GHSA-jfh8-c2jp-5v3q"]
    assert log4j["ratings"][0]["severity"] == "critical"
    assert log4j["affects"][0]["ref"] == ref["log4j-core"]
    props = {p["name"]: p["value"] for p in log4j["properties"]}
    assert props["unvarnish:kev_date_added"] == "2021-12-10"
    assert vulns["GHSA-xxxx-yyyy-zzzz"]["affects"][0]["ref"] == ref["urllib3"]


def test_offline_sbom_invents_no_licence_and_says_not_checked(sbom_tool):
    report = export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                               template=None, timestamp=STAMP)
    doc = _sbom(sbom_tool)
    assert not any("licenses" in c for c in doc["components"])
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["unvarnish:licences"] == "not checked (offline mode)"
    assert "licences: not checked" in report.items[0].detail


def test_online_sbom_carries_licences_and_stays_valid(sbom_tool):
    ctx = build_context(sbom_tool, "alpha")
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    packages = [{"ecosystem": "PyPI", "name": "flask", "version": "2.3.2",
                 "manifest": "requirements.txt", "licences": ["BSD-3-Clause"]},
                {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                 "manifest": "requirements.txt", "licences": ["Apache-2.0", "non-standard"]},
                {"ecosystem": "PyPI", "name": "idna", "version": "3.4",
                 "manifest": "requirements.txt", "licences": ["MIT OR Apache-2.0"]}]
    deps = deps.model_copy(update={
        "dependencies": attach_licences(deps.dependencies, packages),
        "packages": [PackageLicences(**p) for p in packages], "licences_checked": True,
        "licences_note": None})
    write_artifact(ctx.paths.dependencies, deps, produced_by="inventory", inputs_hash="x")
    export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                      template=None, timestamp=STAMP)
    doc = _sbom(sbom_tool)
    assert schema_errors(doc) == []
    comps = {c["name"]: c for c in doc["components"]}
    assert comps["flask"]["licenses"] == [{"expression": "BSD-3-Clause",
                                           "acknowledgement": "declared"}]
    assert comps["requests"]["licenses"] == [
        {"license": {"name": "Apache-2.0", "acknowledgement": "declared"}},
        {"license": {"name": "non-standard", "acknowledgement": "declared"}}]
    # a resolved package no manifest declares is listed with its licence
    assert comps["idna"]["licenses"] == [{"expression": "MIT OR Apache-2.0",
                                          "acknowledgement": "declared"}]
    assert comps["idna"]["purl"] == "pkg:pypi/idna@3.4"
    assert "serde" in comps and "licenses" not in comps["serde"]  # deps.dev had nothing
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["unvarnish:licences"] == "checked (deps.dev, through osv-scanner)"


def test_cyclonedx_is_opt_in(sbom_tool, monkeypatch):
    from unvarnish.export import exporter as exporter_module

    assert FORMATS == ("docx", "html", "pdf") and DATA_FORMATS == ("sarif", "csv")
    md = sbom_tool.tool_paths("alpha").findings_doc
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text("# Findings\n\nNone.\n", encoding="utf-8")

    def fake_pandoc(cmd):
        Path(cmd[cmd.index("-o") + 1]).write_bytes(b"converted")

    monkeypatch.setattr(exporter_module, "run_pandoc", fake_pandoc)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    for args in ([], ["--format", "all"]):
        out = runner.invoke(app, ["export", *args, "-e", str(sbom_tool.root)])
        assert out.exit_code == 0, out.output
        assert not list(sbom_tool.exports_dir.glob("*.cdx.json"))
    out = runner.invoke(app, ["export", "--format", "all", "--format", "cyclonedx",
                              "-e", str(sbom_tool.root)])
    assert out.exit_code == 0, out.output
    assert len(list(sbom_tool.exports_dir.glob("sbom-alpha-*.cdx.json"))) == 1


def test_cyclonedx_needs_no_pandoc_and_no_findings_document(sbom_tool, monkeypatch):
    from unvarnish.export import exporter as exporter_module

    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: None)
    out = runner.invoke(app, ["export", "--format", "cyclonedx", "--doc", "architecture",
                              "-e", str(sbom_tool.root)])
    assert out.exit_code == 0, out.output
    assert len(list(sbom_tool.exports_dir.glob("sbom-alpha-*.cdx.json"))) == 1


def test_cyclonedx_runs_no_osv_scanner(sbom_tool, monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("osv-scanner called at export time")

    monkeypatch.setattr("unvarnish.analysis.advisories.lookup_dependencies", refuse)
    monkeypatch.setattr("unvarnish.analysis.advisories.shutil.which", refuse)
    report = export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                               template=None, timestamp=STAMP)
    assert report.items[0].status == "ok"


def test_cyclonedx_skips_a_tool_without_an_inventory(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    report = export_engagement(engagement, formats=["cyclonedx"], docs=None, tools=["alpha"],
                               template=None, timestamp=STAMP)
    assert [(i.status, i.fmt) for i in report.items] == [("skipped", "cyclonedx")]
    assert "dependencies.json" in report.items[0].detail


def test_two_exports_in_one_second_do_not_overwrite(sbom_tool):
    for _ in range(2):
        export_engagement(sbom_tool, formats=["cyclonedx"], docs=None, tools=["alpha"],
                          template=None, timestamp=STAMP)
    names = sorted(p.name for p in sbom_tool.exports_dir.glob("sbom-alpha-*"))
    assert names == [f"sbom-alpha-{STAMP}-2.cdx.json", f"sbom-alpha-{STAMP}.cdx.json"]
