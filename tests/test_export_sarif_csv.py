"""SARIF 2.1.0 and CSV exports of each tool's findings (UNVAR-41)."""

import csv
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import unvarnish
from unvarnish.artifacts import write_artifact
from unvarnish.cli import app
from unvarnish.export import exporter as exporter_module
from unvarnish.export import findings_data
from unvarnish.export.exporter import FORMATS, export_engagement
from unvarnish.phases.ingest import ingest_tool
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source, Verification
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.verify import ModelFindings

runner = CliRunner()
SCHEMA = json.loads((Path(__file__).parent / "sarif-schema-2.1.0.json")
                    .read_text(encoding="utf-8"))
# Built at runtime so no secret-shaped literal sits in the repository.
PLANTED = "AKIA" + "Q7Z3V5X2W9R4T6YM"[::-1]


# --- a minimal JSON Schema (draft-04) validator over the keywords the SARIF schema uses ------

def _is(inst, t: str) -> bool:
    return {
        "object": isinstance(inst, dict), "array": isinstance(inst, list),
        "string": isinstance(inst, str), "boolean": isinstance(inst, bool),
        "integer": isinstance(inst, int) and not isinstance(inst, bool),
        "number": isinstance(inst, int | float) and not isinstance(inst, bool),
        "null": inst is None,
    }[t]


def schema_errors(inst, schema: dict, path: str = "$") -> list[str]:
    """Every violation of `schema` (type, $ref, required, properties, additionalProperties,
    items, minItems, uniqueItems, enum, minimum, maximum, pattern, anyOf, oneOf)."""
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/definitions/"), ref
        return schema_errors(inst, SCHEMA["definitions"][ref.rsplit("/", 1)[1]], path)
    t = schema.get("type")
    if t is not None and not any(_is(inst, x) for x in ([t] if isinstance(t, str) else t)):
        return [f"{path}: expected {t}, got {type(inst).__name__}"]
    errs: list[str] = []
    if "enum" in schema and inst not in schema["enum"]:
        errs.append(f"{path}: {inst!r} not in {schema['enum']}")
    if isinstance(inst, dict):
        errs += [f"{path}: missing {r}" for r in schema.get("required", []) if r not in inst]
        props, extra = schema.get("properties", {}), schema.get("additionalProperties", True)
        for k, v in inst.items():
            if k in props:
                errs += schema_errors(v, props[k], f"{path}.{k}")
            elif extra is False:
                errs.append(f"{path}: unexpected property {k}")
            elif isinstance(extra, dict):
                errs += schema_errors(v, extra, f"{path}.{k}")
    if isinstance(inst, list):
        if len(inst) < schema.get("minItems", 0):
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems") and len({json.dumps(i, sort_keys=True)
                                              for i in inst}) != len(inst):
            errs.append(f"{path}: items not unique")
        if "items" in schema:
            for i, v in enumerate(inst):
                errs += schema_errors(v, schema["items"], f"{path}[{i}]")
    if _is(inst, "number"):
        if "minimum" in schema and inst < schema["minimum"]:
            errs.append(f"{path}: {inst} < {schema['minimum']}")
        if "maximum" in schema and inst > schema["maximum"]:
            errs.append(f"{path}: {inst} > {schema['maximum']}")
    if isinstance(inst, str) and "pattern" in schema and not re.search(schema["pattern"], inst):
        errs.append(f"{path}: {inst!r} does not match {schema['pattern']}")
    if "anyOf" in schema and all(schema_errors(inst, s, path) for s in schema["anyOf"]):
        errs.append(f"{path}: matches none of anyOf")
    if "oneOf" in schema and sum(not schema_errors(inst, s, path)
                                 for s in schema["oneOf"]) != 1:
        errs.append(f"{path}: does not match exactly one of oneOf")
    return errs


# --- fixtures ---------------------------------------------------------------------------------

def _finding(**kw) -> Finding:
    base = dict(tool="alpha", category=Category.security, severity=Severity.high,
                title="SQL query built from request input",
                summary="The search handler formats the query string into SQL.",
                impact="Anyone who can search can read or change any row.",
                remediation="Use bound parameters.",
                evidence=[Evidence(path="app/db.py", line_start=10, line_end=12,
                                   excerpt='cur.execute(f"... {q}")')],
                source=Source.model, verification=Verification.confirmed, confidence=0.9)
    return Finding(**{**base, **kw})


def _write_findings(eng, tool: str, scan: list[Finding], model: list[Finding] | None) -> None:
    p = eng.tool_paths(tool)
    write_artifact(p.scanner_findings, ScannerFindings(tool=tool, findings=scan),
                   produced_by="test", inputs_hash="x")
    if model is not None:
        write_artifact(p.model_findings, ModelFindings(tool=tool, findings=model),
                       produced_by="test", inputs_hash="x")


SCAN = [
    _finding(source=Source.scanner, scanner="secrets", verification=None, confidence=None,
             severity=Severity.critical, title="AWS access key in source",
             summary="An AWS access key is committed.", remediation="Rotate it.",
             evidence=[Evidence(path="config/settings.py", line_start=3,
                                excerpt="KEY = AKIA…[redacted 20 chars]")]),
    _finding(source=Source.scanner, scanner="bus_factor", verification=None, confidence=None,
             category=Category.process, severity=Severity.medium, title="Bus factor of one",
             summary="One author wrote 97% of the code.", impact="Knowledge risk.",
             remediation="Pair a second maintainer.",
             evidence=[Evidence(path=".", note="repository root")]),
]
MODEL = [
    _finding(),
    _finding(severity=Severity.low, verification=Verification.downgraded,
             evidence=[Evidence(path="app/report search.py", line_start=40),
                       Evidence(path="app/views.py", line_start=7, line_end=9, note="caller")]),
    _finding(title="Admin route without authentication", severity=Severity.high,
             verification=Verification.rejected, summary="Rejected by the verifier.",
             evidence=[Evidence(path="app/admin.py", line_start=1)]),
    _finding(title="Unhandled file read error", category=Category.reliability,
             severity=Severity.info, verification=None, confidence=None,
             evidence=[Evidence(path="app/io.py")]),
]
REJECTED_ID = MODEL[2].id


@pytest.fixture
def tool(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    _write_findings(engagement, "alpha", SCAN, MODEL)
    return engagement


def _export(eng, formats, **kw):
    return export_engagement(eng, formats=formats, docs=kw.pop("docs", None),
                             tools=kw.pop("tools", ["alpha"]), template=None,
                             timestamp="20261108-120000", **kw)


def _sarif(eng) -> dict:
    return json.loads(next(eng.exports_dir.glob("*.sarif")).read_text(encoding="utf-8"))


# --- SARIF ------------------------------------------------------------------------------------

def test_validator_is_not_vacuous():
    assert schema_errors({"version": "2.1.0", "runs": []}, SCHEMA) == []
    assert schema_errors({"runs": []}, SCHEMA)  # version is required
    bad = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}},
                                         "results": [{"message": {"text": "m"},
                                                      "level": "fatal"}]}]}
    assert any("fatal" in e for e in schema_errors(bad, SCHEMA))


def test_sarif_validates_against_the_oasis_schema(tool):
    report = _export(tool, ["sarif"])
    assert [(i.doc, i.tool, i.fmt, i.status) for i in report.items] == [
        ("findings", "alpha", "sarif", "ok")]
    assert report.items[0].path == "exports/findings-alpha-20261108-120000.sarif"
    assert schema_errors(_sarif(tool), SCHEMA) == []


def test_sarif_carries_what_github_requires(tool):
    _export(tool, ["sarif"])
    doc = _sarif(tool)
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json") and doc["version"] == "2.1.0"
    [run] = doc["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Unvarnish" and driver["version"] == unvarnish.__version__
    assert run["automationDetails"]["id"] == "unvarnish/alpha/"
    for rule in driver["rules"]:
        assert rule["id"] and rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"] and rule["help"]["text"]
    results = run["results"]
    ids = [r["partialFingerprints"]["unvarnishFindingId"] for r in results]
    assert REJECTED_ID not in ids  # rejected findings are left out, as in the documents
    assert sorted(ids) == sorted(f.id for f in SCAN + MODEL if f.id != REJECTED_ID)
    for r in results:
        assert driver["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["message"]["text"]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    by_id = dict(zip(ids, results, strict=True))
    top = by_id[MODEL[0].id]
    assert top["level"] == "error"
    assert top["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 10, "endLine": 12, "snippet": {"text": 'cur.execute(f"... {q}")'}}
    assert top["properties"] == {"severity": "high", "source": "model", "category": "security",
                                 "verification": "confirmed", "confidence": 0.9}
    low = by_id[MODEL[1].id]
    assert low["level"] == "note" and low["properties"]["verification"] == "downgraded"
    loc = low["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/report%20search.py"
    assert low["relatedLocations"][0]["physicalLocation"]["region"] == {"startLine": 7,
                                                                        "endLine": 9}
    info = by_id[MODEL[3].id]
    assert info["level"] == "note" and "region" not in info["locations"][0]["physicalLocation"]
    assert info["properties"]["verification"] == "unverified"
    scanner = by_id[SCAN[0].id]
    assert scanner["level"] == "error" and scanner["properties"]["source"] == "scanner"
    assert scanner["properties"]["verification"] == "not_required"
    assert by_id[SCAN[1].id]["level"] == "warning"
    # One rule per (source, category, title): both model SQL findings share one; the rule
    # takes the most severe of its results.
    assert top["ruleId"] == low["ruleId"]
    rule = driver["rules"][top["ruleIndex"]]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "8.0"
    assert "security" in rule["properties"]["tags"]
    assert len(driver["rules"]) == len({r["ruleId"] for r in results}) == 4


def test_sarif_splits_a_tool_over_githubs_result_limit(tool, monkeypatch):
    monkeypatch.setattr(findings_data, "MAX_RESULTS_PER_RUN", 2)
    report = _export(tool, ["sarif"])
    assert [i.path for i in report.items] == [
        "exports/findings-alpha-20261108-120000-part1.sarif",
        "exports/findings-alpha-20261108-120000-part2.sarif",
        "exports/findings-alpha-20261108-120000-part3.sarif"]
    assert all("25,000" in i.detail for i in report.items)
    seen, categories = [], set()
    for item in report.items:
        doc = json.loads((tool.root / item.path).read_text(encoding="utf-8"))
        assert schema_errors(doc, SCHEMA) == []
        [run] = doc["runs"]
        assert len(run["results"]) <= 2
        categories.add(run["automationDetails"]["id"])
        seen += [r["partialFingerprints"]["unvarnishFindingId"] for r in run["results"]]
    assert len(categories) == 3 and len(seen) == len(set(seen)) == 5


def test_sarif_without_model_findings_is_scanner_only(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    _write_findings(engagement, "alpha", SCAN, None)
    _export(engagement, ["sarif"])
    doc = _sarif(engagement)
    assert schema_errors(doc, SCHEMA) == []
    assert {r["properties"]["source"] for r in doc["runs"][0]["results"]} == {"scanner"}


def test_sarif_with_no_findings_has_one_empty_run(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    _write_findings(engagement, "alpha", [], [])
    _export(engagement, ["sarif"])
    doc = _sarif(engagement)
    assert schema_errors(doc, SCHEMA) == []
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []


# --- CSV --------------------------------------------------------------------------------------

def _csv_rows(eng) -> list[dict]:
    with next(eng.exports_dir.glob("*.csv")).open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_csv_round_trips_with_multiline_cells_quoted(tool):
    report = _export(tool, ["csv"])
    assert report.items[0].path == "exports/findings-alpha-20261108-120000.csv"
    raw = (tool.root / report.items[0].path).read_text(encoding="utf-8")
    assert raw.splitlines()[0] == ("Summary,Description,Severity,Tool,Category,Source,Path,"
                                   "Lines,FindingId,Verification")
    rows = _csv_rows(tool)
    assert [r["FindingId"] for r in rows] == [
        SCAN[0].id, MODEL[0].id, SCAN[1].id, MODEL[1].id, MODEL[3].id]  # by severity
    top = next(r for r in rows if r["FindingId"] == MODEL[0].id)
    assert top == {
        "Summary": "SQL query built from request input",
        "Description": ("The search handler formats the query string into SQL.\n\n"
                        "Impact: Anyone who can search can read or change any row.\n\n"
                        "Remediation: Use bound parameters."),
        "Severity": "high", "Tool": "alpha", "Category": "security", "Source": "model",
        "Path": "app/db.py", "Lines": "10-12", "FindingId": MODEL[0].id,
        "Verification": "confirmed"}
    assert '"The search handler formats the query string into SQL.\n\nImpact:' in raw
    low = next(r for r in rows if r["FindingId"] == MODEL[1].id)
    assert low["Lines"] == "40" and low["Path"] == "app/report search.py"
    assert low["Description"].endswith("Further evidence:\n- app/views.py:7-9 (caller)")
    info = next(r for r in rows if r["FindingId"] == MODEL[3].id)
    assert info["Lines"] == "" and info["Verification"] == "unverified"
    assert next(r for r in rows if r["FindingId"] == SCAN[0].id)["Verification"] == (
        "not_required")


def test_csv_neutralises_spreadsheet_formulas(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    _write_findings(engagement, "alpha", [],
                    [_finding(title="=HYPERLINK(\"http://x\")", summary="+1 more")])
    _export(engagement, ["csv"])
    [row] = _csv_rows(engagement)
    assert row["Summary"] == "'=HYPERLINK(\"http://x\")"
    assert row["Description"].startswith("'+1 more")


# --- redaction, opt-in, toolchain -------------------------------------------------------------

def test_no_raw_secret_reaches_either_file(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    leaky = _finding(title=f"Key {PLANTED} in client", summary=f"The key {PLANTED} is used.",
                     impact=f"{PLANTED} grants access.", remediation=f"Rotate {PLANTED}.",
                     evidence=[Evidence(path="app/aws.py", line_start=2,
                                        excerpt=f'KEY = "{PLANTED}"', note=PLANTED)])
    scanner = _finding(source=Source.scanner, scanner="hardcoded_infra", verification=None,
                       title="Hardcoded endpoint", summary=f"Token {PLANTED} in a URL.",
                       evidence=[Evidence(path="app/net.py", line_start=5),
                                 Evidence(path="app/x.py", note=f"value: {PLANTED}")])
    _write_findings(engagement, "alpha", [scanner], [leaky])
    report = _export(engagement, ["sarif", "csv"])
    assert [i.status for i in report.items] == ["ok", "ok"]
    for item in report.items:
        text = (engagement.root / item.path).read_text(encoding="utf-8")
        assert PLANTED not in text, item.fmt
        assert "redacted" in text
    # the finding id is the unredacted finding's, so it matches findings.json
    assert any(r["FindingId"] == leaky.id for r in _csv_rows(engagement))


def test_default_export_is_unchanged_and_new_formats_are_opt_in(tool, monkeypatch):
    assert FORMATS == ("docx", "html", "pdf")
    findings_md = tool.tool_paths("alpha").findings_doc
    findings_md.parent.mkdir(parents=True, exist_ok=True)
    findings_md.write_text("# Findings\n\nNone.\n", encoding="utf-8")
    converted: list[str] = []

    def fake_pandoc(cmd):
        out = Path(cmd[cmd.index("-o") + 1])
        converted.append(out.suffix)
        out.write_bytes(b"converted")

    monkeypatch.setattr(exporter_module, "run_pandoc", fake_pandoc)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    out = runner.invoke(app, ["export", "-e", str(tool.root)])
    assert out.exit_code == 0, out.output
    assert sorted(converted) == [".docx", ".html", ".pdf"]
    assert sorted(p.suffix for p in tool.exports_dir.iterdir()) == [".docx", ".html", ".pdf"]
    out = runner.invoke(app, ["export", "--format", "all", "-e", str(tool.root)])
    assert out.exit_code == 0, out.output
    assert not list(tool.exports_dir.glob("*.sarif")) and not list(tool.exports_dir.glob("*.csv"))
    converted.clear()
    out = runner.invoke(app, ["export", "--format", "all", "--format", "sarif",
                              "-e", str(tool.root)])
    assert out.exit_code == 0, out.output
    assert sorted(converted) == [".docx", ".html", ".pdf"]
    assert len(list(tool.exports_dir.glob("*.sarif"))) == 1


def test_sarif_and_csv_need_no_pandoc(tool, monkeypatch):
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: None)
    out = runner.invoke(app, ["export", "--format", "sarif", "--format", "csv",
                              "-e", str(tool.root)])
    assert out.exit_code == 0, out.output
    assert len(list(tool.exports_dir.glob("findings-alpha-*.sarif"))) == 1
    assert len(list(tool.exports_dir.glob("findings-alpha-*.csv"))) == 1
    # asking for a document format as well still needs the toolchain
    out = runner.invoke(app, ["export", "--format", "csv", "--format", "html",
                              "-e", str(tool.root)])
    assert out.exit_code == 2 and "pandoc" in out.output


def test_unknown_format_and_template_without_documents_exit_2(tool, tmp_path):
    out = runner.invoke(app, ["export", "--format", "xlsx", "-e", str(tool.root)])
    assert out.exit_code == 2 and "sarif" in out.output and "csv" in out.output
    ref = tmp_path / "brand.docx"
    ref.write_bytes(b"x")
    out = runner.invoke(app, ["export", "--format", "sarif", "--template", str(ref),
                              "-e", str(tool.root)])
    assert out.exit_code == 2 and "--template" in out.output


def test_data_formats_follow_the_findings_document(tool):
    report = _export(tool, ["csv"], docs=["architecture"])
    assert report.items == []  # architecture only: no findings export, no conversion
    report = _export(tool, ["csv"], docs=["findings"])
    assert [i.status for i in report.items] == ["ok"]


def test_data_formats_skip_an_unscanned_tool(engagement, synthetic_repo):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    report = _export(engagement, ["sarif", "csv"])
    assert [(i.fmt, i.status) for i in report.items] == [("sarif", "skipped"),
                                                         ("csv", "skipped")]
    assert "scanner-findings.json" in report.items[0].detail


def test_a_failed_data_export_is_recorded(tool, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(exporter_module, "csv_text", boom)
    report = _export(tool, ["csv", "sarif"])
    assert [(i.fmt, i.status) for i in report.items] == [("csv", "failed"), ("sarif", "ok")]
    assert "disk full" in report.items[0].detail
    assert not list(tool.exports_dir.glob("*.csv"))
