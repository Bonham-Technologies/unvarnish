"""Re-audit delta: `unvarnish run --baseline <path>` (UNVAR-40)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from tests.test_render_documents import _phases, _stub
from unvarnish.analysis.delta import (
    BaselineError,
    compute_delta,
    load_baseline,
    match_findings,
)
from unvarnish.analysis.languages import Classification
from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.cli import app
from unvarnish.export.markdown import prepare_markdown
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.compare import run_comparison
from unvarnish.phases.ingest import ingest_tool
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.hardcoded_infra import HardcodedInfraScanner
from unvarnish.scanners.oversized_files import OversizedFilesScanner
from unvarnish.schemas.delta import BaselineInfo, BaselineSnapshot, Delta
from unvarnish.schemas.finding import Evidence, Finding
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    FileMetrics,
    FileRecord,
    Metrics,
)
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.verify import ModelFindings

GOLDEN = Path(__file__).parent / "golden"
FIXED_AT = "2026-11-08 12:00 UTC"


def _freeze(monkeypatch) -> None:
    monkeypatch.setattr("unvarnish.render.findings.generated_at", lambda: FIXED_AT)
    monkeypatch.setattr("unvarnish.render.comparison.generated_at", lambda: FIXED_AT)


def _normalise(text: str, origin: Path) -> str:
    return text.replace(str(origin), "<origin>")


def test_documents_unchanged_without_baseline(engagement, synthetic_repo, monkeypatch):
    """Without a baseline the documents are byte-identical to the output before UNVAR-40.

    The golden files were written by the code on main before the delta existed, then
    regenerated for the effort bands (UNVAR-42). Regenerate them (UNVARNISH_UPDATE_GOLDEN=1)
    only for a deliberate template change."""
    _freeze(monkeypatch)
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    docs = {
        "findings.md": engagement.tool_paths("alpha").findings_doc,
        "comparison.md": engagement.comparison_doc,
    }
    for name, path in docs.items():
        text = _normalise(path.read_text(encoding="utf-8"), synthetic_repo)
        golden = GOLDEN / name
        if os.environ.get("UNVARNISH_UPDATE_GOLDEN") == "1":
            golden.write_text(text, encoding="utf-8")
        assert text == golden.read_text(encoding="utf-8"), name
    assert not (engagement.tool_paths("alpha").analysis / "delta.json").exists()


# --- matching -------------------------------------------------------------------------------

cli = CliRunner()


def _f(title: str, path: str, line: int | None, *, severity: str = "medium",
       fingerprint: str | None = None, source: str = "scanner", excerpt: str | None = None,
       tool: str = "t") -> Finding:
    return Finding(tool=tool, category="security", severity=severity, title=title,
                   summary="s", impact="i", remediation="r", source=source,
                   evidence=[Evidence(path=path, line_start=line, fingerprint=fingerprint,
                                      excerpt=excerpt)])


def _counts(entries) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in entries:
        out[e.status.value] = out.get(e.status.value, 0) + 1
    return out


def test_match_one_fixed_one_moved_one_added():
    fixed, moved, keep1, keep2 = (_f("Fixed", "a.py", 3), _f("Moved", "b.py", 20),
                                  _f("Keep", "c.py", 5), _f("Keep too", "d.py", None))
    cur = [_f("Moved", "b.py", 30), keep1, keep2, _f("Added", "e.py", 1)]
    entries = match_findings([fixed, moved, keep1, keep2], cur, drift=50)
    assert _counts(entries) == {"resolved": 1, "changed": 1, "new": 1, "persistent": 2}
    changed = next(e for e in entries if e.status == "changed")
    assert changed.matched_by == "title_path" and changed.previous_line == 20
    assert changed.previous_id == moved.id != changed.finding.id
    assert next(e for e in entries if e.status == "resolved").finding.id == fixed.id


def test_match_beyond_drift_is_resolved_and_new():
    entries = match_findings([_f("X", "a.py", 10)], [_f("X", "a.py", 80)], drift=50)
    assert _counts(entries) == {"resolved": 1, "new": 1}


def test_match_nearest_wins_and_severity_change_is_changed():
    base = [_f("X", "a.py", 10), _f("X", "a.py", 40)]
    entries = match_findings(base, [_f("X", "a.py", 38)], drift=50)
    changed = next(e for e in entries if e.status == "changed")
    assert changed.previous_line == 40
    rerated = match_findings([_f("Y", "a.py", 1)], [_f("Y", "a.py", 1, severity="high")], 50)
    assert rerated[0].status == "changed" and rerated[0].matched_by == "id"
    assert rerated[0].previous_severity == "medium"
    assert match_findings([_f("Z", "a.py", None)], [_f("Z", "a.py", 3)], 50)[0].status == "new"


def test_match_nearest_pair_wins_whatever_the_order():
    # The pairing is nearest-first across all candidates, not first-come per current finding:
    # the finding at line 100 is 10 lines from the baseline's, the one at 50 is 40 away.
    entries = match_findings([_f("X", "a.py", 90)], [_f("X", "a.py", 50), _f("X", "a.py", 100)],
                             drift=50)
    changed = next(e for e in entries if e.status == "changed")
    assert changed.finding.evidence[0].line_start == 100 and changed.previous_line == 90
    assert next(e for e in entries if e.status == "new").finding.evidence[0].line_start == 50


def test_secrets_match_by_fingerprint_not_by_title():
    a = _f("AWS access key ID", "a.py", 2, severity="critical", fingerprint="fp-a")
    b = _f("AWS access key ID", "a.py", 4, severity="critical", fingerprint="fp-b")
    # the same secret moved to another file; a different secret at the old place
    cur = [_f("AWS access key ID", "conf/x.py", 9, severity="critical", fingerprint="fp-a"),
           _f("AWS access key ID", "a.py", 3, severity="critical", fingerprint="fp-c")]
    entries = match_findings([a, b], cur, drift=50)
    by_fp = {e.finding.evidence[0].fingerprint: e for e in entries}
    assert by_fp["fp-a"].status == "changed" and by_fp["fp-a"].matched_by == "fingerprint"
    assert by_fp["fp-c"].status == "new"  # same title and path, different value
    assert by_fp["fp-b"].status == "resolved"


# --- grouped scanner findings (UNVAR-49) ----------------------------------------------------


def _oversized(*sizes: tuple[str, int]) -> list[Finding]:
    files = [FileMetrics(path=p, lines=n, bytes=1, metrics_method="lines") for p, n in sizes]
    ctx = ScanContext(tool="t", source_root=Path("."),
                      census=Census(tool="t", files=[], totals=CensusTotals()),
                      metrics=Metrics(tool="t", files=files),
                      git=GitStats(tool="t", available=False),
                      dependencies=Dependencies(tool="t", dependencies=[]),
                      options={"file_lines": 1500})
    return OversizedFilesScanner().run(ctx)


def _hardcoded(root: Path, text: str) -> list[Finding]:
    root.mkdir()
    (root / "a.py").write_text(text, encoding="utf-8")
    rec = FileRecord(path="a.py", bytes=len(text), lines=text.count("\n"), language="python",
                     classification=Classification.source, excluded=False,
                     exclusion_reason=None)
    ctx = ScanContext(tool="t", source_root=root,
                      census=Census(tool="t", files=[rec], totals=CensusTotals()),
                      metrics=Metrics(tool="t", files=[]),
                      git=GitStats(tool="t", available=False),
                      dependencies=Dependencies(tool="t", dependencies=[]))
    return HardcodedInfraScanner().run(ctx)


def _legacy(findings: list[Finding]) -> list[Finding]:
    """The findings as a baseline written before UNVAR-49 holds them: no group tag."""
    out = [f.model_copy(deep=True) for f in findings]
    for f in out:
        f.tags = [t for t in f.tags if not t.startswith("group:")]
    return out


def test_partly_fixed_oversized_group_is_changed_not_resolved_and_new():
    base = _oversized(("big1.py", 4000), ("big2.py", 2000))
    cur = _oversized(("big1.py", 900), ("big2.py", 2000))  # the larger file was shrunk
    assert [f.title for f in base] == ["Oversized files"]
    assert [f.title for f in cur] == ["Oversized file"]
    for baseline in (_legacy(base), base):  # a snapshot from before UNVAR-49 matches too
        entries = match_findings(baseline, cur, drift=50)
        assert _counts(entries) == {"changed": 1}
        e = entries[0]
        assert e.matched_by == "group" and e.group == "oversized_files.file"
        assert (e.previous_count, e.count) == (2, 1)
        assert e.previous_id == base[0].id and e.finding.evidence[0].path == "big2.py"
    assert {"group:file", "count:2"} <= set(base[0].tags)  # the scanner names its group


def test_unchanged_group_with_reordered_members_is_persistent():
    base = _oversized(("a.py", 4000), ("b.py", 2000))
    cur = _oversized(("a.py", 2000), ("b.py", 4000))  # same files, the longest swapped
    entries = match_findings(base, cur, drift=50)
    assert [(e.status, e.matched_by) for e in entries] == [("persistent", "group")]


def test_removing_one_of_two_hardcoded_urls_is_changed(tmp_path):
    two = ('A = "https://api.acme-corp.com/v1"\n'
           'B = "https://billing.acme-corp.com/v1"\n')
    base = _hardcoded(tmp_path / "before", two)
    cur = _hardcoded(tmp_path / "after", two.split("\n")[0] + "\n")
    assert base[0].id == cur[0].id  # same title and first location: the id alone matches
    for baseline in (_legacy(base), base):
        entries = match_findings(baseline, cur, drift=50)
        assert _counts(entries) == {"changed": 1}
        assert (entries[0].previous_count, entries[0].count) == (2, 1)
        assert entries[0].group == "hardcoded_infra.url"
    assert {"group:url", "distinct:2"} <= set(base[0].tags)


def test_grouped_hygiene_findings_match_whatever_the_first_path():
    todo = "High density of TODO/FIXME/HACK markers"
    base = _f(todo, "a.py", 3, severity="low")
    base.scanner = "hygiene"
    cur = _f(todo, "z.py", 400, severity="low")  # a.py's markers were resolved
    cur.scanner, cur.tags = "hygiene", ["group:todo_density", "count:12"]
    entries = match_findings([base], [cur], drift=50)
    assert [(e.status, e.matched_by) for e in entries] == [("persistent", "group")]
    assert (entries[0].previous_count, entries[0].count) == (None, 12)  # older: no count
    cur.tags = ["group:todo_density", "count:many"]  # an edited artifact: no count
    assert match_findings([base], [cur], drift=50)[0].count is None
    # A model finding with a scanner's title is no group.
    model = _f(todo, "z.py", 400, severity="low", source="model")
    assert _counts(match_findings([base], [model], drift=50)) == {"new": 1, "resolved": 1}


def test_changed_group_renders_old_and_new_counts():
    from unvarnish.render.findings import delta_context

    base = _oversized(("big1.py", 4000), ("big2.py", 2000))
    cur = _oversized(("big2.py", 2000))
    delta = compute_delta("t", _snap(base), ScannerFindings(tool="t", findings=cur), None,
                          accepted=[], drift=50)
    ctx = delta_context(delta)
    assert ctx is not None and ctx["totals"]["changed"] == 1
    assert ctx["changed"][0]["change"] == "count 2 → 1"
    assert ctx["totals"]["new"] == ctx["totals"]["resolved"] == 0


def _snap(findings, *, model=False, scanner=True) -> BaselineSnapshot:
    return BaselineSnapshot(tool="t", info=BaselineInfo(source="prior", scanner=scanner,
                                                        model=model), findings=findings)


def test_accepted_findings_are_never_resolved():
    gone, kept = _f("Gone", "a.py", 1), _f("Kept", "b.py", 1)
    delta = compute_delta("t", _snap([gone, kept]), ScannerFindings(tool="t", findings=[kept]),
                          None, accepted=[gone.id, kept.id], drift=50)
    assert delta.counts()["accepted"] == 2 and delta.counts()["resolved"] == 0


def test_model_findings_compared_only_when_both_sides_have_them():
    scan = _f("Scan", "a.py", 1)
    model = _f("Model", "b.py", 1, source="model", severity="low")
    mf = ModelFindings(tool="t", findings=[model])
    delta = compute_delta("t", _snap([scan]), ScannerFindings(tool="t", findings=[scan]), mf,
                          accepted=[], drift=50)
    assert delta.compared_sources == ["scanner"] and delta.counts()["new"] == 0
    assert "previous review has no complete model analysis" in delta.notes[0]
    both = compute_delta("t", _snap([scan], model=True),
                         ScannerFindings(tool="t", findings=[scan]), mf, accepted=[], drift=50)
    assert both.compared_sources == ["scanner", "model"] and both.counts()["new"] == 1
    only_model = compute_delta("t", _snap([model], model=True, scanner=False),
                               ScannerFindings(tool="t", findings=[scan]), None, accepted=[],
                               drift=50)
    assert only_model.compared_sources == [] and len(only_model.notes) == 2


# --- resolving a baseline -------------------------------------------------------------------

SECRET = "AKIA" + "Z7Q3V5X2W9R4T6YP"  # built from fragments (UNVAR-36)


def _artifact(path: Path, data, version: int = 1) -> Path:
    write_artifact(path, data, produced_by="test", inputs_hash="x", schema_version=version)
    return path


def test_load_baseline_file_redacts_and_filters_by_tool(tmp_path):
    leaked = _f("AWS access key ID", "a.py", 2, fingerprint="fp", tool="t",
                excerpt=f'ID = "{SECRET}"')
    path = _artifact(tmp_path / "scanner-findings.json",
                     ScannerFindings(tool="t", findings=[leaked]))
    snap = load_baseline(path, "t")
    assert snap is not None and snap.info.scanner and not snap.info.model
    assert SECRET not in snap.model_dump_json() and snap.findings[0].id == leaked.id
    # The free text an older or edited baseline carries is redacted too, ids and fingerprints
    # kept so matching still works.
    wordy = _f(f"Key {SECRET} committed", "b.py", 1, fingerprint="fp2", tool="t")
    wordy.summary = f"The key {SECRET} is live."
    wordy.evidence[0].note = f"value {SECRET}"
    wordy.effort_note = f"rotate {SECRET}"  # UNVAR-42: the band's note is free text too
    wpath = _artifact(tmp_path / "wordy.json", ScannerFindings(tool="t", findings=[wordy]))
    wsnap = load_baseline(wpath, "t")
    assert wsnap is not None and SECRET not in wsnap.model_dump_json()
    assert wsnap.findings[0].id == wordy.id and wsnap.findings[0].evidence[0].fingerprint == "fp2"
    assert load_baseline(path, "other") is None
    mf = _artifact(tmp_path / "findings.json", ModelFindings(
        tool="t", findings=[_f("M", "a.py", 1, source="model", tool="t")]))
    msnap = load_baseline(mf, "t")
    assert msnap is not None and msnap.info.model and not msnap.info.scanner
    stopped = _artifact(tmp_path / "stopped.json", ModelFindings(
        tool="t", findings=[_f("M", "a.py", 1, source="model", tool="t")],
        stopped_for_budget=True))
    ssnap = load_baseline(stopped, "t")
    assert ssnap is not None and not ssnap.info.model and ssnap.findings == []


def test_load_baseline_refuses_other_schema_versions(tmp_path):
    old = _artifact(tmp_path / "old.json", ScannerFindings(tool="t"), version=0)
    with pytest.raises(BaselineError, match="schema version 0, older than the version 1"):
        load_baseline(old, "t")
    new = _artifact(tmp_path / "new.json", ScannerFindings(tool="t"), version=2)
    with pytest.raises(BaselineError, match="newer Unvarnish"):
        load_baseline(new, "t")


def test_load_baseline_rejects_what_it_cannot_read(tmp_path):
    with pytest.raises(BaselineError, match="does not exist"):
        load_baseline(tmp_path / "missing", "t")
    with pytest.raises(BaselineError, match="not an engagement folder"):
        load_baseline(tmp_path, "t")
    junk = tmp_path / "junk.json"
    junk.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError, match="not a readable findings artifact"):
        load_baseline(junk, "t")
    other = tmp_path / "other.json"
    other.write_text('{"meta": {}, "data": {"x": 1}}', encoding="utf-8")
    with pytest.raises(BaselineError, match="not an Unvarnish findings artifact"):
        load_baseline(other, "t")
    bad = tmp_path / "bad.json"
    bad.write_text('{"meta": {"schema_version": 1}, "data": {"findings": [1]}}',
                   encoding="utf-8")
    with pytest.raises(BaselineError, match="not a valid findings artifact"):
        load_baseline(bad, "t")


# --- end to end -----------------------------------------------------------------------------

# built from fragments so no tracked file holds a whole real-format token (UNVAR-36)
KEYS = {"a": "AKIA" + "Z7Q3V5X2W9R4T6YP", "b": "AKIA" + "Q4M8N2B6V9C3X7ZL",
        "c": "AKIA" + "H5J7K2L9P3R8T4WE", "d": "AKIA" + "U3I6O9P2A5S8D1FG"}


def _sources(tmp_path: Path) -> tuple[Path, Path]:
    before, after = tmp_path / "before-src", tmp_path / "after-src"
    for root in (before, after):
        root.mkdir()
    for name in ("a", "b", "c"):
        (before / f"{name}.py").write_text(f'import os\nACCESS_{name.upper()} = '
                                           f'"{KEYS[name]}"\n', encoding="utf-8")
    (after / "a.py").write_text("import os\nACCESS_A = os.environ['ACCESS_A']\n",
                                encoding="utf-8")  # fixed
    (after / "b.py").write_text("import os\n" + "# moved\n" * 10
                                + f'ACCESS_B = "{KEYS["b"]}"\n', encoding="utf-8")  # moved 10
    (after / "c.py").write_text((before / "c.py").read_text(encoding="utf-8"),
                                encoding="utf-8")  # untouched
    (after / "d.py").write_text(f'import os\nACCESS_D = "{KEYS["d"]}"\n',
                                encoding="utf-8")  # added
    return before, after


def _engagement(tmp_path: Path, name: str, src: Path) -> Path:
    eng = tmp_path / name
    assert cli.invoke(app, ["init", str(eng), "--client", "Acme"]).exit_code == 0
    r = cli.invoke(app, ["add", "tool", "--files", str(src), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    return eng


def _no_secret(*texts: str) -> None:
    for text in texts:
        for key in KEYS.values():
            assert key not in text


def test_run_with_baseline_end_to_end(tmp_path, monkeypatch):
    _freeze(monkeypatch)
    before_src, after_src = _sources(tmp_path)
    prior = _engagement(tmp_path, "prior", before_src)
    assert cli.invoke(app, ["run", "-e", str(prior)]).exit_code == 0
    eng = _engagement(tmp_path, "now", after_src)
    tool = eng / "tools" / "tool"

    r = cli.invoke(app, ["run", "--baseline", str(prior), "-e", str(eng)])
    assert r.exit_code == 0, r.output
    delta = read_artifact(tool / "analysis" / "delta.json", Delta)
    assert delta.meta.schema_version == delta.data.schema_version == 1
    counts = delta.data.counts()
    scanned = read_artifact(tool / "inventory" / "scanner-findings.json", ScannerFindings).data
    assert counts == {"resolved": 1, "changed": 1, "new": 1, "accepted": 0,
                      "persistent": len(scanned.findings) - 2}
    assert counts["persistent"] >= 2  # the untouched secret and the tool-level findings
    by_status = {e.status: e for e in delta.data.entries if e.status != "persistent"}
    assert by_status["resolved"].finding.evidence[0].path == "a.py"
    assert by_status["changed"].finding.evidence[0].line_start == 12
    assert by_status["changed"].previous_line == 2
    assert by_status["new"].finding.evidence[0].path == "d.py"

    doc = (tool / "docs" / "findings.md").read_text(encoding="utf-8")
    assert "## Since the previous review (" in doc
    assert doc.index("## Since the previous review") < doc.index("## Executive summary")
    assert "| Severity | Resolved | New | Changed | Persistent | Risk accepted |" in doc
    assert "### Resolved (1)" in doc and "### New (1)" in doc and "### Changed (1)" in doc
    assert "`a.py:2`" in doc and "`d.py:2`" in doc and "moved from `b.py:2`" in doc
    _no_secret(doc, (tool / "analysis" / "delta.json").read_text(encoding="utf-8"),
               (tool / "analysis" / "baseline.json").read_text(encoding="utf-8"))

    # Exports convert the same Markdown, section included.
    md, failures = prepare_markdown(doc, {}, tmp_path / "img")
    assert "## Since the previous review (" in md and not failures

    # The baseline is remembered: a plain rerun keeps the section and renders nothing new.
    again = cli.invoke(app, ["run", "-e", str(eng)])
    assert again.exit_code == 0 and "render" in again.output
    assert again.output.count("fresh") == 5, again.output
    assert (tool / "docs" / "findings.md").read_text(encoding="utf-8") == doc
    # Passing the same baseline again changes nothing either: the snapshot is not rewritten.
    snapshot = (tool / "analysis" / "baseline.json").read_text(encoding="utf-8")
    same = cli.invoke(app, ["run", "--baseline", str(prior), "-e", str(eng)])
    assert same.exit_code == 0 and same.output.count("fresh") == 5, same.output
    assert (tool / "analysis" / "baseline.json").read_text(encoding="utf-8") == snapshot

    # Risk accepted: listed in engagement.yaml, never shown as resolved.
    cfg = yaml.safe_load((eng / "engagement.yaml").read_text(encoding="utf-8"))
    cfg["baseline"] = {"accepted": [by_status["resolved"].finding.id]}
    (eng / "engagement.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert cli.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    accepted = read_artifact(tool / "analysis" / "delta.json", Delta).data.counts()
    assert accepted["resolved"] == 0 and accepted["accepted"] == 1
    doc2 = (tool / "docs" / "findings.md").read_text(encoding="utf-8")
    assert "### Risk accepted (1)" in doc2 and "### Resolved" not in doc2

    # The comparison gains a per-tool trend column.
    r = cli.invoke(app, ["compare", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    cmp = (eng / "comparison" / "comparison.md").read_text(encoding="utf-8")
    assert "| Model analysis | Since the previous review |" in cmp
    assert "| **no** | worsened (0 resolved, 1 new, 1 risk accepted) |" in cmp


def test_own_folder_baseline_is_kept_on_a_rerun(tmp_path, monkeypatch):
    """UNVAR-48: `run --baseline .` twice must not snapshot the first run's own results."""
    _freeze(monkeypatch)
    before_src, after_src = _sources(tmp_path)
    eng = _engagement(tmp_path, "own", before_src)
    tool = eng / "tools" / "tool"
    assert cli.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    shutil.rmtree(tool / "source")
    shutil.copytree(after_src, tool / "source")  # the client fixed, moved and added secrets

    first = cli.invoke(app, ["run", "--baseline", str(eng), "-e", str(eng)])
    assert first.exit_code == 0, first.output
    counts = read_artifact(tool / "analysis" / "delta.json", Delta).data.counts()
    assert counts["resolved"] == counts["new"] == counts["changed"] == 1
    snapshot = (tool / "analysis" / "baseline.json").read_text(encoding="utf-8")

    second = cli.invoke(app, ["run", "--baseline", str(eng / "tools" / "tool"), "-e", str(eng)])
    assert second.exit_code == 0, second.output
    assert read_artifact(tool / "analysis" / "delta.json", Delta).data.counts() == counts
    assert (tool / "analysis" / "baseline.json").read_text(encoding="utf-8") == snapshot
    assert "keeping the stored baseline" in second.output
    assert "delete" in second.output and "baseline.json" in second.output

    # Deleting the snapshot is the explicit way to take a new one from the folder.
    (tool / "analysis" / "baseline.json").unlink()
    fresh = cli.invoke(app, ["run", "--baseline", str(eng), "-e", str(eng)])
    assert fresh.exit_code == 0 and "keeping the stored baseline" not in fresh.output
    recount = read_artifact(tool / "analysis" / "delta.json", Delta).data.counts()
    assert recount["resolved"] == recount["new"] == recount["changed"] == 0


def test_own_folder_baseline_replaces_an_unusable_snapshot(tmp_path, monkeypatch):
    """A broken stored snapshot is not kept: render tells the user to rerun with --baseline."""
    _freeze(monkeypatch)
    _, after_src = _sources(tmp_path)
    eng = _engagement(tmp_path, "broken", after_src)
    tool = eng / "tools" / "tool"
    assert cli.invoke(app, ["run", "-e", str(eng)]).exit_code == 0
    stored = tool / "analysis" / "baseline.json"
    stored.write_text("not json", encoding="utf-8")

    monkeypatch.chdir(eng)
    r = cli.invoke(app, ["run", "--baseline", ".", "-e", str(eng)])
    assert r.exit_code == 0, r.output
    assert "keeping the stored baseline" not in r.output
    assert read_artifact(stored, BaselineSnapshot).data.findings
    assert (tool / "analysis" / "delta.json").exists()


def test_run_refuses_an_older_baseline(tmp_path):
    _, after_src = _sources(tmp_path)
    eng = _engagement(tmp_path, "now", after_src)
    old = _artifact(tmp_path / "old.json", ScannerFindings(tool="tool"), version=0)
    r = cli.invoke(app, ["run", "--baseline", str(old), "-e", str(eng)])
    assert r.exit_code == 2
    assert "schema version 0" in r.output and "older" in r.output
    assert not (eng / "tools" / "tool" / "inventory" / "census.json").exists()  # nothing ran
    dry = cli.invoke(app, ["run", "--dry-run", "--baseline", str(old), "-e", str(eng)])
    assert dry.exit_code == 2


def test_run_baseline_without_the_tool(tmp_path):
    _, after_src = _sources(tmp_path)
    eng = _engagement(tmp_path, "now", after_src)
    other = _artifact(tmp_path / "other.json", ScannerFindings(tool="someone-else"))
    r = cli.invoke(app, ["run", "--baseline", str(other), "-e", str(eng)])
    assert r.exit_code == 2 and "no findings for" in r.output
    ok = cli.invoke(app, ["run", "--dry-run", "--baseline",
                          str(_artifact(tmp_path / "t.json", ScannerFindings(tool="tool"))),
                          "-e", str(eng)])
    assert ok.exit_code == 0, ok.output
    assert not (eng / "tools" / "tool" / "analysis" / "baseline.json").exists()


def test_baseline_change_rerenders_without_rerunning_model_phases(engagement, synthetic_repo,
                                                                 tmp_path, monkeypatch):
    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")
    stub = _stub()
    ctx = build_context(engagement, "alpha", budget=BudgetTracker(None))
    assert all(r.status == PhaseStatus.ok for r in PhaseRunner(_phases(stub)).run(ctx))
    before = {k: stub.count(k) for k in ("UnitExtraction", "ModuleRollup", "Verdict")}
    snap = load_baseline(engagement.tool_paths("alpha").root, "alpha")  # a tool folder
    assert snap is not None and snap.info.model and snap.info.commit
    write_artifact(ctx.paths.baseline, snap, produced_by="baseline", inputs_hash="")
    results = PhaseRunner(_phases(stub)).run(ctx)
    assert {r.phase: r.status for r in results if r.status != PhaseStatus.skipped} == {
        "render": PhaseStatus.ok}
    assert {k: stub.count(k) for k in before} == before  # no model phase reran
    delta = read_artifact(ctx.paths.delta, Delta).data
    assert delta.compared_sources == ["scanner", "model"]
    assert set(delta.counts()) >= {"persistent"} and delta.counts()["persistent"] == len(
        delta.entries)  # compared with itself
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert f"## Since the previous review ({snap.info.reviewed_at:%Y-%m-%d}, commit " in doc
    assert "No findings resolved." in doc and "No new findings." in doc
    # A matcher change alone re-renders the delta, still with no model call (UNVAR-49).
    import unvarnish.phases.render as render_phase
    monkeypatch.setattr(render_phase, "MATCH_VERSION", f"{render_phase.MATCH_VERSION}+")
    results = PhaseRunner(_phases(stub)).run(ctx)
    assert {r.phase: r.status for r in results if r.status != PhaseStatus.skipped} == {
        "render": PhaseStatus.ok}
    assert {k: stub.count(k) for k in before} == before
    # Removing the baseline removes the delta and the section.
    ctx.paths.baseline.unlink()
    PhaseRunner(_phases(stub)).run(ctx)
    assert not ctx.paths.delta.exists()
    assert "Since the previous review" not in ctx.paths.findings_doc.read_text(encoding="utf-8")
    # A prior engagement folder without this tool has nothing to compare.
    assert load_baseline(engagement.root, "ghost") is None


def test_unreadable_baseline_snapshot_is_a_recorded_failure(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    ctx.paths.baseline.parent.mkdir(parents=True, exist_ok=True)
    ctx.paths.baseline.write_text("{broken", encoding="utf-8")
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    render = results[-1]
    assert render.status == PhaseStatus.ok and any("baseline" in f for f in render.failures)
    assert not ctx.paths.delta.exists()
    assert "Since the previous review" not in ctx.paths.findings_doc.read_text(encoding="utf-8")


def test_tool_folder_baseline_edge_cases(tmp_path):
    folder = tmp_path / "prior-tool"
    scan = ScannerFindings(tool="t", findings=[_f("S", "a.py", 1)])
    _artifact(folder / "inventory" / "scanner-findings.json", scan)
    _artifact(folder / "analysis" / "findings.json", ModelFindings(
        tool="t", findings=[_f("M", "a.py", 1, source="model")], stopped_for_budget=True))
    snap = load_baseline(folder, "t")  # no tool.yaml: no commit; stopped model run: not used
    assert snap is not None and snap.info.commit is None and not snap.info.model
    assert [f.title for f in snap.findings] == ["S"]
    assert load_baseline(folder, "other") is None


def test_delta_rendering_details(engagement, tmp_path):
    from unvarnish.render.comparison import tool_trends, trend_text
    from unvarnish.render.findings import delta_context

    def delta(entries_base, entries_cur, accepted=()):
        return compute_delta("t", _snap(entries_base), ScannerFindings(tool="t",
                             findings=entries_cur), None, accepted=list(accepted), drift=50)

    keep = _f("K", "a.py", 1)
    assert trend_text(delta([keep], [keep])) == "no change (0 resolved, 0 new)"
    assert trend_text(delta([keep, _f("G", "b.py", 1)], [keep])).startswith("improved")
    assert trend_text(delta([_f("G", "b.py", 1)], [_f("N", "c.py", 1)])).startswith("level")
    rerated = delta([keep], [_f("K", "a.py", 1, severity="high")])
    ctx = delta_context(rerated)
    assert ctx is not None and ctx["changed"][0]["change"] == "re-rated from medium"
    assert ctx["heading"] == "Since the previous review" and delta_context(None) is None
    accepted = delta([keep], [keep, _f("N", "c.py", 1)], accepted=[keep.id])
    assert delta_context(accepted)["accepted"][0]["change"] == "still present"
    # An unreadable delta costs its trend cell, not the comparison.
    engagement.register_tool("t")
    bad = engagement.tool_paths("t").delta
    bad.parent.mkdir(parents=True)
    bad.write_text("{broken", encoding="utf-8")
    assert tool_trends(engagement, ["t", "absent"]) == {}


def test_snapshot_from_another_schema_version_is_a_recorded_failure(ingested):
    eng, tool = ingested
    ctx = build_context(eng, tool)
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase
    write_artifact(ctx.paths.baseline, BaselineSnapshot(
        schema_version=2, tool=tool, info=BaselineInfo(source="x")), produced_by="t",
        inputs_hash="")
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    assert any("schema version 2" in f for f in results[-1].failures)
