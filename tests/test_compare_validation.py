"""Fixes found by validating comparison on ESCAPESUITE's four tools (craft, artist, plan,
headless-artist) on Anthropic."""
from unvarnish.model.estimate import (
    MODULE_OUTPUT_TOKENS,
    SYSTEM_PROMPT_TOKENS,
    estimate_extract,
    estimate_rollup_modules,
)
from unvarnish.schemas.analysis import Unit, UnitKind, UnitsIndex


def _index(modules: dict[str, int]) -> UnitsIndex:
    units, mods = [], {}
    for path, n in modules.items():
        ids = []
        for i in range(n):
            uid = f"{path}-{i}"
            ids.append(uid)
            units.append(Unit(id=uid, tool="t", module_id=path, path=path, language="python",
                              kind=UnitKind.function, line_start=1, line_end=2, byte_start=0,
                              byte_end=1, token_estimate=100, split_method="structural"))
        mods[path] = ids
    return UnitsIndex(tool="t", unit_tokens=8000, units=units, modules=mods)


def test_module_rollup_estimate_counts_only_modules_that_get_a_call():
    """The dry run priced a model call for every module; one-unit modules are derived."""
    idx = _index({"a.py": 1, "b.py": 1, "c.py": 3})
    assert estimate_rollup_modules(idx).output_tokens == MODULE_OUTPUT_TOKENS
    assert estimate_rollup_modules(idx, single_unit_calls=True).output_tokens == \
        3 * MODULE_OUTPUT_TOKENS


def test_extract_estimate_prices_the_repeated_system_prompt_as_cache_reads():
    idx = _index({"a.py": 3})
    cached = estimate_extract(idx, cached_system=True)
    assert cached.cache_read_tokens == 2 * SYSTEM_PROMPT_TOKENS  # the first call writes it
    plain = estimate_extract(idx)
    assert plain.cache_read_tokens == 0 and plain.input_tokens > cached.input_tokens


# ---------------------------------------------------------------- targeted verification

def _tool_finding(title, summary, paths):
    from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source

    return Finding(tool="t", category=Category.security, severity=Severity.high, title=title,
                   summary=summary, impact="i", remediation="r", source=Source.model,
                   evidence=[Evidence(path=p) for p in paths])


def test_large_cited_files_are_shown_as_windows_around_matching_lines(tmp_path):
    """ESCAPESUITE's "Host origin for postMessage trust derivable from URL parameter" cited a
    546-line and a 1,172-line file and stayed unverified."""
    from unvarnish.phases.verify import whole_file_evidence

    lines = [f"const filler{i} = {i};" for i in range(1, 2001)]
    lines[1199] = "window.addEventListener('message', (e) => {  // no origin check"
    lines[1201] = "  const hostOrigin = params.get('hostOrigin');"
    (tmp_path / "integration.ts").write_text("\n".join(lines) + "\n")
    (tmp_path / "small.ts").write_text("export const a = 1;\n")
    f = _tool_finding("Host origin for postMessage trust derivable from URL parameter",
                      "The `hostOrigin` URL parameter decides which origin's messages are "
                      "trusted.", ["integration.ts", "small.ts"])
    shown = whole_file_evidence(tmp_path, f)
    assert shown is not None
    big = next(s for s in shown if s.startswith("integration.ts"))
    assert "  1202:   const hostOrigin" in big and "  1200: window.addEventListener" in big
    assert "     1: const filler1 " not in big and "excerpts around" in big
    assert any(s.startswith("small.ts (whole file") for s in shown)


def test_large_files_with_no_matching_lines_leave_the_finding_unverified(tmp_path):
    from unvarnish.phases.verify import whole_file_evidence

    (tmp_path / "big.ts").write_text("const x = 1;\n" * 2000)
    f = _tool_finding("No authentication anywhere", "Nothing checks a token.", ["big.ts"])
    assert whole_file_evidence(tmp_path, f) is None


# ---------------------------------------------------------------- prose counts

FACTS = {"findings": {"total": 34, "by_severity": {"medium": 13, "low": 18, "info": 3}}}


def test_count_mismatches_reads_digits_and_number_words():
    from unvarnish.render.prose import count_mismatches

    assert count_mismatches("The review found eight medium-severity issues.", FACTS) == [
        "eight medium (facts: 13)"]
    assert count_mismatches("There are 13 medium findings and no high ones.", FACTS) == []
    assert count_mismatches("It found 2 critical findings.", FACTS) == ["2 critical (facts: 0)"]
    assert count_mismatches("Nothing here mentions counts.", {"other": 1}) == []


def test_a_miscounting_summary_is_retried_once_with_the_facts():
    """qwen2.5:14b wrote "eight medium severity issues" above a table showing 13."""
    from tests.stub_backend import StubBackend
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.render.prose import generate_prose

    replies = iter(["The review found eight medium severity issues.",
                    "The review found 13 medium severity issues."])
    stub = StubBackend({"prose": lambda req: next(replies)})
    out = generate_prose(stub, {"executive_summary": FACTS}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert out.text["executive_summary"] == "The review found 13 medium severity issues."
    assert len(stub.requests) == 2
    assert "eight medium (facts: 13)" in stub.requests[1].messages[-1].content
    assert out.failures == []


def test_a_summary_still_miscounting_after_the_retry_is_kept_and_recorded():
    from tests.stub_backend import StubBackend
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.render.prose import generate_prose

    stub = StubBackend({"prose": "The review found eight medium severity issues."})
    out = generate_prose(stub, {"executive_summary": FACTS}, tone="direct", effort=None,
                         budget=BudgetTracker(None))
    assert "eight medium" in out.text["executive_summary"]
    assert len(stub.requests) == 2
    assert out.failures and "eight medium (facts: 13)" in out.failures[0].error


# ---------------------------------------------------------------- site kit

def test_offline_advisory_note_states_the_database_date(tmp_path, monkeypatch):
    """An air-gapped report should say how old its advisory database is."""
    import json as _json
    import subprocess

    from unvarnish.analysis.advisories import lookup_advisories

    monkeypatch.delenv("UNVARNISH_DISABLE_OSV", raising=False)
    db = tmp_path / "osv"
    db.mkdir()
    (db / "DATE").write_text("2026-10-19\n")
    monkeypatch.setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", str(db))
    report = _json.dumps({"results": [{"source": {"path": "/s/requirements.txt"}, "packages": [
        {"package": {"name": "flask", "version": "2.2.0", "ecosystem": "PyPI"},
         "vulnerabilities": [], "groups": []}]}]})

    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, report.encode(),
                                           b"Loaded PyPI local db from /x/all.zip\n")

    checked, _, note = lookup_advisories(tmp_path, {}, which=lambda t: "osv", run=run)
    assert checked and note == "offline database dated 2026-10-19"


def test_site_kit_seeds_every_common_ecosystem():
    from pathlib import Path

    script = (Path(__file__).resolve().parents[1] / "scripts" / "site-kit.sh").read_text()
    for eco in ("PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist"):
        assert eco in script
    assert "sha256sum" in script or "shasum -a 256" in script


def test_local_source_packages_do_not_make_an_ecosystem_look_unchecked():
    """A lockfile entry with no registry source is "LOCAL" to osv-scanner and never matched;
    the site-kit walk-through reported "npm not checked: no offline database" for it although
    the npm database was loaded fine for registry packages."""
    from unvarnish.analysis.advisories import unchecked_note

    report = {"results": [{"packages": [
        {"package": {"name": "lodash", "ecosystem": "npm",
                     "purl": "pkg:npm/lodash@4.17.20?source=LOCAL"}},
        {"package": {"name": "flask", "ecosystem": "PyPI", "purl": "pkg:pypi/flask@2.2.0"}}]}]}
    assert unchecked_note(report, "Loaded PyPI local db from /x\n") is None


# ---------------------------------------------------------------- refusals

def _resp(text="ok", refusal=None):
    from unvarnish.model.base import CompletionResponse
    from unvarnish.schemas.cost import Usage

    return CompletionResponse(text=text, model="m", usage=Usage(input_tokens=10),
                              refusal_category=refusal)


class _Scripted:
    def __init__(self, name, replies):
        from unvarnish.config import BackendCapabilities

        self.name, self.model, self.replies, self.calls = name, name, list(replies), 0
        self.capabilities = BackendCapabilities()

    def complete(self, req):
        self.calls += 1
        return self.replies.pop(0)


REQ_C = None


def _req():
    from unvarnish.model.base import CompletionRequest, Message

    return CompletionRequest(system="s", messages=[Message(role="user", content="u")])


def test_a_refusal_is_retried_once_on_the_same_model():
    """Opus refused capability normalisation for ESCAPESUITE's four tools as "cyber"; the
    same request succeeded when run again, and without it nothing grouped across tools."""
    from unvarnish.model.refusal import RefusalRetryBackend

    primary = _Scripted("opus", [_resp(refusal="cyber"), _resp("grouped")])
    out = RefusalRetryBackend(primary).complete(_req())
    assert out.text == "grouped" and out.refusal_category is None and primary.calls == 2
    assert out.usage.input_tokens == 20  # both calls are paid for


def test_a_second_refusal_goes_to_the_fallback_model():
    from unvarnish.model.refusal import RefusalRetryBackend

    primary = _Scripted("opus", [_resp(refusal="cyber"), _resp(refusal="cyber")])
    fallback = _Scripted("sonnet", [_resp("grouped by sonnet")])
    out = RefusalRetryBackend(primary, fallback).complete(_req())
    assert out.text == "grouped by sonnet" and fallback.calls == 1


def test_without_a_fallback_the_second_refusal_is_returned():
    from unvarnish.model.refusal import RefusalRetryBackend

    primary = _Scripted("opus", [_resp(refusal="cyber"), _resp(refusal="cyber")])
    assert RefusalRetryBackend(primary).complete(_req()).refusal_category == "cyber"


def test_refusal_fallback_is_configured_per_engagement(tmp_path):
    from unvarnish.config import EngagementConfig
    from unvarnish.engagement import Engagement
    from unvarnish.model.registry import resolve_backend

    eng = Engagement.create(tmp_path / "e", client="Acme")
    data = eng.config.model_dump()
    data["backends"] = {"a": {"type": "anthropic", "api_key_env": None}}
    data["models"] = {"default": {"backend": "a", "model": "claude-opus-5-5"},
                      "refusal_fallback": {"backend": "a", "model": "claude-sonnet-5-5"}}
    eng.config = EngagementConfig.model_validate(data)
    backend = resolve_backend(eng, "compare")
    inner = backend.inner.inner  # cache, then concurrency limit, then refusal retry
    assert inner.fallback is not None and inner.fallback.model == "claude-sonnet-5-5"


# ---------------------------------------------------------------- integration grouping

def _tm(stores):
    from tests.test_comparison_joins import _tm as joins_tm
    from unvarnish.schemas.toolmodel import DataStore

    return joins_tm("t", stores=[DataStore(name=n, kind=k, description="d")
                                 for n, k in stores])


def _models():
    return {"craft": _tm([("Shared ESCAPE Suite IndexedDB", "browser_storage"),
                          ("In-memory recorder store", "cache")]),
            "artist": _tm([("IndexedDB video-editor-db", "browser_storage"),
                           ("Editor store", "cache")]),
            "plan": _tm([("IndexedDB settings (theme-preference)", "browser_storage"),
                         ("Theme setting", "browser_storage")])}


def test_integration_items_have_stable_ids():
    from unvarnish.analysis.comparison import integration_items

    items = integration_items(_models())
    assert [i.id for i in items][:2] == ["craft#1", "craft#2"]
    assert items[0].name == "Shared ESCAPE Suite IndexedDB" and items[0].category == "data_store"


def test_model_grouping_joins_differently_named_stores_and_drops_internal_state():
    """ESCAPESUITE's one shared IndexedDB appeared under seven names, so the map could not
    show which tools share it; in-memory editor and recorder stores filled the map."""
    from unvarnish.analysis.comparison import integration_map
    from unvarnish.schemas.comparison import IntegrationGroup, IntegrationGrouping

    grouping = IntegrationGrouping(groups=[
        IntegrationGroup(name="Shared IndexedDB (video-editor-db)",
                         members=["craft#1", "artist#1", "plan#1"], internal=False),
        IntegrationGroup(name="In-process state", members=["craft#2", "artist#2"],
                         internal=True)])
    rows = integration_map(_models(), grouping)
    assert rows[0].name == "Shared IndexedDB (video-editor-db)"
    assert rows[0].tools == ["craft", "artist", "plan"]
    names = [r.name for r in rows]
    assert "Editor store" not in names and "In-process state" not in names
    assert "Theme setting" in names  # not grouped: kept on its own


def test_without_grouping_the_map_joins_by_name_as_before():
    from unvarnish.analysis.comparison import integration_map

    rows = integration_map(_models())
    assert len(rows) == 6 and all(len(r.tools) == 1 for r in rows)


def test_compare_asks_for_integration_grouping_and_survives_a_bad_reply(engagement,
                                                                         synthetic_repo):
    import json

    from tests.test_compare_phase import _compare_stub, _two_tools
    from unvarnish.artifacts import read_artifact
    from unvarnish.phases.compare import run_comparison
    from unvarnish.schemas.comparison import Comparison

    stub = _compare_stub(IntegrationGrouping="not json")
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    assert any(r.schema_name == "IntegrationGrouping" for r in stub.requests)
    cmp = read_artifact(engagement.comparison_file, Comparison).data
    assert cmp.integration_map  # fell back to name joins
    stub2 = _compare_stub(IntegrationGrouping=json.dumps({"groups": []}))
    assert stub2 is not None


def test_comparison_table_shows_one_sentence_of_purpose():
    from unvarnish.render.markdown import make_env

    first = make_env().filters["first_sentence"]
    assert first("ESCAPECRAFT records screens. It stores them locally.") == \
        "ESCAPECRAFT records screens."
    assert first("No full stop here") == "No full stop here"
    assert first("v1.2 of the tool. More.") == "v1.2 of the tool."
