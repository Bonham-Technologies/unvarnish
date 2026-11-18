"""Fixes found by the release-candidate runs: ESCAPESUITE on Anthropic and an air-gapped run
against a local OpenAI-compatible model."""
import json

from typer.testing import CliRunner

from tests.fake_llm import FakeLLM
from tests.test_cli_model_commands import _engagement
from unvarnish.cli import app

runner = CliRunner()


def test_probe_accepts_any_schema_valid_reply(tmp_path, fake_llm: FakeLLM):
    """qwen2.5:14b, told to keep every list empty, sometimes left purpose empty too; the reply
    was valid against the schema, which is what the probe exists to prove."""
    eng = _engagement(tmp_path, fake_llm)
    fake_llm.script(json.dumps({
        "purpose": "", "interface": [], "external_calls": [], "data_read": [],
        "data_written": [], "auth_behaviour": None, "error_handling": None, "risks": [],
        "candidate_findings": [], "confidence": 0.5}))
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "unexpected" not in r.output and "ok" in r.output
    assert "purpose" in fake_llm.requests[0]["system"][0]["text"]


import pytest  # noqa: E402

from unvarnish.analysis.languages import Excluder  # noqa: E402


@pytest.mark.parametrize("path,reason", [
    # ESCAPESUITE committed 566k tokens of Playwright reports and a 144k-token dist-headless
    # build; both went to the model as source.
    ("apps/e2e/playwright-report-journeys/index.html", "build_output:playwright-report-journeys"),
    ("apps/e2e/playwright-report/index.html", "build_output:playwright-report"),
    ("apps/e2e/test-results/run/trace.json", "build_output:test-results"),
    ("apps/artist/dist-headless/assets/app.js", "build_output:dist-headless"),
    ("web/dist_prod/main.js", "build_output:dist_prod"),
    ("ui/storybook-static/index.html", "build_output:storybook-static"),
    ("htmlcov/index.html", "build_output:htmlcov"),
    (".turbo/cache/x.json", "build_output:.turbo"),
    (".svelte-kit/output/x.js", "build_output:.svelte-kit"),
    ("src/distance.ts", None),
    ("tools/build-scripts/x.py", None),
    ("src/distribution/index.ts", None),
])
def test_generated_output_directories_are_excluded(tmp_path, path, reason):
    from pathlib import PurePosixPath

    assert Excluder(tmp_path).reason(PurePosixPath(path)) == reason


from unvarnish.analysis.languages import Classification  # noqa: E402
from unvarnish.scanners.oversized_files import OversizedFilesScanner  # noqa: E402
from unvarnish.schemas.finding import Severity  # noqa: E402
from unvarnish.schemas.inventory import FileMetrics, FileRecord  # noqa: E402


def _oversized(files: list[tuple[str, int, int, str]]):
    """(path, file lines, longest function lines, classification)"""
    from tests.test_scanner_oversized import _ctx

    ctx = _ctx([FileMetrics(path=p, lines=n, bytes=1, functions=1, max_function_lines=f,
                            max_function_name=f"fn_{i}", max_function_start=1,
                            max_function_end=f, metrics_method="treesitter")
                for i, (p, n, f, _) in enumerate(files)])
    ctx.census.files = [FileRecord(path=p, bytes=1, lines=n, language="typescript",
                                   classification=Classification(c), excluded=False,
                                   exclusion_reason=None)
                        for p, n, _, c in files]
    return {f.title: f for f in OversizedFilesScanner().run(ctx)}


def test_oversized_functions_are_one_finding_per_severity():
    """ESCAPESUITE's findings.md repeated "Oversized function" 63 times (600 of 936 lines)."""
    found = _oversized([("a.ts", 400, 200, "source"), ("b.ts", 400, 300, "source"),
                        ("c.ts", 400, 160, "source"), ("d.ts", 2000, 1000, "source"),
                        ("e.ts", 2000, 900, "source")])
    medium, high = found["Oversized functions"], found["Very large functions"]
    assert medium.severity == Severity.medium and high.severity == Severity.high
    assert [e.path for e in medium.evidence] == ["b.ts", "a.ts", "c.ts"]  # longest first
    assert [e.path for e in high.evidence] == ["d.ts", "e.ts"]
    assert medium.summary.startswith("3 functions are longer than 150 lines")
    assert "fn_1 in b.ts (300 lines)" in medium.summary
    assert medium.evidence[0].note == "fn_1: 300 lines"


def test_oversized_files_are_one_finding():
    found = _oversized([("a.ts", 1600, 10, "source"), ("b.ts", 3000, 10, "source")])
    f = found["Oversized files"]
    assert [e.path for e in f.evidence] == ["b.ts", "a.ts"]
    assert f.summary.startswith("2 files are longer than 1,500 lines")


def test_long_test_blocks_are_not_oversized_functions():
    """A 1,117-line describe() callback in a test file was reported as a function."""
    found = _oversized([("src/x.test.ts", 1200, 1117, "test"), ("src/x.ts", 300, 200, "source")])
    assert [e.path for e in found["Oversized function"].evidence] == ["src/x.ts"]


def test_oversized_evidence_is_capped():
    found = _oversized([(f"m{i:02}.ts", 400, 151 + i, "source") for i in range(30)])
    f = found["Oversized functions"]
    assert len(f.evidence) == 25 and f.evidence[0].path == "m29.ts"
    assert "The 25 longest are listed." in f.summary


def test_gitleaks_titles_are_short_and_descriptions_move_to_the_summary():
    """gitleaks descriptions are sentences ("Detected a Generic API Key, potentially exposing
    access to various services...") and made unreadable titles in ESCAPESUITE's report."""
    from unvarnish.scanners.secrets import gitleaks_title

    assert gitleaks_title("generic-api-key") == "Generic API key"
    assert gitleaks_title("jwt") == "JWT"
    assert gitleaks_title("stripe-access-token") == "Stripe access token"
    assert gitleaks_title("gcp-api-key") == "GCP API key"
    assert gitleaks_title("slack-webhook-url") == "Slack webhook URL"
    assert gitleaks_title("aws-access-token") == "AWS access token"
    assert gitleaks_title("") == "Secret"


# ---------------------------------------------------------------- slow on-prem servers

import httpx2 as httpx  # noqa: E402  (openai 3.x ships httpx2)
import openai  # noqa: E402

from unvarnish.config import BackendCapabilities  # noqa: E402
from unvarnish.model.base import BackendError, BackendUnavailable, CompletionRequest, Message  # noqa: E402,E501
from unvarnish.model.openai_backend import OpenAICompatibleBackend  # noqa: E402


class _Completions:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    def create(self, **kwargs):
        self.calls += 1
        out = self.outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def _backend(outcomes, **kw):
    b = OpenAICompatibleBackend(name="onprem", model="m", api_key="none",
                                base_url="http://llm:11434/v1",
                                capabilities=BackendCapabilities(), sleep=lambda s: None, **kw)
    comp = _Completions(outcomes)
    b._client = type("C", (), {"chat": type("Ch", (), {"completions": comp})()})()
    return b, comp


REQ = CompletionRequest(system="s", messages=[Message(role="user", content="u")], max_tokens=10)
_HTTP = httpx.Request("POST", "http://llm:11434/v1/chat/completions")


def test_a_timeout_fails_the_unit_not_the_run_and_is_not_retried():
    """qwen2.5:14b on CPU needed more than the SDK's 10-minute default for one unit; the SDK
    retried it three times and the run would then have aborted with exit 2."""
    b, comp = _backend([openai.APITimeoutError(request=_HTTP)], timeout_s=1800)
    try:
        b.complete(REQ)
        raise AssertionError("expected BackendError")
    except BackendUnavailable as exc:
        raise AssertionError(f"a timeout must not stop the run: {exc}") from exc
    except BackendError as exc:
        assert "1800" in str(exc) and "timeout_s" in str(exc)
        # lowering unit_tokens does not help a rollup, whose output is the slow part
        assert "unit_tokens" not in str(exc)
    assert comp.calls == 1


def test_server_errors_are_retried_with_backoff():
    from types import SimpleNamespace

    ok = SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content="{}", refusal=None), finish_reason="stop")],
        usage=None, model="m")
    err = openai.InternalServerError("boom", response=httpx.Response(500, request=_HTTP),
                                     body=None)
    b, comp = _backend([err, err, ok])
    assert b.complete(REQ).text == "{}" and comp.calls == 3


def test_openai_backend_timeout_comes_from_config():
    from unvarnish.config import BackendConfig
    from unvarnish.model.registry import build_backend

    cfg = BackendConfig(type="openai_compatible", base_url="http://llm/v1")
    assert build_backend("onprem", cfg, "m")._client.timeout == 1800
    cfg = BackendConfig(type="openai_compatible", base_url="http://llm/v1", timeout_s=7200)
    assert build_backend("onprem", cfg, "m")._client.timeout == 7200


def test_an_anthropic_timeout_fails_the_unit_not_the_run():
    import anthropic

    from unvarnish.model.anthropic_backend import AnthropicBackend

    b = AnthropicBackend(name="anthropic", model="m", api_key="k", base_url=None,
                         capabilities=BackendCapabilities(), sleep=lambda s: None)

    class _Messages:
        def create(self, **kwargs):
            raise anthropic.APITimeoutError(request=_HTTP)

    b._client = type("C", (), {"messages": _Messages()})()
    try:
        b.complete(REQ)
        raise AssertionError("expected BackendError")
    except BackendUnavailable as exc:
        raise AssertionError(f"a timeout must not stop the run: {exc}") from exc
    except BackendError as exc:
        assert "no reply within" in str(exc)


def test_files_without_behaviour_are_not_sent_to_the_model(engagement, tmp_path):
    """Extracting apps/plan/.gitignore took qwen2.5:14b five and a half minutes."""
    from tests.test_split_phase import _split
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    (pile / "public").mkdir(parents=True)
    for name in (".gitignore", ".dockerignore", ".editorconfig", ".nvmrc", "LICENSE",
                 "LICENSE.md", "COPYING", "public/robots.txt", "public/sitemap.xml"):
        (pile / name).write_text("x\n")
    (pile / "app.py").write_text("def main():\n    return 1\n")
    (pile / "README.md").write_text("# App\n\nDoes things.\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    paths = {u.path for u in _split(engagement, "pile")[0].units}
    assert paths == {"app.py", "README.md"}


def test_placeholder_entries_are_dropped_from_extractions():
    """qwen2.5:14b wrote risks: ["None"] for a .gitignore."""
    from unvarnish.schemas.analysis import UnitExtraction

    e = UnitExtraction.model_validate({
        "purpose": "p", "interface": ["N/A"], "data_read": ["none"], "data_written": ["-"],
        "auth_behaviour": "None", "error_handling": "Not applicable.",
        "risks": ["None", "No risks identified.", "Token stored in localStorage."],
        "confidence": 0.5})
    assert e.risks == ["Token stored in localStorage."]
    assert e.interface == [] and e.data_read == [] and e.data_written == []
    assert e.auth_behaviour is None and e.error_handling is None


def test_extract_prompt_rules_out_strengths_as_findings():
    """The same model reported "Documentation of changes" (a CHANGELOG) as a finding."""
    from unvarnish.model.prompts.extract import PROMPT_VERSION, build_system_prompt

    text = build_system_prompt()
    assert "Never report a strength" in text and "empty list" in text
    assert PROMPT_VERSION >= "2026-10-19.1"


# ---------------------------------------------------------------- per-model prices

def _ledger():
    from datetime import UTC, datetime

    from unvarnish.schemas.cost import CostEntry, CostLedger, Usage

    now = datetime.now(UTC)
    return CostLedger(entries=[
        CostEntry(tool="t", phase="extract", backend="a", model="claude-sonnet-5-5", at=now,
                  usage=Usage(input_tokens=1_000_000, output_tokens=100_000,
                              cache_read_tokens=2_000_000)),
        CostEntry(tool="t", phase="rollup_tool", backend="a", model="claude-opus-5-5", at=now,
                  usage=Usage(input_tokens=1_000_000, output_tokens=100_000)),
    ])


def test_prices_per_model_and_cache_rates():
    """ESCAPESUITE runs extract on Sonnet and everything else on Opus; one price was wrong."""
    from unvarnish.config import BudgetConfig

    budget = BudgetConfig.model_validate({"prices": {
        "claude-sonnet-5-5": {"input_per_mtok": 2, "output_per_mtok": 10,
                              "cache_read_per_mtok": 0.2},
        "claude-opus-5-5": {"input_per_mtok": 4, "output_per_mtok": 20}}})
    # sonnet: 1M*2 + 0.1M*10 + 2M*0.2 = 3.4; opus: 1M*4 + 0.1M*20 = 6
    assert round(_ledger().estimate_usd(budget.prices), 2) == 9.40


def test_a_single_price_still_works_and_unpriced_models_are_named():
    from unvarnish.config import BudgetConfig
    from unvarnish.schemas.cost import priced

    single = BudgetConfig.model_validate({"prices": {"input_per_mtok": 1, "output_per_mtok": 1}})
    assert round(_ledger().estimate_usd(single.prices), 2) == 4.20  # cache billed as input
    partial = BudgetConfig.model_validate({"prices": {
        "claude-opus-5-5": {"input_per_mtok": 4, "output_per_mtok": 20}}})
    assert _ledger().estimate_usd(partial.prices) is None
    assert priced(partial.prices, "claude-sonnet-5-5") is None


def test_config_check_probes_the_default_model_when_extract_is_overridden(tmp_path,
                                                                         fake_llm: FakeLLM):
    """ESCAPESUITE runs extract on Sonnet and every other phase on the Opus default; config
    check probed only Sonnet."""
    from tests.conftest import model_config

    cfg = model_config(fake_llm, model="opus-default")
    cfg["models"]["phases"] = {"extract": {"backend": "fake", "model": "sonnet-extract"}}
    eng = _engagement(tmp_path, **cfg)
    good = json.dumps({"purpose": "p", "interface": [], "external_calls": [], "data_read": [],
                       "data_written": [], "auth_behaviour": None, "error_handling": None,
                       "risks": [], "candidate_findings": [], "confidence": 0.5})
    fake_llm.script(good, good)
    r = runner.invoke(app, ["config", "check", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert sorted(q["model"] for q in fake_llm.requests) == ["opus-default", "sonnet-extract"]


@pytest.mark.parametrize("path", [".Rhistory", "a/.bash_history", ".python_history",
                                  ".node_repl_history", ".zsh_history", ".psql_history"])
def test_shell_and_repl_history_is_not_sent_to_the_model(path):
    """ESCAPESUITE has a committed .Rhistory; it went to the model as a unit."""
    from unvarnish.phases.split import describes_no_behaviour

    assert describes_no_behaviour(path)
    assert not describes_no_behaviour("src/history.ts")


def test_budget_counts_cache_reads_at_a_tenth():
    """ESCAPESUITE hit a 16M cap with 7.3M of it cache reads, billed at a tenth of input."""
    from unvarnish.model.budget import BudgetTracker
    from unvarnish.schemas.cost import Usage

    t = BudgetTracker(1_000)
    t.add(Usage(input_tokens=500, output_tokens=100, cache_read_tokens=3_000))
    assert t.used == 900 and not t.exceeded  # 500 + 100 + 3000 / 10
    t.add(Usage(input_tokens=101))
    assert t.exceeded


def test_low_and_info_findings_render_as_one_table_row_each(ingested):
    """ESCAPESUITE's findings.md was 35,276 lines: 2,327 low and info findings with full
    sections. Leadership reads the top; the rest is a table, full detail in findings.json."""
    from tests.test_render import _render

    eng, tool = ingested
    doc, _ = _render(eng, tool)
    low = doc.split("### Low (", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
    assert "#### " not in low
    assert "| Finding | Category | Source | Effort | Location |" in low  # effort: UNVAR-42
    assert "findings.json" in low
    rows = [ln for ln in low.splitlines() if ln.startswith("| ") and "---" not in ln]
    assert len(rows) >= 2  # header plus at least one finding
    medium = doc.split("### Medium (", 1)[1].split("\n### ", 1)[0]
    assert "#### " in medium  # medium and above keep full sections


def test_detail_threshold_is_configurable(ingested):
    from tests.test_render import _render
    from unvarnish.config import EngagementConfig

    eng, tool = ingested
    data = eng.config.model_dump()
    data["report"]["detail_from"] = "low"
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    doc, _ = _render(eng, tool)
    assert "#### " in doc.split("### Low (", 1)[1].split("\n## ", 1)[0]


# ---------------------------------------------------------------- verification of tool-level

def test_tool_level_findings_on_small_files_are_verified_against_the_whole_files(tmp_path):
    """ESCAPESUITE's six unverified high findings were all tool-level claims citing whole files
    (an unauthenticated render API, postMessage trust); the files were small enough to read."""
    from unvarnish.phases.verify import whole_file_evidence
    from unvarnish.schemas.finding import Category, Evidence, Finding, Source

    (tmp_path / "serve.ts").write_text("".join(f"line {i}\n" for i in range(1, 301)))
    (tmp_path / "big.ts").write_text("x\n" * 700)
    f = Finding(tool="t", category=Category.security, severity=Severity.high, title="No auth",
                summary="s", impact="i", remediation="r", source=Source.model,
                evidence=[Evidence(path="serve.ts", note="cited by tool-level analysis")])
    excerpts = whole_file_evidence(tmp_path, f)
    assert excerpts and "   300: line 300" in excerpts[0] and "serve.ts (whole file" in excerpts[0]
    f.evidence.append(Evidence(path="big.ts"))
    assert whole_file_evidence(tmp_path, f) is None  # too large to show whole


def test_reworded_tool_level_findings_from_different_chunks_are_merged():
    """ESCAPESUITE's hierarchical rollup produced "AI agent scripts approve CI runs, force-push
    and merge using developer credentials" and "Agent scripts auto-approve CI runs and merge to
    main with developer credentials" as two high findings."""
    from unvarnish.phases.rollup_tool import merge_similar_findings
    from unvarnish.schemas.finding import Category, Evidence, Finding, Source

    def f(title, paths, cat=Category.security):
        return Finding(tool="t", category=cat, severity=Severity.high, title=title, summary="s",
                       impact="i", remediation="r", source=Source.model,
                       evidence=[Evidence(path=p) for p in paths])

    a = f("AI agent scripts approve CI runs, force-push and merge using developer credentials",
          ["r.sh", "w.sh", "m.sh"], Category.process)
    b = f("Agent scripts auto-approve CI runs and merge to main with developer credentials",
          ["r.sh", "c/r.sh", "w.sh"])
    c = f("postMessage trust comes from an attacker-controllable URL parameter", ["i.ts"])
    d = f("Host postMessage bridge may lack origin checks and exposes full state", ["i.ts", "h.ts"])
    merged = merge_similar_findings([a, b, c, d])
    assert len(merged) == 3
    assert {e.path for e in merged[0].evidence} == {"r.sh", "w.sh", "m.sh", "c/r.sh"}
    assert merged[0].title == a.title


def test_by_the_numbers_ranks_source_files_not_tests(engagement, tmp_path):
    """ESCAPESUITE's "Largest file" and all five "Largest files" rows were test files."""
    from tests.test_render import _render
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    (pile / "tests").mkdir(parents=True)
    (pile / "tests" / "test_app.py").write_text("def test_x():\n" + "    x = 1\n" * 400)
    (pile / "app.py").write_text("def main():\n" + "    y = 2\n" * 50)
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    assert "| Largest source file | `app.py`" in doc
    assert "| Longest source function | `main` in `app.py`" in doc
    table = doc.split("### Largest source files", 1)[1].split("\n## ", 1)[0]
    assert "test_app.py" not in table


@pytest.mark.skipif(not __import__("shutil").which("pandoc"), reason="pandoc not installed")
def test_export_format_is_repeatable(engagement, synthetic_repo):
    """`--format docx --format html --format pdf` wrote only PDFs: the last flag won."""
    from tests.test_export_cli import _rendered

    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--format", "docx", "--format", "html", "--doc",
                              "findings", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    suffixes = {p.suffix for p in engagement.exports_dir.iterdir()}
    assert suffixes == {".docx", ".html"}


def test_entry_points_from_different_chunks_are_merged_by_module_and_kind():
    """ESCAPESUITE's architecture listed 94 entry points; "Agent release chain scripts" and
    "release-version-pr.sh" were the same script from two rollup chunks."""
    from unvarnish.phases.rollup_tool import merge_entry_points
    from unvarnish.schemas.toolmodel import EntryPoint

    def ep(name, kind, module):
        return EntryPoint(name=name, kind=kind, module=module, description="d")

    merged = merge_entry_points(
        [ep("Agent release chain scripts", "cli", ".claude/r.sh"),
         ep("POST /render", "http", "s.ts")],
        [ep("r.sh", "cli", ".claude/r.sh"), ep("GET /healthz", "http", "s.ts"),
         ep("POST /render", "http", "s.ts"), ep("Decode worker", "queue", "w.ts")])
    assert [(e.name, e.kind) for e in merged] == [
        ("Agent release chain scripts", "cli"), ("POST /render", "http"),
        ("GET /healthz", "http"), ("Decode worker", "queue")]


# ---------------------------------------------------------------- single-unit modules

def test_single_unit_modules_are_rolled_up_without_a_model_call(ingested):
    """912 of ESCAPESUITE's 1,048 modules had one unit; their Opus rollups restated the unit
    and added 1,009 findings of their own, mostly low."""
    from tests.test_rollup_modules import _extracted, _stub
    from unvarnish.artifacts import read_artifact
    from unvarnish.phases.rollup_modules import RollupModulesPhase
    from unvarnish.schemas.analysis import UnitsIndex
    from unvarnish.schemas.rollup import Module, ModulesIndex, module_file_id

    eng, tool = ingested
    stub = _stub()
    ctx = _extracted(eng, tool, stub)
    index = read_artifact(ctx.paths.units_index, UnitsIndex).data
    single = [p for p, ids in index.modules.items() if len(ids) == 1]
    multi = [p for p, ids in index.modules.items() if len(ids) > 1]
    assert single and multi, "fixture needs both kinds"
    assert RollupModulesPhase(backend=stub).run(ctx).status.value == "ok"
    assert stub.count("ModuleRollup") == len(multi)
    m = read_artifact(ctx.paths.module_dir / f"{module_file_id(single[0])}.json", Module).data
    assert m.rollup.summary == "Does a thing." and m.findings == [] and m.model == "derived"
    digests = read_artifact(ctx.paths.modules_index, ModulesIndex).data.modules
    assert len(digests) == len(single) + len(multi)


def test_single_unit_rollups_can_be_requested(ingested):
    from tests.test_rollup_modules import _extracted, _stub
    from unvarnish.artifacts import read_artifact
    from unvarnish.config import EngagementConfig
    from unvarnish.phases.base import build_context
    from unvarnish.phases.rollup_modules import RollupModulesPhase
    from unvarnish.schemas.analysis import UnitsIndex

    eng, tool = ingested
    data = eng.config.model_dump()
    data["pipeline"]["rollup_single_unit_modules"] = True
    eng.config = EngagementConfig.model_validate(data)
    eng.save_config()
    stub = _stub()
    _extracted(eng, tool, stub)
    ctx = build_context(eng, tool)
    assert RollupModulesPhase(backend=stub).run(ctx).status.value == "ok"
    index = read_artifact(ctx.paths.units_index, UnitsIndex).data
    assert stub.count("ModuleRollup") == len(index.modules)


def test_data_stores_named_differently_by_different_chunks_are_merged():
    """ESCAPESUITE's data inventory listed one IndexedDB database four times and the editor
    store four times, each name a reordering or extension of another."""
    from unvarnish.phases.rollup_tool import merge_similar_named
    from unvarnish.schemas.toolmodel import DataStore

    def ds(name):
        return DataStore(name=name, kind="db", description="d")

    names = ["video-editor-db IndexedDB", "Editor store", "localStorage",
             "IndexedDB video-editor-db", "Editor store (zustand)", "Zustand editor store",
             "IndexedDB video-editor-db (videos, thumbnails, projects, settings)",
             "In-memory editor store and undo history", "sessionStorage", "S3 bucket"]
    merged = merge_similar_named([], [ds(n) for n in names])
    assert [d.name for d in merged] == ["video-editor-db IndexedDB", "Editor store",
                                        "localStorage", "sessionStorage", "S3 bucket"]
