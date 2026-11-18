import json

from tests.conftest import LEAKED_KEY
from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.ask.index import build_index
from unvarnish.ask.tools import TOOL_SPECS, AskTools


def _tools(engagement, synthetic_repo) -> AskTools:
    _two_tools(engagement, synthetic_repo, _compare_stub())
    return AskTools(engagement, build_index(engagement))


def test_tool_specs_match_spec_names():
    assert set(TOOL_SPECS) == {"search_index", "get_unit", "get_module", "get_tool",
                               "get_findings", "grep_source"}


def test_search_and_get_unit_module_tool(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    hits = t.search_index("does a thing", tool="alpha")["hits"]
    unit_hit = next(h for h in hits if h["kind"] == "unit")
    unit = t.get_unit(unit_hit["id"])
    assert unit["path"] and unit["extraction"]["purpose"] == "Does a thing." and "usage" not in unit
    module_hit = next(h for h in t.search_index("module", tool="alpha")["hits"]
                      if h["kind"] == "module")
    module = t.get_module(module_hit["id"])
    assert module["path"] and module["summary"] == "A module." and module["unit_ids"]
    tool = t.get_tool("alpha")
    assert tool["purpose"] == "Tracks expenses." and tool["capabilities"][0]["id"]
    assert "findings" not in tool  # findings come from get_findings
    assert t.get_tool("nope") == {"error": "unknown tool 'nope'; known: alpha, beta"}
    assert "unit id" in t.get_unit("nope")["error"]  # malformed ids are rejected up front


def test_get_findings_filters_and_excludes_rejected(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    all_findings = t.get_findings()["findings"]
    assert any(f["source"] == "scanner" for f in all_findings)
    assert any(f["source"] == "model" for f in all_findings)
    assert not any(f["title"] == "No auth anywhere" and f.get("verification") == "rejected"
                   for f in all_findings)
    high = t.get_findings(severity="high")["findings"]
    assert high and all(f["severity"] == "high" for f in high)
    sec = t.get_findings(tool="beta", category="security")["findings"]
    assert sec and all(f["tool"] == "beta" and f["category"] == "security" for f in sec)
    assert t.get_findings(severity="loud")["error"].startswith("unknown severity")
    assert all({"id", "evidence"} <= set(f) for f in all_findings)


def test_grep_source_respects_exclusions_and_caps(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    out = t.grep_source("module.exports", tool="alpha")
    assert out["matches"] == [] and out["searched_files"] > 0  # node_modules is excluded
    out = t.grep_source(r"x\d+ = data", tool="alpha", max_results=5)
    assert len(out["matches"]) == 5 and out["truncated"] is True
    assert all(m["path"] == "app.py" and m["line"] > 0 and "data" in m["text"]
               for m in out["matches"])
    assert t.grep_source("anything", tool="nope")["error"].startswith("unknown tool")


def test_grep_source_on_a_missing_source_is_a_tool_error(engagement, synthetic_repo):
    """UNVAR-31: a tool whose source is gone must not answer "no matches"."""
    import shutil

    t = _tools(engagement, synthetic_repo)
    shutil.rmtree(engagement.tool_paths("alpha").source)
    out = t.grep_source("data", tool="alpha")
    assert "does not exist" in out["error"] and "matches" not in out
    assert str(engagement.root) not in out["error"]  # no consultant path goes to the model


def test_grep_source_invalid_regex_is_a_tool_error(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    out = t.grep_source("(unclosed", tool="alpha")
    assert "error" in out and "regex" in out["error"]


def test_tool_results_are_redacted(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    # the leaked key is only in git history; append one to a file the census already lists
    with (engagement.tool_paths("alpha").source / "README.md").open("a") as fh:
        fh.write(f'K = "{LEAKED_KEY}"\n')
    out = t.grep_source("K = ", tool="alpha")
    assert out["matches"] and LEAKED_KEY not in json.dumps(out)
    assert LEAKED_KEY not in json.dumps(t.get_findings(tool="alpha"))


def test_dispatch_errors_are_returned_not_raised(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    assert t.dispatch("fly", {})["error"].startswith("unknown tool 'fly'")
    assert t.dispatch("get_unit", {})["error"].startswith("get_unit needs")
    assert t.dispatch("grep_source", {"pattern": "x"})["error"].startswith("grep_source needs")
    assert t.dispatch("search_index", {"query": "thing", "tool": "alpha"})["hits"]
    assert t.dispatch("grep_source", {"pattern": "def", "tool": "alpha",
                                      "max_results": "3"})["matches"]  # coerces the int


def test_grep_source_catastrophic_pattern_times_out(engagement, synthetic_repo):
    import time

    t = _tools(engagement, synthetic_repo)
    engagement.config.ask.grep_timeout_s = 0.5
    app = engagement.tool_paths("alpha").source / "app.py"
    app.write_text("x = 1\n" + "a" * 1999 + "!\n", encoding="utf-8")
    start = time.monotonic()
    out = t.grep_source("(a+)+$", tool="alpha")
    assert time.monotonic() - start < 3
    assert out["error"] == "pattern too slow; simplify it"
    assert out["matches"] == [] and out["truncated"] is True
    found = t.grep_source(r"x = \d", tool="alpha")  # an ordinary pattern is unaffected
    assert "error" not in found and found["matches"][0]["path"] == "app.py"


def test_grep_source_keeps_matches_found_before_the_timeout(engagement, synthetic_repo):
    t = _tools(engagement, synthetic_repo)
    engagement.config.ask.grep_timeout_s = 0.5
    app = engagement.tool_paths("alpha").source / "app.py"
    app.write_text("aaa\n" + "a" * 1999 + "!\n", encoding="utf-8")
    out = t.grep_source("(a+)+$", tool="alpha")
    assert out["error"] == "pattern too slow; simplify it"
    assert [m["line"] for m in out["matches"]] == [1]


def test_ask_config_grep_timeout_default():
    from unvarnish.config import AskConfig
    assert AskConfig().grep_timeout_s == 5.0


def test_grep_source_rejects_repeats_that_expand_at_compile(engagement, synthetic_repo):
    # regex writes out each repeat's minimum count when it compiles, so nested minimums
    # multiply; a{4294967294} or (?:x{65535}){65535} would exhaust memory before any timeout
    t = _tools(engagement, synthetic_repo)
    out = t.grep_source("(?:a{1000}){1000}", tool="alpha")  # ~1e6 nodes; safe if unguarded
    assert out == {"error": "pattern too large; use smaller repeat counts"}
    for ordinary in (r"[0-9a-f]{12,16}", r"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}", r"x{0,99999}",
                     r"\p{L}{3}", r"a\{99999\}", r"[{]99999}", r"[]{]{3}", r"(?:ab|cd){2,}"):
        assert "error" not in t.grep_source(ordinary, tool="alpha"), ordinary


def test_grep_source_deadline_covers_every_line(engagement, synthetic_repo, monkeypatch):
    # past the deadline no line gets a fresh slice of time, so the total stays bounded
    from types import SimpleNamespace

    import unvarnish.ask.tools as tools_mod

    t = _tools(engagement, synthetic_repo)
    engagement.config.ask.grep_timeout_s = 2.5
    clock = iter(range(10**6))
    monkeypatch.setattr(tools_mod, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    out = t.grep_source(r"\w", tool="alpha", max_results=50)  # each search is instant
    assert out["error"] == "pattern too slow; simplify it" and out["truncated"] is True
    assert len(out["matches"]) <= 2
