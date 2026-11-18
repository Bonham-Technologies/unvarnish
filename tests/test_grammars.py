"""UNVAR-45: tree-sitter grammars are fetched ahead of time, and a missing one is reported."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest
import tree_sitter_language_pack as pack
from typer.testing import CliRunner

from unvarnish.analysis import treesitter
from unvarnish.analysis.languages import EXTENSION_MAP, FILENAME_MAP, SHEBANG_MAP
from unvarnish.artifacts import read_artifact
from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.phases.base import build_context, is_fresh
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.schemas.inventory import Census, Metrics


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def no_download(monkeypatch: pytest.MonkeyPatch):
    """The pack's loader fails as it does when GitHub is unreachable; state starts clean."""
    calls: list[str] = []

    def failing(name: str):
        calls.append(name)
        raise pack.DownloadError("Download error: Failed to fetch manifest: 504 Gateway Timeout")

    monkeypatch.setattr(pack, "get_parser", failing)
    monkeypatch.setattr(treesitter, "_unavailable", {})
    monkeypatch.setattr(treesitter, "grammar_cached", lambda language: False)
    treesitter.get_parser.cache_clear()
    handler = _Records()
    treesitter.log.addHandler(handler)
    yield calls, handler
    treesitter.log.removeHandler(handler)
    treesitter.get_parser.cache_clear()


def test_grammar_languages_cover_every_census_language():
    names = treesitter.grammar_languages()
    detected = set(EXTENSION_MAP.values()) | set(FILENAME_MAP.values()) | set(SHEBANG_MAP.values())
    for language in detected - treesitter.NO_GRAMMAR:
        assert treesitter.PACK_NAMES.get(language, language) in names, language
    assert "csharp" in names and "c_sharp" not in names
    assert "javascript" in names  # html script blocks are measured with it
    assert "text" not in names and "jupyter" not in names
    assert names == sorted(set(names))


def test_language_without_a_grammar_never_downloads(no_download):
    calls, handler = no_download
    assert treesitter.get_parser("text") is None
    assert treesitter.get_parser("not-a-language") is None
    assert calls == [] and handler.records == []


def test_download_error_warns_once_and_is_recorded(no_download):
    calls, handler = no_download
    assert treesitter.get_parser("python") is None
    assert treesitter.get_parser("python") is None
    treesitter.get_parser.cache_clear()  # a second phase in the same process
    assert treesitter.get_parser("python") is None
    warnings = [r for r in handler.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
    assert "python" in warnings[0].getMessage()
    assert "unvarnish grammars fetch" in warnings[0].getMessage()
    reason = treesitter.grammar_unavailable("python")
    assert reason is not None and "DownloadError" in reason and "504" in reason
    assert treesitter.grammar_unavailable("go") is None  # never asked for


def _pile(engagement: Engagement, tmp_path: Path) -> str:
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (pile / "b.py").write_text("def g():\n    return 2\n", encoding="utf-8")
    (pile / "page.html").write_text("<script>function h() { return 3; }</script>\n",
                                    encoding="utf-8")
    (pile / "README.md").write_text("# notes\n", encoding="utf-8")
    ingest_tool(engagement, "pile", str(pile), "files")
    return "pile"


def test_inventory_notes_a_missing_grammar_once(no_download, engagement: Engagement,
                                                tmp_path: Path):
    _, handler = no_download
    name = _pile(engagement, tmp_path)
    ctx = build_context(engagement, name)
    result = InventoryPhase().run(ctx)
    census = read_artifact(ctx.paths.census, Census).data
    metrics = read_artifact(ctx.paths.metrics, Metrics).data
    assert all(m.metrics_method == "lines" for m in metrics.files)
    assert census.grammars_unavailable == ["javascript", "python"]
    assert len(census.notes) == 2, census.notes
    py = next(n for n in census.notes if "python" in n)
    assert "2 files" in py and "line counts" in py and "unvarnish grammars fetch" in py
    js = next(n for n in census.notes if "javascript" in n)
    assert "1 file" in js
    assert "no tree-sitter grammar" in (result.message or "")
    warnings = [r for r in handler.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2  # one per language, not one per file


def test_missing_grammar_reaches_the_findings_document(no_download, engagement: Engagement,
                                                       tmp_path: Path):
    from tests.test_render import _render

    name = _pile(engagement, tmp_path)
    doc, _ = _render(engagement, name)
    section = doc.split("## Not analysed", 1)[1].split("\n## ", 1)[0]
    assert section.count("No tree-sitter grammar for python") == 1, section
    assert "No tree-sitter grammar for javascript" in section


def test_inventory_reruns_once_the_grammar_arrives(no_download, engagement: Engagement,
                                                   tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch):
    name = _pile(engagement, tmp_path)
    ctx = build_context(engagement, name)
    phase = InventoryPhase()
    phase.run(ctx)
    assert is_fresh(phase, ctx)  # still missing: nothing to redo
    monkeypatch.setattr(treesitter, "grammar_cached", lambda language: language == "python")
    assert not is_fresh(phase, ctx)  # `unvarnish grammars fetch` ran: measure again


def test_inventory_hash_unchanged_when_nothing_was_missing(engagement: Engagement,
                                                           tmp_path: Path):
    """No grammar gap adds nothing to the hash, so existing engagements stay fresh."""
    from unvarnish.artifacts import hash_inputs

    name = _pile(engagement, tmp_path)
    ctx = build_context(engagement, name)
    phase = InventoryPhase()
    assert phase.inputs_hash(ctx) == phase._hash(ctx, [])
    assert phase._hash(ctx, []) != hash_inputs([])


def test_fetch_retries_with_backoff_then_succeeds(monkeypatch: pytest.MonkeyPatch):
    attempts: list[list[str]] = []
    sleeps: list[float] = []

    def flaky(languages: list[str]) -> None:
        attempts.append(list(languages))
        if len(attempts) < 3:
            raise pack.DownloadError("Download error: HTTP 504")

    monkeypatch.setattr(pack, "prefetch", flaky)
    monkeypatch.setattr(pack, "downloaded_languages", treesitter.grammar_languages)
    cache, missing = treesitter.fetch_grammars(attempts=4, backoff=1.5, sleep=sleeps.append)
    assert len(attempts) == 3 and attempts[0] == treesitter.grammar_languages()
    assert sleeps == [1.5, 3.0]
    assert missing == [] and cache


def test_fetch_gives_up_after_the_last_attempt(monkeypatch: pytest.MonkeyPatch):
    sleeps: list[float] = []

    def down(languages: list[str]) -> None:
        raise pack.DownloadError("Download error: HTTP 504")

    monkeypatch.setattr(pack, "prefetch", down)
    with pytest.raises(treesitter.GrammarFetchError, match="3 attempts.*504"):
        treesitter.fetch_grammars(attempts=3, backoff=1, sleep=sleeps.append)
    assert sleeps == [1, 2]


def test_fetch_into_a_chosen_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    configured: list[str | None] = []
    monkeypatch.setattr(pack, "configure", lambda config: configured.append(config.cache_dir))
    monkeypatch.setattr(pack, "prefetch", lambda languages: None)
    monkeypatch.setattr(pack, "downloaded_languages", lambda: ["python"])
    _, missing = treesitter.fetch_grammars(tmp_path / "ts", sleep=lambda s: None)
    assert configured == [str(tmp_path / "ts")]
    assert "python" not in missing and "go" in missing


def test_cli_grammars_fetch(monkeypatch: pytest.MonkeyPatch):
    seen: dict = {}

    def fake_fetch(cache_dir=None, attempts=4, **_):
        seen.update(cache_dir=cache_dir, attempts=attempts)
        return "/opt/tree-sitter/libs", []

    monkeypatch.setattr(treesitter, "fetch_grammars", fake_fetch)
    out = CliRunner().invoke(app, ["grammars", "fetch", "--attempts", "2"])
    assert out.exit_code == 0, out.output
    assert seen == {"cache_dir": None, "attempts": 2}
    assert "/opt/tree-sitter/libs" in out.output


def test_cli_grammars_fetch_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch):
    def broken(cache_dir=None, attempts=4, **_):
        raise treesitter.GrammarFetchError("gave up after 4 attempts: HTTP 504")

    monkeypatch.setattr(treesitter, "fetch_grammars", broken)
    out = CliRunner().invoke(app, ["grammars", "fetch"])
    assert out.exit_code == 1
    assert "HTTP 504" in out.output


def test_cli_grammars_status(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pack, "downloaded_languages", treesitter.grammar_languages)
    out = CliRunner().invoke(app, ["grammars", "status"])
    assert out.exit_code == 0, out.output
    assert f"{len(treesitter.grammar_languages())} of" in out.output
    monkeypatch.setattr(pack, "downloaded_languages", lambda: ["python"])
    out = CliRunner().invoke(app, ["grammars", "status"])
    assert out.exit_code == 1
    assert "missing" in out.output and "go" in out.output
