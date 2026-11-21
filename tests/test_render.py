from tests.conftest import LEAKED_DB_URL, LEAKED_KEY
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context, is_fresh
from unvarnish.phases.extract import ExtractPhase
from unvarnish.phases.git import GitPhase
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.phases.render import RenderPhase
from unvarnish.phases.rollup_modules import RollupModulesPhase
from unvarnish.phases.rollup_tool import RollupToolPhase
from unvarnish.phases.scan import ScanPhase
from unvarnish.phases.verify import VerifyPhase
from unvarnish.render.markdown import fmt_int, make_env, pct
from unvarnish.schemas.render import RenderState


def _render(eng: Engagement, name: str):
    ctx = build_context(eng, name)
    results = PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    return ctx.paths.findings_doc.read_text(), ctx


def test_filters():
    assert fmt_int(3010) == "3,010"
    assert fmt_int(None) == "—"
    assert pct(0.966) == "97%"
    assert pct(None) == "—"


def test_findings_document_content(ingested):
    doc, ctx = _render(*ingested)
    assert doc.startswith("# expense-bot: Findings")
    assert "Acme" in doc and "Bonham Technologies" in doc
    assert "## By the numbers" in doc
    assert "## Findings" in doc
    for title in ("AWS access key ID in git history", "Oversized file", "Very large function",
                  "Single-author concentration", "No automated tests"):
        assert title in doc, title
    assert "### Critical" not in doc  # synthetic repo has history-only secrets, which are high
    assert "### High" in doc
    assert "## Not analysed" in doc
    assert "vendored:node_modules" in doc and "node_modules/leftpad/index.js" in doc
    assert "CLAUDE.md" in doc  # AI tooling indicator row
    assert LEAKED_KEY not in doc and "hunter2" not in doc and LEAKED_DB_URL not in doc
    assert "Dependency vulnerabilities | not checked" in doc


def test_render_state_and_freshness(ingested):
    doc, ctx = _render(*ingested)
    state = read_artifact(ctx.paths.render_state, RenderState).data
    assert "findings.md" in state.documents
    assert is_fresh(RenderPhase(), ctx)
    results = PhaseRunner([RenderPhase()]).run(ctx)
    assert results[0].status == PhaseStatus.skipped


def test_detail_from_change_makes_render_stale_only(ingested):
    """UNVAR-51: the findings template reads report.detail_from, so it is a render input."""
    eng, name = ingested
    _, ctx = _render(eng, name)
    model_phases = [ExtractPhase(), RollupModulesPhase(), RollupToolPhase(), VerifyPhase()]
    before = [p.inputs_hash(ctx) for p in model_phases]
    assert is_fresh(RenderPhase(), ctx)
    eng.config.report.detail_from = "critical"
    ctx = build_context(eng, name)
    assert not is_fresh(RenderPhase(), ctx)
    assert [p.inputs_hash(ctx) for p in model_phases] == before  # no model phase reruns
    results = PhaseRunner([RenderPhase()]).run(ctx)
    assert results[0].status == PhaseStatus.ok


def test_template_override(ingested):
    eng, name = ingested
    tdir = eng.root / "templates"
    tdir.mkdir()
    (tdir / "findings.md.j2").write_text("CUSTOM {{ tool.name }} {{ numbers.total_findings }}\n")
    doc, ctx = _render(eng, name)
    assert doc.startswith("CUSTOM expense-bot ")
    # changing the template invalidates freshness
    (tdir / "findings.md.j2").write_text("OTHER {{ tool.name }}\n")
    assert not is_fresh(RenderPhase(), ctx)


def test_make_env_strict_undefined():
    import pytest
    from jinja2 import StrictUndefined, UndefinedError

    env = make_env()
    assert env.undefined is StrictUndefined
    with pytest.raises(UndefinedError):
        env.from_string("{{ nope }}").render()


# --- fixes from the first real-repo run (ESCAPESUITE) -----------------------
def test_not_analysed_bullets_render_on_separate_lines(engagement: Engagement, tmp_path):
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    (pile / "node_modules" / "x").mkdir(parents=True)
    (pile / "node_modules" / "x" / "i.js").write_text("1\n")
    (pile / "package-lock.json").write_text("{}\n")
    (pile / ".gitignore").write_text("*.log\n")
    (pile / "app.log").write_text("log\n")
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    section = doc.split("## Not analysed", 1)[1]
    bullet_lines = [ln for ln in section.splitlines() if ln.startswith("- **")]
    assert len(bullet_lines) == 3, section
    assert all(ln.count("- **") == 1 for ln in bullet_lines)


def test_not_analysed_names_dirs_skipped_at_ingest(engagement: Engagement, tmp_path):
    import subprocess

    from unvarnish.phases.ingest import ingest_tool

    repo = tmp_path / "app"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("node_modules/\n.venv/\n")
    (repo / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e.com", "commit", "-q",
                    "-m", "i"], cwd=repo, check=True)
    for d in ("node_modules/x", ".venv/lib"):
        (repo / d).mkdir(parents=True)
        (repo / d / "f.js").write_text("1\n")
    ingest_tool(engagement, "app", str(repo), "repo")
    doc, _ = _render(engagement, "app")
    section = doc.split("## Not analysed", 1)[1].split("\n## ", 1)[0]
    assert "skipped when the repository was copied" in section, section
    assert "`node_modules`" in section and "`.venv`" in section
    assert "| Files analysed / total | 2 / 2 |" in doc  # the skipped files are not counted


def test_not_analysed_notes_tracked_despite_gitignore(engagement: Engagement, tmp_path):
    """UNVAR-28: a committed file a .gitignore rule matches is analysed, and the document says
    so, since a reader checking the .gitignore would expect it left out."""
    from tests.conftest import _git
    from unvarnish.phases.ingest import ingest_tool

    repo = tmp_path / "app"
    repo.mkdir()
    (repo / ".gitignore").write_text("config.json\n", encoding="utf-8")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "config.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "add", "-f", "config.json")
    _git(repo, "commit", "-q", "-m", "i")
    ingest_tool(engagement, "app", str(repo), "repo")
    doc, _ = _render(engagement, "app")
    section = doc.split("## Not analysed", 1)[1].split("\n## ", 1)[0]
    assert "because they are tracked in git (1): `config.json`" in section, section


def test_not_analysed_says_secrets_scanner_read_gitignored_files(engagement: Engagement, tmp_path):
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / ".gitignore").write_text(".env\n")
    (pile / ".env").write_text("DEBUG=1\n")
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    section = doc.split("## Not analysed", 1)[1]
    assert "**gitignore**" in section
    assert "The secrets scanner still read gitignored text files" in section
    # it did not read all of them: caches, vendored directories and large files are skipped
    sentence = section.split("The secrets scanner still read", 1)[1].split("\n", 1)[0]
    assert "vendored directories" in sentence and "over 5 MB" in sentence


def test_not_analysed_omits_gitignore_sentence_without_gitignored_files(
    engagement: Engagement, tmp_path
):
    from unvarnish.phases.ingest import ingest_tool

    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    doc, _ = _render(engagement, "pile")
    assert "gitignored text files" not in doc


def test_inert_block_neutralises_every_block_opener():
    """UNVAR-76: model text in a paragraph slot cannot open a block."""
    from unvarnish.render.markdown import inert_block

    assert inert_block("A plain sentence with *emphasis*, `code` and [a link](x).") == \
        "A plain sentence with *emphasis*, `code` and [a link](x)."
    cases = {
        "## X": "\\## X", "# X": "\\# X", "> q": "\\> q", "- item": "\\- item",
        "* item": "\\* item", "+ item": "\\+ item", "1. item": "1\\. item",
        "12) item": "12\\) item", "```": "\\```", "~~~python": "\\~~~python",
        "| a |": "\\| a |", "---|---": "\\---|---", ":--|--:": "\\:--|--:", "---": "\\---",
        "***": "\\***", "_ _ _": "\\_ _ _", "===": "\\===", "    indented code": "indented code",
        "[ref]: http://x": "\\[ref]: http://x", "[^1]: note": "\\[^1]: note",
    }
    for raw, safe in cases.items():
        assert inert_block(raw) == safe, raw
    assert inert_block("one\n\n## two\n\nthree") == "one\n\n\\## two\n\nthree"
    assert inert_block(None) == "" and inert_block("#hashtag and 3 files") == \
        "#hashtag and 3 files"
    assert inert_block("<!-- x") == "\\<!-- x"
    assert inert_block("[a\\]b]: http://x") == "\\[a\\]b]: http://x"


def test_prose_cannot_open_a_section_heading():
    """UNVAR-76: a prose block keeps its own sub-headings but not the outline's levels."""
    from unvarnish.render.markdown import cap_headings

    text = "Intro.\n\n## Fake section\n\n# Fake title\n\n### Allowed\n\n- a list stays\n"
    assert cap_headings(text) == (
        "Intro.\n\n\\## Fake section\n\n\\# Fake title\n\n### Allowed\n\n- a list stays\n")
    assert cap_headings("Title\n===\n") == "Title\n\\===\n"
    assert cap_headings("Title\n---") == "Title\n\\---"
    assert cap_headings("Plain prose.") == "Plain prose."
    assert cap_headings("- ## Fake\n> # Fake\n1. ## Fake") == \
        "- \\## Fake\n> \\# Fake\n1. \\## Fake"
    assert cap_headings("Fake\n-") == "Fake\n\\-"
    assert cap_headings("> Fake\n> ---") == "> Fake\n> \\---"
    assert cap_headings("<!--\nhidden") == "\\<!--\nhidden"


def test_model_list_items_cannot_open_a_block():
    """UNVAR-76: a template list item filled with `cell` also goes through `inert_block`."""
    import re
    from pathlib import Path

    templates = Path(__file__).parent.parent / "src/unvarnish/render/templates"
    bare = [f"{p.name}:{n}" for p in sorted(templates.glob("*.md.j2"))
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if re.match(r"\s*- \{\{[^}]*\| cell \}\}\s*$", line)]
    assert bare == []
