"""Scale tests.

The full pipeline on a real repository with schema-filled fake replies is skipped unless
UNVARNISH_SCALE_REPO points at a repository. It exercises the machinery (splitting, thousands
of unit and module artifacts, hierarchical rollup, three documents) without spending tokens;
run it before a large engagement to catch pipeline regressions:

    UNVARNISH_SCALE_REPO=~/Projects/ESCAPESUITE uv run pytest --no-cov tests/test_scale.py -s -v
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.conftest import HTML_SAMPLE, model_config
from unvarnish.analysis import treesitter
from unvarnish.analysis.metrics import compute_metrics
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.budget import BudgetTracker
from unvarnish.phases import default_phases
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.ingest import ingest_tool

REPO = os.environ.get("UNVARNISH_SCALE_REPO")


def test_metrics_walk_each_tree_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """UNVAR-54: functions, nesting and comment lines come from one walk of each parse tree.

    Three walks per file cost 201 s of a 205 s inventory on a 600,000-line tool."""
    walks: list[object] = []
    real_walk = treesitter._walk

    def spy(root, *args, **kwargs):
        walks.append(root)
        return real_walk(root, *args, **kwargs)

    monkeypatch.setattr(treesitter, "_walk", spy)
    files = {
        "m.py": ("python", b"# c\ndef f(x):\n    if x:\n        return 1\n", 1),
        "m.js": ("javascript", b"// c\nfunction f(x) { if (x) { return () => 1; } }\n", 1),
        "index.html": ("html", HTML_SAMPLE.encode(), 2),  # one parse per script block
    }
    for name, (language, data, parses) in files.items():
        (tmp_path / name).write_bytes(data)
        walks.clear()
        m = compute_metrics(tmp_path / name, name, language)
        assert m.metrics_method == "treesitter"
        assert m.functions and m.max_nesting
        assert len(walks) == parses, name


@pytest.mark.skipif(not REPO, reason="set UNVARNISH_SCALE_REPO=/path/to/repo")
def test_full_pipeline_on_real_repo(tmp_path: Path, fake_llm):
    fake_llm.autofill = True
    eng = Engagement.create(tmp_path / "scale", client="Scale")
    conf = model_config(fake_llm)
    conf["pipeline"] = {"concurrency": 8, "rollup_input_tokens": 4000}  # force chunking
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(), **conf})
    eng.save_config()
    ingest_tool(eng, "scale", str(Path(REPO).expanduser()), "link")
    ctx = build_context(eng, "scale", budget=BudgetTracker(None))
    timings: list[tuple[str, float, str]] = []
    for phase in default_phases():
        t0 = time.monotonic()
        result = phase.run(ctx)
        timings.append((phase.name, time.monotonic() - t0, result.message or ""))
        assert result.status == PhaseStatus.ok, (phase.name, result.model_dump())
    print()
    for name, secs, msg in timings:
        print(f"{name:16s} {secs:8.1f}s  {msg}")
    print(f"requests served: {len(fake_llm.requests)}")
    print(f"engagement: {eng.root}")
    for doc in (ctx.paths.findings_doc, ctx.paths.architecture_doc, ctx.paths.requirements_doc):
        assert doc.exists() and doc.stat().st_size > 500, doc
