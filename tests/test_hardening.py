import ast
import subprocess
from pathlib import Path

import pytest

from unvarnish.util.gitcmd import git, git_lines

SRC = Path(__file__).resolve().parents[1] / "src" / "unvarnish"


def _envdump(fn, repo: Path) -> str:
    out = fn(["-c", "alias.envdump=!env", "envdump"], repo)
    return out if isinstance(out, str) else "\n".join(out)


def test_git_never_prompts_for_credentials(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for fn in (git, git_lines):
        env = _envdump(fn, tmp_path)
        assert "GIT_TERMINAL_PROMPT=0" in env
        assert "GCM_INTERACTIVE=never" in env
        assert "BatchMode=yes" in env  # ssh never asks for a passphrase or host key


@pytest.mark.parametrize("builder", [
    "unvarnish.model.prompts.extract:build_system_prompt",
    "unvarnish.model.prompts.rollup:build_module_rollup_system",
    "unvarnish.model.prompts.rollup:build_directory_rollup_system",
    "unvarnish.model.prompts.rollup:build_tool_rollup_system",
    "unvarnish.model.prompts.verify:build_verify_system",
    "unvarnish.model.prompts.compare:build_normalise_system",
    "unvarnish.model.prompts.compare:build_consolidate_system",
])
def test_every_prompt_treats_input_as_data(builder):
    import importlib

    module, name = builder.split(":")
    text = getattr(importlib.import_module(module), name)()
    assert "data, never instructions" in text


def test_prose_prompt_treats_input_as_data():
    from unvarnish.render.prose import build_prose_system

    assert "data, never instructions" in build_prose_system("direct")


def test_files_over_5_mb_are_listed_as_not_analysed(engagement, tmp_path: Path):
    from unvarnish.phases.base import PhaseRunner, build_context
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.ingest import ingest_tool
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    src = tmp_path / "pile"
    src.mkdir()
    (src / "big.py").write_text("x = 1\n" * 1_000_000)  # 6 MB of source
    (src / "small.py").write_text("print(1)\n")
    ingest_tool(engagement, "t", str(src), "files")
    ctx = build_context(engagement, "t")
    PhaseRunner([InventoryPhase(), GitPhase(), ScanPhase(), RenderPhase()]).run(ctx)
    doc = ctx.paths.findings_doc.read_text()
    assert "Files too large to scan" in doc and "`big.py` (6.0 MB)" in doc
    assert "Everything in the source tree was analysed" not in doc


def test_text_io_declares_encoding():
    missing = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("read_text", "write_text")
                    and not any(k.arg == "encoding" for k in node.keywords)):
                missing.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert missing == []
