from pathlib import Path

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.artifacts import read_artifact
from unvarnish.export.markdown import DIAGRAM_MARKER, prepare_markdown
from unvarnish.phases.compare import run_comparison
from unvarnish.render.diagram import Diagram, Node
from unvarnish.schemas.diagrams import DiagramSet

MD = """# Doc

Intro.

<!-- unvarnish-diagram: context -->
```mermaid
flowchart LR
    n0["x"]
```

Text after.

<!-- unvarnish-diagram: missing -->
```mermaid
flowchart LR
```

```mermaid
flowchart LR
    n9["unmarked stays"]
```
"""


def _fake_render(src: str, fmt: str) -> bytes:
    if "boom" in src:
        raise RuntimeError("dot: boom")
    return f"<svg>{fmt}</svg>".encode()


def test_prepare_markdown_rewrites_marked_fences(tmp_path: Path):
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="x")])}
    out, failures = prepare_markdown(MD, diagrams, tmp_path / "images", render=_fake_render)
    alt = "Context diagram: who uses the tool and the systems it connects to"
    assert f"![{alt}](images/context.svg)" in out
    assert (tmp_path / "images" / "context.svg").read_bytes() == b"<svg>svg</svg>"
    assert "flowchart LR\n    n0" not in out  # the marked fence is gone
    assert 'n9["unmarked stays"]' in out  # an unmarked fence is left alone
    assert "Text after." in out
    assert failures == ["missing: no diagram with that name",
                        "1 Mermaid block without an unvarnish-diagram marker was left as text"]
    assert "(diagram 'missing' unavailable" in out


def test_prepare_markdown_keeps_going_when_a_diagram_fails(tmp_path: Path):
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="boom")])}
    out, failures = prepare_markdown(MD, diagrams, tmp_path / "img", render=_fake_render,
                                     image_format="png")
    assert failures and failures[0].startswith("context: dot: boom")
    assert "(diagram 'context' unavailable" in out and "![" not in out.split("Text after")[0]
    assert DIAGRAM_MARKER.format(name="context") not in out


def test_render_phases_write_diagram_sets_and_markers(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    paths = engagement.tool_paths("alpha")
    tool_set = read_artifact(paths.diagrams, DiagramSet).data
    assert set(tool_set.diagrams) == {"context", "modules"}
    assert tool_set.diagrams["context"].nodes[0].kind == "tool"
    arch = paths.architecture_doc.read_text()
    assert "<!-- unvarnish-diagram: context -->\n```mermaid" in arch
    assert "<!-- unvarnish-diagram: modules -->\n```mermaid" in arch
    cmp_set = read_artifact(engagement.comparison_diagrams, DiagramSet).data
    assert set(cmp_set.diagrams) == {"integration"}
    assert "<!-- unvarnish-diagram: integration -->\n```mermaid" in (
        engagement.comparison_doc.read_text())
