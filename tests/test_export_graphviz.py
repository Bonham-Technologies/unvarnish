import shutil

import pytest

from unvarnish.export.graphviz import dot_label, render_with_dot, to_dot
from unvarnish.render.diagram import Diagram, Edge, Group, Node


def _diagram() -> Diagram:
    return Diagram(title="t", nodes=[
        Node(id="a", label='Admin "finance"', kind="actor"),
        Node(id="t", label="expense-bot", kind="tool"),
        Node(id="s", label="expenses db", kind="store"),
        Node(id="x", label="Stripe\nAPI", kind="external"),
        Node(id="m", label="app.py", kind="module")],
        edges=[Edge(source="a", target="t", label="uses"), Edge(source="t", target="s"),
               Edge(source="t", target="nowhere")],
        groups=[Group(id="g1", label="apps", nodes=["m"])])


def test_to_dot_escapes_labels():
    assert dot_label('say "hi"\\now') == 'say \\"hi\\"\\\\now'
    assert dot_label("two\nlines") == "two\\nlines"
    src = to_dot(_diagram())
    assert src.startswith("digraph {")
    assert 'n0 [label="Admin \\"finance\\"", shape=ellipse]' in src
    assert 'n1 [label="expense-bot", shape=box3d]' in src
    assert 'n2 [label="expenses db", shape=cylinder]' in src
    assert 'n3 [label="Stripe\\nAPI", shape=hexagon]' in src
    assert 'subgraph cluster_g1 {' in src and 'label="apps"' in src and 'n4 [label="app.py"' in src
    assert 'n0 -> n1 [label="uses"]' in src and "n1 -> n2" in src
    assert "nowhere" not in src  # dangling edge dropped, as in the Mermaid emitter
    assert "rankdir=LR" in src


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz not installed")
def test_render_with_dot_produces_svg():
    svg = render_with_dot(to_dot(_diagram()))
    assert svg.lstrip().startswith(b"<?xml") or b"<svg" in svg
    assert b"app.py" in svg
    assert b"expense-bot" in svg or b"expense&#45;bot" in svg  # dot escapes "-" in SVG
    png = render_with_dot(to_dot(_diagram()), fmt="png")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz not installed")
def test_render_with_dot_reports_failures():
    with pytest.raises(RuntimeError, match="dot"):
        render_with_dot("this is not dot")
