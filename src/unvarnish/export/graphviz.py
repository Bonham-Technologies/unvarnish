from __future__ import annotations

import subprocess

from unvarnish.render.diagram import Diagram

SHAPES_DOT: dict[str, str] = {
    "actor": "ellipse", "tool": "box3d", "module": "box", "store": "cylinder",
    "external": "hexagon",
}


def dot_label(text: str) -> str:
    """Escape a label for a double-quoted DOT string."""
    return (text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "")
            .replace("\n", "\\n"))


def to_dot(d: Diagram) -> str:
    """The DOT rendering of a Diagram: the same model the Mermaid emitter draws."""
    ids = {n.id: f"n{i}" for i, n in enumerate(d.nodes)}
    by_id = {n.id: n for n in d.nodes}
    grouped = {nid for g in d.groups for nid in g.nodes}
    lines = ["digraph {", "    rankdir=LR;", '    node [fontname="Helvetica", fontsize=10];',
             '    edge [fontname="Helvetica", fontsize=9];']
    for n in d.nodes:
        if n.id not in grouped:
            lines.append(f'    {ids[n.id]} [label="{dot_label(n.label)}", '
                         f'shape={SHAPES_DOT[n.kind]}];')
    for g in d.groups:
        lines.append(f"    subgraph cluster_{g.id} {{")
        lines.append(f'        label="{dot_label(g.label)}"; style=rounded; color=gray;')
        for nid in g.nodes:
            if nid in by_id:
                n = by_id[nid]
                lines.append(f'        {ids[n.id]} [label="{dot_label(n.label)}", '
                             f'shape={SHAPES_DOT[n.kind]}];')
        lines.append("    }")
    for e in d.edges:
        if e.source in ids and e.target in ids:
            label = f' [label="{dot_label(e.label)}"]' if e.label else ""
            lines.append(f"    {ids[e.source]} -> {ids[e.target]}{label};")
    lines.append("}")
    return "\n".join(lines)


def render_with_dot(dot_src: str, fmt: str = "svg", dot: str = "dot") -> bytes:
    """Run Graphviz on DOT source and return the image bytes."""
    proc = subprocess.run([dot, f"-T{fmt}"], input=dot_src.encode("utf-8"),
                          capture_output=True, timeout=120)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"dot exited {proc.returncode}: {err[:300]}")
    return proc.stdout
