from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.schemas.toolmodel import ToolModel

Kind = Literal["actor", "tool", "module", "store", "external"]
SHAPES: dict[str, tuple[str, str]] = {
    "actor": ("([", "])"), "tool": ("[[", "]]"), "module": ("[", "]"),
    "store": ("[(", ")]"), "external": ("{{", "}}"),
}


class Node(BaseModel):
    id: str
    label: str
    kind: Kind = "module"


class Edge(BaseModel):
    source: str
    target: str
    label: str | None = None


class Group(BaseModel):
    id: str
    label: str
    nodes: list[str]


class Diagram(BaseModel):
    title: str
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)
    note: str | None = None


def _label(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def to_mermaid(d: Diagram) -> str:
    ids = {n.id: f"n{i}" for i, n in enumerate(d.nodes)}
    by_id = {n.id: n for n in d.nodes}

    def decl(n: Node) -> str:
        open_, close = SHAPES[n.kind]
        return f'{ids[n.id]}{open_}"{_label(n.label)}"{close}'

    grouped = {nid for g in d.groups for nid in g.nodes}
    lines = ["flowchart LR"]
    lines += [f"    {decl(n)}" for n in d.nodes if n.id not in grouped]
    for g in d.groups:
        lines.append(f'    subgraph {g.id}["{_label(g.label)}"]')
        lines += [f"        {decl(by_id[nid])}" for nid in g.nodes if nid in by_id]
        lines.append("    end")
    for e in d.edges:
        if e.source in ids and e.target in ids:
            label = f'|"{_label(e.label)}"|' if e.label else ""
            lines.append(f"    {ids[e.source]} -->{label} {ids[e.target]}")
    return "\n".join(lines)


def context_diagram(tm: ToolModel) -> Diagram:
    nodes = [Node(id="tool", label=tm.tool, kind="tool")]
    edges: list[Edge] = []
    for i, a in enumerate(tm.actors):
        nodes.append(Node(id=f"actor{i}", label=a.name, kind="actor"))
        edges.append(Edge(source=f"actor{i}", target="tool", label="uses"))
    for i, s in enumerate(tm.data_stores):
        nodes.append(Node(id=f"store{i}", label=s.name, kind="store"))
        edges.append(Edge(source="tool", target=f"store{i}", label=s.kind))
    for i, x in enumerate(tm.external_systems):
        nid = f"ext{i}"
        nodes.append(Node(id=nid, label=x.name, kind="external"))
        if x.direction in ("outbound", "both"):
            edges.append(Edge(source="tool", target=nid, label=x.kind))
        if x.direction in ("inbound", "both"):
            edges.append(Edge(source=nid, target="tool", label=x.kind))
    return Diagram(title=f"{tm.tool}: context", nodes=nodes, edges=edges)


def module_diagram(tm: ToolModel, max_nodes: int = 30) -> Diagram:
    entries = tm.module_map
    inbound = Counter(d for m in entries for d in m.depends_on)
    ranked = sorted(entries, key=lambda m: (-(len(m.depends_on) + inbound[m.path]), m.path))
    chosen = ranked[:max_nodes]
    paths = {m.path for m in chosen}
    nodes = [Node(id=m.path, label="/".join(m.path.split("/")[-2:]), kind="module")
             for m in chosen]
    edges = [Edge(source=m.path, target=d) for m in chosen for d in m.depends_on if d in paths]
    dirs: dict[str, list[str]] = {}
    for m in chosen:
        top = m.path.rsplit("/", 1)[0] if "/" in m.path else ""
        dirs.setdefault(top, []).append(m.path)
    groups = ([Group(id=f"g{i}", label=d, nodes=ns)
               for i, (d, ns) in enumerate(sorted(dirs.items())) if d]
              if len(dirs) > 1 else [])
    note = (f"Showing the {len(chosen)} most connected of {len(entries)} modules."
            if len(entries) > max_nodes else None)
    return Diagram(title=f"{tm.tool}: modules", nodes=nodes, edges=edges, groups=groups,
                   note=note)
