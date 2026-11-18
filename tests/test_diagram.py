from unvarnish.render.diagram import (
    Diagram,
    Edge,
    Group,
    Node,
    context_diagram,
    module_diagram,
    to_mermaid,
)
from unvarnish.schemas.cost import Usage
from unvarnish.schemas.toolmodel import (
    Actor,
    DataStore,
    ExternalSystem,
    ModuleMapEntry,
    ToolModel,
)


def _tm(module_map=None, externals=None) -> ToolModel:
    return ToolModel(
        tool="expense-bot", purpose="p", actors=[Actor(name="admin", description="d")],
        entry_points=[], data_stores=[DataStore(name="expenses db", kind="db", description="d")],
        external_systems=externals or [
            ExternalSystem(name="AWS S3", kind="storage", direction="outbound", description="d"),
            ExternalSystem(name="Slack", kind="http", direction="both", description="d"),
            ExternalSystem(name="Webhook", kind="http", direction="inbound", description="d")],
        internal_stack=[], module_map=module_map or [], data_flows=[],
        deployment_assumptions=[], capabilities=[], business_rules=[], open_questions=[],
        confidence=0.5, backend="b", model="m", usage=Usage(), prompt_version="v",
    )


def test_to_mermaid_shapes_groups_and_escaping():
    d = Diagram(title="t", nodes=[
        Node(id="a", label='Say "hi"', kind="actor"), Node(id="t", label="tool", kind="tool"),
        Node(id="s", label="db", kind="store"), Node(id="x", label="ext", kind="external"),
        Node(id="m", label="mod", kind="module")],
        edges=[Edge(source="a", target="t", label="uses"), Edge(source="t", target="s"),
               Edge(source="t", target="missing")],
        groups=[Group(id="g1", label="apps", nodes=["m"])])
    out = to_mermaid(d)
    assert out.splitlines()[0] == "flowchart LR"
    assert "n0([\"Say 'hi'\"])" in out and 'n1[["tool"]]' in out
    assert 'n2[("db")]' in out and 'n3{{"ext"}}' in out
    assert 'subgraph g1["apps"]' in out and 'n4["mod"]' in out and "    end" in out
    assert 'n0 -->|"uses"| n1' in out and "n1 --> n2" in out
    assert "missing" not in out


def test_context_diagram_edges_follow_direction():
    d = context_diagram(_tm())
    ids = {n.label: n.id for n in d.nodes}
    edges = {(e.source, e.target) for e in d.edges}
    assert (ids["admin"], ids["expense-bot"]) in edges
    assert (ids["expense-bot"], ids["expenses db"]) in edges
    assert (ids["expense-bot"], ids["AWS S3"]) in edges
    assert (ids["Webhook"], ids["expense-bot"]) in edges
    assert (ids["Slack"], ids["expense-bot"]) in edges
    assert (ids["expense-bot"], ids["Slack"]) in edges
    assert {n.kind for n in d.nodes} == {"actor", "tool", "store", "external"}


def test_module_diagram_caps_and_groups():
    entries = [ModuleMapEntry(path=f"apps/{'ab'[i % 2]}/m{i}.py", role="r",
                              depends_on=[f"apps/{'ab'[(i + 1) % 2]}/m{i + 1}.py"])
               for i in range(40)]
    d = module_diagram(_tm(module_map=entries), max_nodes=25)
    assert len(d.nodes) == 25 and d.note and "25 most connected of 40" in d.note
    assert {g.label for g in d.groups} == {"apps/a", "apps/b"}
    shown = {n.id for n in d.nodes}
    assert all(e.source in shown and e.target in shown for e in d.edges)
    small = module_diagram(_tm(module_map=entries[:3]))
    assert small.note is None and len(small.nodes) == 3
    assert {n.label for n in small.nodes} == {"a/m0.py", "b/m1.py", "a/m2.py"}
