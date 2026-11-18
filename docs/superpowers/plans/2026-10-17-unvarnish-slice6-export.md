# Unvarnish Slice 6: Export and Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `unvarnish export` (DOCX, self-contained HTML, PDF with the consultant's branding, diagrams rendered to SVG with Graphviz), plus the Docker image and PyPI packaging.

**Architecture:** Render phases now also write the `Diagram` models they drew (`docs/diagrams.json`, `comparison/diagrams.json`) and mark each Mermaid fence with an HTML comment naming its diagram. The exporter (`src/unvarnish/export/`) rewrites a document's marked fences into images rendered by `dot` from a second emitter over the same `Diagram` model, then runs pandoc with the bundled or configured reference DOCX and stylesheet. Missing external tools produce one clear message with install hints and exit 2; a document that fails to convert is recorded and the rest still export. Distribution adds a Dockerfile bundling pandoc, Graphviz, weasyprint, and git, PyPI metadata, a schema-version guard, and CI coverage of the real conversions.

**Tech Stack:** Python 3.12+, pandoc (subprocess), Graphviz `dot` (subprocess), weasyprint (pandoc PDF engine), Docker. No new Python dependencies.

**Spec:** `docs/superpowers/specs/2026-10-15-unvarnish-design.md` sections 3 (`export`), 4 (`exports/`), 8.7, 11, 12.

## Global Constraints

- Python 3.12+, Pydantic v2, ruff `line-length = 100`, select `E,F,I,UP,B`; PEP 695 generics.
- Spec 11: DOCX uses `--reference-doc` from `report.branding.reference_docx` with a bundled neutral fallback; HTML is a self-contained single file with embedded CSS from `report.branding.html_css` or the bundled stylesheet, diagrams inlined as SVG; PDF goes through pandoc's HTML route with `weasyprint`. "Diagrams are rendered to SVG with Graphviz before conversion. If `pandoc` or `dot` is missing on a laptop install, the command explains how to install them and exits 2."
- Spec 8.7: one `Diagram` model, two emitters (Mermaid for Markdown, SVG via `dot` for exports), "no duplicated logic".
- Spec 4: exports land in `exports/<doc>-<tool>-<timestamp>.<ext>`; "The export step therefore always starts from the latest render."
- Spec 3: `unvarnish export [--format docx|pdf|html|all] [--template PATH] [--doc DOC ...]`. Exit codes 0/1/2/3 as elsewhere.
- Spec 12: PyPI package `unvarnish` with console scripts `unvarnish` and `unv`; Docker image `ghcr.io/bonham-technologies/unvarnish` bundling pandoc, Graphviz, weasyprint (gitleaks, osv-scanner, and the OSV database are slice 7 with their scanners); engagement mounted as a volume; the runner refuses an engagement whose `schema_version` it does not support.
- Secrets never reach exports beyond what the Markdown already carries (redacted upstream). No absolute paths in artifacts; `exports/` file names are relative.
- Tests that need pandoc, `dot`, or weasyprint are skipped when the tool is absent (`pytest.mark.skipif(shutil.which(...) is None)`); pure logic (DOT emission, fence rewriting, command building, tool detection messages) is tested without them. CI installs pandoc and Graphviz so the real conversions run there.
- Commit messages end with the session's attribution lines. Lint touched files per task, the whole tree at the end.

## Review Focus

1. **pandoc or `dot` missing** on a laptop. One message naming each missing tool with a `brew` and an `apt` hint, exit 2, nothing half-written in `exports/`. (Task 3: `test_export_missing_tools_exits_2_with_hints`.)
2. **A diagram that `dot` cannot render** (bad label, dot crash). The document still exports with a visible placeholder where the diagram was; the failure is reported. (Task 1: `test_prepare_markdown_keeps_going_when_a_diagram_fails`.)
3. **A tool whose documents were never rendered** (scanner-only engagement, or render failed). `export` says which documents were skipped and why, exports the rest, exits 0 if anything exported and 1 if nothing did. (Task 3: `test_export_skips_missing_documents`.)
4. **Model-written text with characters that break DOT** (quotes, newlines, backslashes) in node labels. The DOT emitter escapes them; `dot` succeeds. (Task 1: `test_to_dot_escapes_labels`.)
5. **An engagement written by a newer Unvarnish** (`schema_version: 2`). Every command refuses it with a clear message and exit 2 instead of misreading artifacts. (Task 4: `test_newer_schema_version_is_refused`.)
6. **`--template` with the wrong kind of file** (a `.css` for DOCX, a `.docx` for HTML). The exporter explains what it expected and exits 2 before running pandoc. (Task 3: `test_export_template_kind_mismatch_exits_2`.)

## File Structure

Created:

- `src/unvarnish/export/__init__.py` (empty), `src/unvarnish/export/graphviz.py` (`to_dot`, `render_with_dot`), `src/unvarnish/export/markdown.py` (`DIAGRAM_MARKER_RE`, `prepare_markdown`), `src/unvarnish/export/tools.py` (`INSTALL_HINTS`, `missing_tools`, `ToolsMissing`), `src/unvarnish/export/pandoc.py` (`build_pandoc_command`, `run_pandoc`, `bundled_asset`), `src/unvarnish/export/exporter.py` (`DOC_NAMES`, `ExportItem`, `ExportReport`, `export_engagement`), `src/unvarnish/export/assets/report.css`, `src/unvarnish/export/assets/reference.docx`.
- `src/unvarnish/schemas/diagrams.py` (`DiagramSet`).
- `Dockerfile`, `.dockerignore`.
- `tests/test_export_graphviz.py`, `tests/test_export_markdown.py`, `tests/test_export_pandoc.py`, `tests/test_export_cli.py`, `tests/test_distribution.py`.

Modified:

- `src/unvarnish/render/architecture.py`, `comparison.py` — return `diagrams` alongside the Mermaid text.
- `src/unvarnish/render/templates/architecture.md.j2`, `comparison.md.j2` — marker comments before Mermaid fences.
- `src/unvarnish/phases/render.py`, `src/unvarnish/phases/compare.py` — write `diagrams.json`.
- `src/unvarnish/engagement.py` — `ToolPaths.diagrams`, `Engagement.comparison_diagrams`.
- `src/unvarnish/config.py` — `SUPPORTED_SCHEMA_VERSION`, refusal in `load_config`.
- `src/unvarnish/cli.py` — `export` command.
- `pyproject.toml` — classifiers, URLs, package data for assets.
- `.github/workflows/ci.yml` — install pandoc and graphviz; `uv build`.
- `README.md`, `scripts/smoke.sh` (export at the end).

---

### Task 1: DOT emitter, diagram artifacts, and fence rewriting

**Files:**
- Create: `src/unvarnish/export/__init__.py`, `src/unvarnish/export/graphviz.py`, `src/unvarnish/export/markdown.py`, `src/unvarnish/schemas/diagrams.py`
- Modify: `src/unvarnish/render/architecture.py`, `src/unvarnish/render/comparison.py`, `src/unvarnish/render/templates/architecture.md.j2`, `src/unvarnish/render/templates/comparison.md.j2`, `src/unvarnish/phases/render.py`, `src/unvarnish/phases/compare.py`, `src/unvarnish/engagement.py`
- Test: `tests/test_export_graphviz.py`, `tests/test_export_markdown.py`

**Interfaces:**
- Consumes: `Diagram`, `Node`, `Edge`, `Group` (`render/diagram.py`), `context_diagram`, `module_diagram`, `integration_diagram`, `write_artifact`/`read_artifact`.
- Produces:
  - `unvarnish.schemas.diagrams.DiagramSet(diagrams: dict[str, Diagram])`.
  - `ToolPaths.diagrams` (`docs/diagrams.json`), `Engagement.comparison_diagrams` (`comparison/diagrams.json`).
  - `unvarnish.export.graphviz`: `SHAPES_DOT: dict[str, str]`, `dot_label(text) -> str`, `to_dot(d: Diagram) -> str`, `render_with_dot(dot_src: str, fmt: str = "svg", dot: str = "dot") -> bytes` (raises `RuntimeError` with stderr on failure).
  - `unvarnish.export.markdown`: `DIAGRAM_MARKER = "<!-- unvarnish-diagram: {name} -->"`, `DIAGRAM_BLOCK_RE`, `prepare_markdown(md: str, diagrams: dict[str, Diagram], image_dir: Path, *, image_format: str = "svg", render: Callable[[str, str], bytes] = render_with_dot) -> tuple[str, list[str]]` (rewritten markdown, list of diagram failures).
  - Templates emit `<!-- unvarnish-diagram: context -->`, `<!-- unvarnish-diagram: modules -->`, `<!-- unvarnish-diagram: integration -->` on the line before the fence; context builders return `"diagrams": {name: Diagram}`; render phases write the set.

- [ ] **Step 1: Write the failing tests**

`tests/test_export_graphviz.py`:

```python
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
    assert b"expense-bot" in svg
    png = render_with_dot(to_dot(_diagram()), fmt="png")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz not installed")
def test_render_with_dot_reports_failures():
    with pytest.raises(RuntimeError, match="dot"):
        render_with_dot("this is not dot")
```

`tests/test_export_markdown.py`:

```python
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
    assert "![context](images/context.svg)" in out
    assert (tmp_path / "images" / "context.svg").read_bytes() == b"<svg>svg</svg>"
    assert "flowchart LR\n    n0" not in out  # the marked fence is gone
    assert 'n9["unmarked stays"]' in out  # an unmarked fence is left alone
    assert "Text after." in out
    assert failures == ["missing: no diagram with that name"]
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_export_graphviz.py tests/test_export_markdown.py -q 2>&1 | tail -3`
Expected: FAIL at import (`ModuleNotFoundError: No module named 'unvarnish.export'`).

- [ ] **Step 3: Write the emitter, the rewriter, and the schema**

`src/unvarnish/export/__init__.py`: empty.

`src/unvarnish/schemas/diagrams.py`:

```python
from __future__ import annotations

from pydantic import BaseModel, Field

from unvarnish.render.diagram import Diagram


class DiagramSet(BaseModel):
    """Artifact docs/diagrams.json (per tool) and comparison/diagrams.json: the diagrams a
    render drew, by the name the document's marker comments use."""

    diagrams: dict[str, Diagram] = Field(default_factory=dict)
```

`src/unvarnish/export/graphviz.py`:

```python
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
```

`src/unvarnish/export/markdown.py`:

```python
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from unvarnish.export.graphviz import render_with_dot, to_dot
from unvarnish.render.diagram import Diagram

DIAGRAM_MARKER = "<!-- unvarnish-diagram: {name} -->"
DIAGRAM_BLOCK_RE = re.compile(
    r"<!-- unvarnish-diagram: (?P<name>[a-z0-9_-]+) -->\n```mermaid\n.*?\n```", re.DOTALL)


def prepare_markdown(md: str, diagrams: dict[str, Diagram], image_dir: Path, *,
                     image_format: str = "svg",
                     render: Callable[[str, str], bytes] = render_with_dot,
                     ) -> tuple[str, list[str]]:
    """Replace each marked Mermaid fence with an image rendered from its Diagram.

    Images are written under `image_dir` and referenced relative to its parent (the pandoc
    resource path). A missing or unrenderable diagram becomes a visible placeholder and a
    recorded failure; the rest of the document is untouched.
    """
    failures: list[str] = []
    image_dir.mkdir(parents=True, exist_ok=True)

    def replace(m: re.Match) -> str:
        name = m.group("name")
        d = diagrams.get(name)
        if d is None:
            failures.append(f"{name}: no diagram with that name")
            return f"*(diagram '{name}' unavailable: not found in diagrams.json)*"
        try:
            data = render(to_dot(d), image_format)
        except Exception as exc:  # one bad diagram never kills an export
            failures.append(f"{name}: {exc}"[:300])
            return f"*(diagram '{name}' unavailable: {str(exc)[:120]})*"
        path = image_dir / f"{name}.{image_format}"
        path.write_bytes(data)
        return f"![{name}]({image_dir.name}/{path.name})"

    return DIAGRAM_BLOCK_RE.sub(replace, md), failures
```

- [ ] **Step 4: Wire the diagrams through render**

In `src/unvarnish/engagement.py`: add `self.diagrams = self.docs / "diagrams.json"` to `ToolPaths.__init__` and a property `comparison_diagrams` returning `self.comparison_dir / "diagrams.json"`.

In `src/unvarnish/render/architecture.py`, keep a reference to the context diagram and return it:

```python
    ctx_diagram = context_diagram(tm)
    ...
        "context_mermaid": to_mermaid(ctx_diagram),
        "module_mermaid": to_mermaid(mod_diagram), "module_diagram_note": mod_diagram.note,
        "diagrams": {"context": ctx_diagram, "modules": mod_diagram},
```

In `src/unvarnish/render/comparison.py` return `"diagrams": {"integration": integration_diagram(cmp)}` (compute the diagram once into a local and reuse it for `integration_mermaid`).

In `src/unvarnish/render/findings.py` and `requirements.py`, return `"diagrams": {}` so every context has the key.

In the templates, put the marker on the line immediately before each fence:

```jinja
<!-- unvarnish-diagram: context -->
```mermaid
{{ context_mermaid }}
```
```

(and `modules`, `integration` likewise).

In `src/unvarnish/phases/render.py`, collect diagrams across documents and write them once after the loop, before the render state (import `DiagramSet`):

```python
        diagrams: dict = {}
        ...
            context = builder(ctx, inp)
            diagrams.update(context.get("diagrams", {}))
        ...
        write_artifact(ctx.paths.diagrams, DiagramSet(diagrams=diagrams), produced_by=self.name,
                       inputs_hash="")
```

In `src/unvarnish/phases/compare.py` `RenderComparisonPhase.run`, after rendering: `write_artifact(eng.comparison_diagrams, DiagramSet(diagrams=context.get("diagrams", {})), produced_by=self.name, inputs_hash="")`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_export_graphviz.py tests/test_export_markdown.py tests/test_render_documents.py tests/test_render_comparison.py -q 2>&1 | tail -3`
Expected: all PASS (the two `dot` tests are skipped when Graphviz is absent).

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/export src/unvarnish/schemas/diagrams.py src/unvarnish/render src/unvarnish/phases/render.py src/unvarnish/phases/compare.py src/unvarnish/engagement.py tests/test_export_graphviz.py tests/test_export_markdown.py
git add src/unvarnish/export src/unvarnish/schemas/diagrams.py src/unvarnish/render src/unvarnish/phases/render.py src/unvarnish/phases/compare.py src/unvarnish/engagement.py tests/test_export_graphviz.py tests/test_export_markdown.py
git commit -m "feat: DOT emitter, diagram artifacts, and marked-fence rewriting for export"
```

---

### Task 2: Tool detection and the pandoc pipeline

**Files:**
- Create: `src/unvarnish/export/tools.py`, `src/unvarnish/export/pandoc.py`, `src/unvarnish/export/assets/report.css`, `src/unvarnish/export/assets/reference.docx`
- Modify: `pyproject.toml` (ship `assets/*` with the wheel)
- Test: `tests/test_export_pandoc.py`

**Interfaces:**
- Consumes: `BrandingConfig` (`config.py`), `prepare_markdown`.
- Produces:
  - `unvarnish.export.tools`: `INSTALL_HINTS: dict[str, str]`, `REQUIRED_BY_FORMAT: dict[str, tuple[str, ...]]` (`docx: (pandoc, dot)`, `html: (pandoc, dot)`, `pdf: (pandoc, dot, weasyprint)`), `missing_tools(formats: Sequence[str], which=shutil.which) -> list[str]`, `ToolsMissing(Exception)` whose message lists each tool with its hint.
  - `unvarnish.export.pandoc`: `bundled_asset(name) -> Path`, `build_pandoc_command(src: Path, fmt: str, out: Path, *, title: str, resource_dir: Path, reference_docx: Path | None, css: Path | None, pandoc: str = "pandoc") -> list[str]`, `run_pandoc(cmd: list[str]) -> None` (raises `RuntimeError` with stderr), `export_markdown(md_path: Path, fmt: str, out: Path, *, diagrams: dict[str, Diagram], branding: BrandingConfig, template: Path | None, work_dir: Path, render=render_with_dot) -> list[str]` (diagram failures; raises `RuntimeError` on conversion failure).
  - Assets: `report.css` (bundled stylesheet), `reference.docx` (generated once with `pandoc -o reference.docx --print-default-data-file reference.docx` and committed).

- [ ] **Step 1: Write the failing tests**

`tests/test_export_pandoc.py`:

```python
import shutil
from pathlib import Path

import pytest

from unvarnish.config import BrandingConfig
from unvarnish.export.pandoc import build_pandoc_command, bundled_asset, export_markdown
from unvarnish.export.tools import INSTALL_HINTS, ToolsMissing, missing_tools
from unvarnish.render.diagram import Diagram, Node

SAMPLE = """# Sample: Findings

**Client:** Acme

## Summary

| Measure | Value |
|---|---|
| Files | 12 |

<!-- unvarnish-diagram: context -->
```mermaid
flowchart LR
    n0["x"]
```

Done.
"""


def test_missing_tools_lists_each_with_hints():
    present = {"pandoc": "/usr/bin/pandoc"}
    missing = missing_tools(["docx", "pdf"], which=lambda t: present.get(t))
    assert missing == ["dot", "weasyprint"]
    assert missing_tools(["html"], which=lambda t: "/x") == []
    msg = str(ToolsMissing(missing))
    assert "dot" in msg and "weasyprint" in msg and "brew install graphviz" in msg
    assert all(tool in INSTALL_HINTS for tool in ("pandoc", "dot", "weasyprint"))


def test_bundled_assets_exist():
    assert bundled_asset("report.css").read_text().strip().startswith(("body", "/*", ":root"))
    assert bundled_asset("reference.docx").stat().st_size > 1000


def test_build_pandoc_command_per_format(tmp_path: Path):
    src = tmp_path / "doc.md"
    docx = build_pandoc_command(src, "docx", tmp_path / "o.docx", title="T",
                                resource_dir=tmp_path, reference_docx=Path("/r.docx"), css=None)
    assert docx[:4] == ["pandoc", str(src), "-f", "gfm"] and "--reference-doc=/r.docx" in docx
    assert "-t" in docx and docx[docx.index("-t") + 1] == "docx"
    html = build_pandoc_command(src, "html", tmp_path / "o.html", title="T",
                                resource_dir=tmp_path, reference_docx=None, css=Path("/s.css"))
    assert "--standalone" in html and "--embed-resources" in html and "--css=/s.css" in html
    assert "--metadata=pagetitle:T" in html and f"--resource-path={tmp_path}" in html
    pdf = build_pandoc_command(src, "pdf", tmp_path / "o.pdf", title="T",
                               resource_dir=tmp_path, reference_docx=None, css=Path("/s.css"))
    assert "--pdf-engine=weasyprint" in pdf and "--css=/s.css" in pdf


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None,
                    reason="pandoc and graphviz needed")
def test_export_markdown_html_and_docx(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE)
    diagrams = {"context": Diagram(title="c", nodes=[Node(id="a", label="ctx node")])}
    failures = export_markdown(md, "html", tmp_path / "out.html", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work")
    html = (tmp_path / "out.html").read_text()
    assert failures == [] and "<table" in html and "ctx node" in html
    assert "data:image/svg+xml" in html or "<svg" in html  # inlined, self-contained
    assert "<title>Sample: Findings</title>" in html
    failures = export_markdown(md, "docx", tmp_path / "out.docx", diagrams=diagrams,
                               branding=BrandingConfig(), template=None,
                               work_dir=tmp_path / "work2")
    assert failures == [] and (tmp_path / "out.docx").stat().st_size > 5000


@pytest.mark.skipif(shutil.which("pandoc") is None or shutil.which("dot") is None
                    or shutil.which("weasyprint") is None, reason="pdf toolchain needed")
def test_export_markdown_pdf(tmp_path: Path):
    md = tmp_path / "findings.md"
    md.write_text(SAMPLE)
    export_markdown(md, "pdf", tmp_path / "out.pdf", diagrams={}, branding=BrandingConfig(),
                    template=None, work_dir=tmp_path / "work")
    assert (tmp_path / "out.pdf").read_bytes()[:5] == b"%PDF-"


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="pandoc needed")
def test_export_markdown_reports_pandoc_failure(tmp_path: Path):
    md = tmp_path / "doc.md"
    md.write_text("# x\n")
    with pytest.raises(RuntimeError, match="pandoc"):
        export_markdown(md, "docx", tmp_path / "out.docx", diagrams={},
                        branding=BrandingConfig(reference_docx="/nonexistent/ref.docx"),
                        template=None, work_dir=tmp_path / "w")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_export_pandoc.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.export.pandoc'`.

- [ ] **Step 3: Write tool detection, the pipeline, and the assets**

`src/unvarnish/export/tools.py`:

```python
from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence

INSTALL_HINTS: dict[str, str] = {
    "pandoc": "brew install pandoc  |  apt install pandoc  |  https://pandoc.org/installing",
    "dot": "brew install graphviz  |  apt install graphviz  |  https://graphviz.org/download",
    "weasyprint": "brew install weasyprint  |  apt install weasyprint  |  pip install weasyprint",
}
REQUIRED_BY_FORMAT: dict[str, tuple[str, ...]] = {
    "docx": ("pandoc", "dot"),
    "html": ("pandoc", "dot"),
    "pdf": ("pandoc", "dot", "weasyprint"),
}


def missing_tools(formats: Sequence[str],
                  which: Callable[[str], str | None] = shutil.which) -> list[str]:
    needed: list[str] = []
    for fmt in formats:
        for tool in REQUIRED_BY_FORMAT[fmt]:
            if tool not in needed:
                needed.append(tool)
    return [t for t in needed if which(t) is None]


class ToolsMissing(Exception):
    def __init__(self, tools: Sequence[str]) -> None:
        self.tools = list(tools)
        lines = [f"export needs {', '.join(self.tools)} on PATH:"]
        lines += [f"  {t}: {INSTALL_HINTS[t]}" for t in self.tools]
        lines.append("  or run Unvarnish from the Docker image, which bundles them.")
        super().__init__("\n".join(lines))
```

`src/unvarnish/export/pandoc.py`:

```python
from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from unvarnish.config import BrandingConfig
from unvarnish.export.graphviz import render_with_dot
from unvarnish.export.markdown import prepare_markdown
from unvarnish.render.diagram import Diagram

TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
IMAGE_FORMAT = {"docx": "png", "html": "svg", "pdf": "svg"}


def bundled_asset(name: str) -> Path:
    return Path(str(resources.files("unvarnish.export").joinpath("assets", name)))


def document_title(md: str, fallback: str) -> str:
    m = TITLE_RE.search(md)
    return m.group(1) if m else fallback


def build_pandoc_command(src: Path, fmt: str, out: Path, *, title: str, resource_dir: Path,
                         reference_docx: Path | None, css: Path | None,
                         pandoc: str = "pandoc") -> list[str]:
    cmd = [pandoc, str(src), "-f", "gfm", f"--resource-path={resource_dir}",
           f"--metadata=pagetitle:{title}", "-o", str(out)]
    if fmt == "docx":
        cmd += ["-t", "docx"]
        if reference_docx is not None:
            cmd.append(f"--reference-doc={reference_docx}")
    elif fmt == "html":
        cmd += ["-t", "html5", "--standalone", "--embed-resources"]
        if css is not None:
            cmd.append(f"--css={css}")
    elif fmt == "pdf":
        cmd += ["-t", "html5", "--standalone", "--pdf-engine=weasyprint"]
        if css is not None:
            cmd.append(f"--css={css}")
    else:
        raise ValueError(f"unknown export format {fmt!r}")
    return cmd


def run_pandoc(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, timeout=600)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"pandoc exited {proc.returncode}: {err[:400]}")


def _branding(fmt: str, branding: BrandingConfig,
              template: Path | None) -> tuple[Path | None, Path | None]:
    """(reference_docx, css) for this format: --template, then config, then bundled."""
    if fmt == "docx":
        ref = template or (Path(branding.reference_docx) if branding.reference_docx else None)
        return ref or bundled_asset("reference.docx"), None
    css = template or (Path(branding.html_css) if branding.html_css else None)
    return None, css or bundled_asset("report.css")


def export_markdown(md_path: Path, fmt: str, out: Path, *, diagrams: dict[str, Diagram],
                    branding: BrandingConfig, template: Path | None, work_dir: Path,
                    render: Callable[[str, str], bytes] = render_with_dot,
                    pandoc: str = "pandoc") -> list[str]:
    """Convert one rendered Markdown document; returns diagram failures (non-fatal)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    md = md_path.read_text(encoding="utf-8")
    prepared, failures = prepare_markdown(md, diagrams, work_dir / "images",
                                          image_format=IMAGE_FORMAT[fmt], render=render)
    src = work_dir / md_path.name
    src.write_text(prepared, encoding="utf-8")
    reference_docx, css = _branding(fmt, branding, template)
    out.parent.mkdir(parents=True, exist_ok=True)
    run_pandoc(build_pandoc_command(src, fmt, out, title=document_title(md, md_path.stem),
                                    resource_dir=work_dir, reference_docx=reference_docx,
                                    css=css, pandoc=pandoc))
    return failures
```

`src/unvarnish/export/assets/report.css`:

```css
/* Unvarnish bundled stylesheet: neutral, print-friendly. Override with report.branding.html_css. */
:root { --ink: #1a1a1a; --muted: #555; --rule: #d0d0d0; --accent: #8a1c1c; }
body { font-family: Georgia, "Times New Roman", serif; color: var(--ink); max-width: 52em;
       margin: 2em auto; padding: 0 1.5em; line-height: 1.45; }
h1, h2, h3, h4 { font-family: Helvetica, Arial, sans-serif; line-height: 1.2; }
h1 { font-size: 1.9em; border-bottom: 2px solid var(--accent); padding-bottom: .2em; }
h2 { font-size: 1.4em; margin-top: 2em; border-bottom: 1px solid var(--rule); }
h3 { font-size: 1.15em; margin-top: 1.5em; }
h4 { font-size: 1em; margin-top: 1.2em; }
table { border-collapse: collapse; width: 100%; font-size: .92em; margin: 1em 0; }
th, td { border: 1px solid var(--rule); padding: .35em .6em; vertical-align: top; text-align: left; }
th { background: #f3f3f3; font-family: Helvetica, Arial, sans-serif; }
code { font-family: Menlo, Consolas, monospace; font-size: .9em; background: #f6f6f6;
       padding: 0 .2em; }
pre { background: #f6f6f6; padding: .8em; overflow-x: auto; }
blockquote { color: var(--muted); border-left: 3px solid var(--rule); margin: 1em 0;
             padding: .2em 1em; }
img { max-width: 100%; }
@page { size: A4; margin: 2cm; }
@media print { body { margin: 0; max-width: none; } h2 { page-break-after: avoid; } }
```

Generate the reference document once (pandoc must be installed for this step; if it is not, ledger a ruling and omit the file, letting `_branding` fall back to no `--reference-doc` by returning `None` when the asset is missing):

```bash
cd src/unvarnish/export/assets && pandoc -o reference.docx --print-default-data-file reference.docx
```

In `pyproject.toml`, under `[tool.hatch.build.targets.wheel]`, hatchling includes package data by default (`src/unvarnish` with all files); confirm with `uv build` in Task 4. Ensure `*.docx` and `*.css` are not excluded by `.gitignore` (they are not).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_export_pandoc.py -q 2>&1 | tail -3`
Expected: all PASS (conversion tests skipped if the toolchain is absent; the PDF test needs weasyprint).

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/unvarnish/export tests/test_export_pandoc.py
git add src/unvarnish/export tests/test_export_pandoc.py
git commit -m "feat: pandoc export pipeline with tool detection, bundled branding, and diagrams"
```

---

### Task 3: The exporter and the `export` command

**Files:**
- Create: `src/unvarnish/export/exporter.py`
- Modify: `src/unvarnish/cli.py`
- Test: `tests/test_export_cli.py`

**Interfaces:**
- Consumes: `export_markdown`, `missing_tools`, `ToolsMissing`, `DiagramSet`, `Engagement`, `ToolPaths`, `read_artifact`, `BrandingConfig`.
- Produces:
  - `unvarnish.export.exporter`: `DOC_NAMES = ("architecture", "findings", "requirements", "comparison")`, `FORMATS = ("docx", "html", "pdf")`, `ExportItem(doc, tool, fmt, path: str | None, status: Literal["ok","skipped","failed"], detail: str)`, `ExportReport(items: list[ExportItem])` with `ok`, `failed`, `skipped` properties, `template_kind(path: Path) -> str` (`"docx"` or `"css"`), `check_template(template: Path | None, formats: Sequence[str]) -> None` (raises `ValueError` on a kind mismatch), `export_engagement(eng, *, formats: Sequence[str], docs: Sequence[str] | None, tools: Sequence[str] | None, template: Path | None, timestamp: str | None = None, render=render_with_dot, pandoc="pandoc") -> ExportReport`. Output names: `exports/<doc>-<tool>-<timestamp>.<ext>`; the comparison uses tool name `engagement`.
  - `unvarnish export [--format docx|pdf|html|all] [--template PATH] [--doc DOC ...] [TOOL ...] [-e DIR]`: exit 2 for missing tools, unknown doc or tool, or a template kind mismatch; exit 1 when nothing exported or any conversion failed; exit 0 otherwise.

- [ ] **Step 1: Write the failing tests**

`tests/test_export_cli.py`:

```python
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_compare_phase import _compare_stub, _two_tools
from unvarnish.cli import app
from unvarnish.export import exporter as exporter_module
from unvarnish.export.exporter import check_template, export_engagement, template_kind
from unvarnish.phases.compare import run_comparison

runner = CliRunner()
HAVE_TOOLS = shutil.which("pandoc") is not None and shutil.which("dot") is not None


def _rendered(engagement, synthetic_repo):
    stub = _compare_stub()
    _two_tools(engagement, synthetic_repo, stub)
    run_comparison(engagement, backend=stub)
    return engagement


def test_template_kind_and_mismatch():
    assert template_kind(Path("brand.docx")) == "docx" and template_kind(Path("x.CSS")) == "css"
    with pytest.raises(ValueError, match="docx"):
        check_template(Path("brand.css"), ["docx"])
    with pytest.raises(ValueError, match="css"):
        check_template(Path("brand.docx"), ["html"])
    check_template(Path("brand.docx"), ["docx"])
    check_template(None, ["docx", "html", "pdf"])


def test_export_missing_tools_exits_2_with_hints(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: None)
    out = runner.invoke(app, ["export", "--format", "html", "-e", str(engagement.root)])
    assert out.exit_code == 2, out.output
    assert "pandoc" in out.output and "dot" in out.output and "brew install" in out.output
    assert list(engagement.exports_dir.iterdir()) == []


def test_export_unknown_doc_or_tool_exits_2(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--doc", "poetry", "-e", str(engagement.root)])
    assert out.exit_code == 2 and "unknown document" in out.output
    out = runner.invoke(app, ["export", "nope", "-e", str(engagement.root)])
    assert out.exit_code == 2 and "unknown tool" in out.output


def test_export_template_kind_mismatch_exits_2(engagement, synthetic_repo, tmp_path):
    _rendered(engagement, synthetic_repo)
    css = tmp_path / "brand.css"
    css.write_text("body{}")
    out = runner.invoke(app, ["export", "--format", "docx", "--template", str(css),
                              "-e", str(engagement.root)])
    assert out.exit_code == 2 and "docx" in out.output


def _fake_render(src: str, fmt: str) -> bytes:
    return b"<svg/>" if fmt == "svg" else b"\x89PNG\r\n\x1a\n"


def _fake_pandoc_ok(cmd):
    Path(cmd[cmd.index("-o") + 1]).write_bytes(b"converted")


def test_export_skips_missing_documents(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)
    engagement.tool_paths("beta").architecture_doc.unlink()
    monkeypatch.setattr(exporter_module, "run_pandoc", _fake_pandoc_ok)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["html"], docs=None, tools=None,
                               template=None, timestamp="20261017-120000", render=_fake_render)
    skipped = [i for i in report.items if i.status == "skipped"]
    assert [(i.doc, i.tool) for i in skipped] == [("architecture", "beta")]
    assert "not rendered" in skipped[0].detail
    ok = [i for i in report.items if i.status == "ok"]
    assert {i.path for i in ok} >= {"exports/findings-alpha-20261017-120000.html",
                                    "exports/comparison-engagement-20261017-120000.html"}
    assert all(Path(engagement.root, i.path).exists() for i in ok)


def test_export_records_conversion_failures(engagement, synthetic_repo, monkeypatch):
    _rendered(engagement, synthetic_repo)

    def flaky(cmd):
        if "findings" in cmd[1]:
            raise RuntimeError("pandoc exited 1: boom")
        _fake_pandoc_ok(cmd)

    monkeypatch.setattr(exporter_module, "run_pandoc", flaky)
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    report = export_engagement(engagement, formats=["docx"], docs=["findings", "requirements"],
                               tools=["alpha"], template=None, render=_fake_render)
    assert [(i.doc, i.status) for i in report.items] == [("findings", "failed"),
                                                         ("requirements", "ok")]
    assert "boom" in report.failed[0].detail


@pytest.mark.skipif(not HAVE_TOOLS, reason="pandoc and graphviz needed")
def test_export_cli_end_to_end(engagement, synthetic_repo):
    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "--format", "html", "--doc", "findings",
                              "--doc", "comparison", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    produced = sorted(p.name for p in engagement.exports_dir.glob("*.html"))
    assert len(produced) == 3  # findings for alpha and beta, plus the comparison
    html = next(engagement.exports_dir.glob("comparison-engagement-*.html")).read_text()
    assert "<table" in html and ("<svg" in html or "data:image/svg+xml" in html)
    out = runner.invoke(app, ["export", "--format", "docx", "alpha", "-e", str(engagement.root)])
    assert out.exit_code == 0, out.output
    assert len(list(engagement.exports_dir.glob("*-alpha-*.docx"))) == 3


def test_export_cli_nothing_to_export_exits_1(engagement, synthetic_repo, monkeypatch):
    from unvarnish.phases.ingest import ingest_tool

    ingest_tool(engagement, "alpha", str(synthetic_repo), "repo")  # never run
    monkeypatch.setattr(exporter_module.shutil, "which", lambda t: "/x")
    out = runner.invoke(app, ["export", "-e", str(engagement.root)])
    assert out.exit_code == 1 and "nothing to export" in out.output.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_export_cli.py -q 2>&1 | tail -3`
Expected: FAIL with `ModuleNotFoundError: No module named 'unvarnish.export.exporter'`.

- [ ] **Step 3: Write the exporter**

`src/unvarnish/export/exporter.py`:

```python
from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.export.graphviz import render_with_dot
from unvarnish.export.pandoc import export_markdown, run_pandoc  # noqa: F401 - patched in tests
from unvarnish.export.tools import ToolsMissing, missing_tools
from unvarnish.render.diagram import Diagram
from unvarnish.schemas.diagrams import DiagramSet

log = logging.getLogger("unvarnish.export")
DOC_NAMES = ("architecture", "findings", "requirements", "comparison")
FORMATS = ("docx", "html", "pdf")
ENGAGEMENT = "engagement"


class ExportItem(BaseModel):
    doc: str
    tool: str
    fmt: str
    path: str | None = None  # relative to the engagement root
    status: Literal["ok", "skipped", "failed"]
    detail: str = ""


class ExportReport(BaseModel):
    items: list[ExportItem] = Field(default_factory=list)

    @property
    def ok(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "ok"]

    @property
    def failed(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "failed"]

    @property
    def skipped(self) -> list[ExportItem]:
        return [i for i in self.items if i.status == "skipped"]


def template_kind(path: Path) -> str:
    return "docx" if path.suffix.lower() == ".docx" else "css"


def check_template(template: Path | None, formats: Sequence[str]) -> None:
    if template is None:
        return
    kind = template_kind(template)
    wants_docx = "docx" in formats
    wants_css = any(f in formats for f in ("html", "pdf"))
    if wants_docx and not wants_css and kind != "docx":
        raise ValueError(f"--template for docx must be a .docx reference document, not {template.name}")
    if wants_css and not wants_docx and kind != "css":
        raise ValueError(f"--template for html/pdf must be a .css stylesheet, not {template.name}")
    if wants_docx and wants_css:
        raise ValueError("--template applies to one kind of output; pass --format docx or "
                         "--format html/pdf with it")


def _sources(eng: Engagement, docs: Sequence[str], tools: Sequence[str]
             ) -> list[tuple[str, str, Path, Path]]:
    """(doc, tool, markdown path, diagrams path) for every requested document."""
    out: list[tuple[str, str, Path, Path]] = []
    for tool in tools:
        p = eng.tool_paths(tool)
        for doc in docs:
            if doc == "comparison":
                continue
            md = {"architecture": p.architecture_doc, "findings": p.findings_doc,
                  "requirements": p.requirements_doc}[doc]
            out.append((doc, tool, md, p.diagrams))
    if "comparison" in docs:
        out.append(("comparison", ENGAGEMENT, eng.comparison_doc, eng.comparison_diagrams))
    return out


def _diagrams(path: Path) -> dict[str, Diagram]:
    if not path.exists():
        return {}
    try:
        return read_artifact(path, DiagramSet).data.diagrams
    except Exception as exc:
        log.warning("ignoring unreadable %s: %r", path, exc)
        return {}


def export_engagement(eng: Engagement, *, formats: Sequence[str], docs: Sequence[str] | None,
                      tools: Sequence[str] | None, template: Path | None,
                      timestamp: str | None = None,
                      render: Callable[[str, str], bytes] = render_with_dot,
                      pandoc: str = "pandoc") -> ExportReport:
    """Export every requested document in every requested format. Raises ToolsMissing and
    ValueError before touching exports/; per-document conversion failures are recorded."""
    formats = list(formats)
    missing = missing_tools(formats, which=shutil.which)
    if missing:
        raise ToolsMissing(missing)
    check_template(template, formats)
    docs = list(docs or DOC_NAMES)
    tools = list(tools or eng.tool_names())
    stamp = timestamp or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    report = ExportReport()
    eng.exports_dir.mkdir(parents=True, exist_ok=True)
    for doc, tool, md, diagrams_path in _sources(eng, docs, tools):
        for fmt in formats:
            item = ExportItem(doc=doc, tool=tool, fmt=fmt, status="skipped")
            if not md.exists():
                item.detail = f"not rendered: {md.relative_to(eng.root)} does not exist"
                report.items.append(item)
                continue
            out = eng.exports_dir / f"{doc}-{tool}-{stamp}.{fmt}"
            with tempfile.TemporaryDirectory(prefix="unvarnish-export-") as tmp:
                try:
                    failures = export_markdown(
                        md, fmt, out, diagrams=_diagrams(diagrams_path),
                        branding=eng.config.report.branding, template=template,
                        work_dir=Path(tmp), render=render, pandoc=pandoc)
                except Exception as exc:  # one failed conversion never kills the export
                    log.exception("export %s/%s/%s failed", doc, tool, fmt)
                    item.status, item.detail = "failed", str(exc)[:300]
                    out.unlink(missing_ok=True)
                    report.items.append(item)
                    continue
            item.status = "ok"
            item.path = out.relative_to(eng.root).as_posix()
            item.detail = ("; ".join(failures) if failures else "")
            report.items.append(item)
    return report
```

`export_markdown` must call `run_pandoc` through the `exporter` module's name for the tests' monkeypatch to take effect: in `pandoc.py`, `export_markdown` takes an optional `runner: Callable[[list[str]], None] = run_pandoc`; `exporter.py` passes `runner=run_pandoc` where `run_pandoc` is looked up from its own module namespace at call time (`runner=globals()["run_pandoc"]` is unnecessary; simply reference the imported name inside the function body, which resolves at call time and so sees the monkeypatch). Add the `runner` parameter to `export_markdown` and use it instead of calling `run_pandoc` directly.

- [ ] **Step 4: Add the command**

In `src/unvarnish/cli.py`, import `from unvarnish.export.exporter import DOC_NAMES, FORMATS, export_engagement` and `from unvarnish.export.tools import ToolsMissing`, then add after `ask`:

```python
@app.command()
def export(
    tools: list[str] | None = typer.Argument(None, help="Tools to export (default: all)."),
    fmt: str = typer.Option("all", "--format", help="docx, html, pdf, or all."),
    template: Path | None = typer.Option(None, "--template",
                                         help="A .docx reference (docx) or .css (html/pdf)."),
    doc: list[str] | None = typer.Option(None, "--doc", help="architecture, findings, "
                                         "requirements, comparison (default: all)."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Convert the rendered Markdown documents to DOCX, HTML, or PDF under exports/."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, tools)
    formats = list(FORMATS) if fmt == "all" else [fmt]
    if any(f not in FORMATS for f in formats):
        err_console.print(f"[red]error:[/red] unknown format {fmt!r}; use docx, html, pdf, or all")
        raise typer.Exit(code=2)
    unknown = [d for d in (doc or []) if d not in DOC_NAMES]
    if unknown:
        err_console.print(f"[red]error:[/red] unknown document(s): {', '.join(unknown)}; "
                          f"known: {', '.join(DOC_NAMES)}")
        raise typer.Exit(code=2)
    try:
        report = export_engagement(eng, formats=formats, docs=doc or None, tools=names,
                                   template=template)
    except (ToolsMissing, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {exc}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    table = Table("document", "tool", "format", "status", "detail", title="export")
    for i in report.items:
        colour = {"ok": "green", "skipped": "dim", "failed": "red"}[i.status]
        table.add_row(i.doc, i.tool, i.fmt, f"[{colour}]{i.status}[/{colour}]",
                      i.path or i.detail if i.status == "ok" else i.detail)
    console.print(table)
    if not report.ok:
        err_console.print("Nothing to export: run `unvarnish run` (and `compare`) first.")
        raise typer.Exit(code=1)
    console.print(f"{len(report.ok)} file(s) written under exports/")
    if report.failed:
        err_console.print(f"{len(report.failed)} conversion(s) failed; see the table above.")
        raise typer.Exit(code=1)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_export_cli.py tests/test_export_pandoc.py -q 2>&1 | tail -3`
Expected: all PASS (the end-to-end CLI test is skipped without the toolchain).

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src/unvarnish/export src/unvarnish/cli.py tests/test_export_cli.py
git add src/unvarnish/export/exporter.py src/unvarnish/export/pandoc.py src/unvarnish/cli.py tests/test_export_cli.py
git commit -m "feat: export command producing DOCX, HTML, and PDF under exports/"
```

---

### Task 4: Distribution: Docker image, packaging, schema guard, CI, docs

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `tests/test_distribution.py`
- Modify: `pyproject.toml`, `.github/workflows/ci.yml`, `src/unvarnish/config.py`, `src/unvarnish/cli.py` (schema error → exit 2), `README.md`, `scripts/smoke.sh`

**Interfaces:**
- Produces: `SUPPORTED_SCHEMA_VERSION = 1` and `class UnsupportedSchemaVersion(ValueError)` in `config.py`; `load_config` raises it when `schema_version > SUPPORTED_SCHEMA_VERSION`; `_load_engagement` in the CLI prints the message and exits 2. A Docker image that runs `unvarnish` with pandoc, Graphviz, weasyprint, and git available; `uv build` producing a wheel that contains `export/assets/*`.

- [ ] **Step 1: Write the failing tests**

`tests/test_distribution.py`:

```python
import re
import subprocess
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.config import SUPPORTED_SCHEMA_VERSION, UnsupportedSchemaVersion, load_config
from unvarnish.engagement import Engagement

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


def test_newer_schema_version_is_refused(tmp_path: Path):
    eng = Engagement.create(tmp_path / "e")
    text = eng.config_file.read_text().replace("schema_version: 1",
                                               f"schema_version: {SUPPORTED_SCHEMA_VERSION + 1}")
    eng.config_file.write_text(text)
    with pytest.raises(UnsupportedSchemaVersion, match="newer"):
        load_config(eng.config_file)
    out = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert out.exit_code == 2 and "newer Unvarnish" in out.output


def test_dockerfile_bundles_the_export_toolchain():
    text = (ROOT / "Dockerfile").read_text()
    for pkg in ("pandoc", "graphviz", "weasyprint", "git"):
        assert pkg in text, pkg
    assert "python:3.12" in text and 'ENTRYPOINT ["unvarnish"]' in text
    assert "/engagement" in text
    ignore = (ROOT / ".dockerignore").read_text()
    assert ".venv" in ignore and ".git" in ignore


def test_pyproject_metadata():
    text = (ROOT / "pyproject.toml").read_text()
    assert "[project.urls]" in text and "Bonham-Technologies/Unvarnish" in text
    assert "Programming Language :: Python :: 3.12" in text
    assert re.search(r'^unv = "unvarnish.cli:app"$', text, re.M)


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs the repository")
def test_wheel_contains_export_assets(tmp_path: Path):
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(tmp_path)], cwd=ROOT, check=True,
                   capture_output=True, timeout=300)
    wheel = next(tmp_path.glob("unvarnish-*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert any(n.endswith("export/assets/report.css") for n in names)
    assert any(n.endswith("export/assets/reference.docx") for n in names)
    assert any(n.endswith("render/templates/findings.md.j2") for n in names)
    assert any(n.endswith("model/prompts/extract_system.md") for n in names)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_distribution.py -q 2>&1 | tail -3`
Expected: FAIL (`ImportError: cannot import name 'SUPPORTED_SCHEMA_VERSION'`).

- [ ] **Step 3: Implement**

In `src/unvarnish/config.py`:

```python
SUPPORTED_SCHEMA_VERSION = 1


class UnsupportedSchemaVersion(ValueError):
    pass
```

and in `load_config`, after merging and before validation:

```python
    version = merged.get("schema_version", 1)
    if isinstance(version, int) and version > SUPPORTED_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"{engagement_file} has schema_version {version}, written by a newer Unvarnish; "
            f"this version supports {SUPPORTED_SCHEMA_VERSION}. Upgrade Unvarnish to work on "
            "this engagement.")
```

In `src/unvarnish/cli.py` `_load_engagement`, catch `UnsupportedSchemaVersion` alongside `NotAnEngagement` (both print the message and exit 2); the message must contain "newer Unvarnish".

`Dockerfile`:

```dockerfile
# Unvarnish: portable image with the export toolchain. Engagement mounted at /engagement.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git pandoc graphviz weasyprint fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && rm -rf /root/.cache
ENV PATH="/app/.venv/bin:${PATH}" UNVARNISH_CONFIG_DIR=/engagement/.unvarnish

WORKDIR /engagement
VOLUME ["/engagement"]
ENTRYPOINT ["unvarnish"]
CMD ["--help"]
```

`.dockerignore`:

```
.git
.venv
.superpowers
.pytest_cache
.ruff_cache
__pycache__
dist
build
*.egg-info
tests
docs
```

In `pyproject.toml`, add under `[project]`:

```toml
classifiers = [
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Environment :: Console",
  "Intended Audience :: Information Technology",
  "Topic :: Software Development :: Quality Assurance",
]

[project.urls]
Homepage = "https://unvarnish.com"
Repository = "https://github.com/Bonham-Technologies/Unvarnish"
```

(keep the existing `[project.scripts]` with `unvarnish` and `unv`).

In `.github/workflows/ci.yml`, add before the pytest step:

```yaml
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends pandoc graphviz weasyprint
```

and after it:

```yaml
      - run: uv build
```

In `README.md`, add after the "Asking questions" section:

```markdown
## Exporting

    unvarnish export                         # every rendered document, docx + html + pdf
    unvarnish export --format docx expense-bot
    unvarnish export --format html --doc findings --doc comparison
    unvarnish export --format docx --template brand.docx

Needs `pandoc` and Graphviz `dot` on PATH, plus `weasyprint` for PDF; if any is missing the
command says how to install each and exits 2. Files land in `exports/<doc>-<tool>-<timestamp>.<ext>`
(`comparison-engagement-...` for the comparison). Diagrams are rendered to SVG (PNG for DOCX)
with Graphviz from the same model that produced the Mermaid in the Markdown. Branding: set
`report.branding.reference_docx` (a Word reference document) and `report.branding.html_css` in
`engagement.yaml`, or pass `--template`; the bundled neutral reference and stylesheet are the
fallback. Export always starts from the latest render; hand edits to the Markdown survive
until the next `run`.

## Docker

    docker build -t unvarnish .
    docker run --rm -v "$PWD/acme-2026-10:/engagement" unvarnish run
    docker run --rm -v "$PWD/acme-2026-10:/engagement" -e ANTHROPIC_API_KEY unvarnish run

The image bundles Python, the tree-sitter grammars, git, pandoc, Graphviz, and weasyprint.
`docker save unvarnish | gzip > unvarnish.tar.gz` moves it to an air-gapped site. Keys are
passed as environment variables; nothing is baked into the image or the engagement.

## Install

    uv tool install unvarnish        # once published; from a checkout: uv tool install .
```

(merge with the existing Install section rather than duplicating it).

In `scripts/smoke.sh`, after the `ask` line:

```bash
uv run unvarnish export --format html -e "$E" || echo "export exited $?"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_distribution.py -q 2>&1 | tail -3`
Expected: all PASS (the wheel test runs `uv build`, which needs network only for the build backend if not cached).

- [ ] **Step 5: Build the image and run the toolchain-gated tests inside it**

The laptop has no pandoc or Graphviz (Homebrew could not write `/usr/local/share/man/man8`), so the real conversions are verified in the image:

```bash
docker build -t unvarnish:dev .
docker run --rm --entrypoint sh unvarnish:dev -c "pandoc --version | head -1; dot -V; weasyprint --version; unvarnish --version"
docker run --rm --entrypoint sh -v "$PWD/tests:/app/tests:ro" -w /app unvarnish:dev -c \
  "uv sync --frozen --all-groups >/dev/null && uv run pytest tests/test_export_graphviz.py tests/test_export_pandoc.py tests/test_export_cli.py -q"
```

Expected: the image builds; the three tools print versions; the export tests all PASS including the previously skipped ones. Record the result in the ledger. If the PDF test fails on fonts, add `fonts-liberation` to the apt line.

- [ ] **Step 6: Lint, run the whole suite, commit**

```bash
uv run ruff check .
uv run pytest -q
git add Dockerfile .dockerignore pyproject.toml .github/workflows/ci.yml src/unvarnish/config.py src/unvarnish/cli.py README.md scripts/smoke.sh tests/test_distribution.py
git commit -m "feat: Docker image, PyPI metadata, schema-version guard, CI export toolchain"
```

---

## Self-review notes

**Spec coverage.** 3 `export [--format] [--template] [--doc]` (Task 3; tool names added as positional arguments, consistent with `run`). 4 `exports/<doc>-<tool>-<timestamp>.<ext>` (Task 3). 8.7 second emitter over the same `Diagram` model (Task 1). 11 DOCX reference with bundled fallback, self-contained HTML with embedded CSS and inlined SVG, PDF via weasyprint, Graphviz before conversion, install hints and exit 2 (Tasks 2, 3). 12 PyPI metadata and console scripts, Docker image with pandoc/Graphviz/weasyprint/git (gitleaks, osv-scanner, OSV database with their scanners in slice 7), schema-version refusal (Task 4). 14 end-to-end export to HTML exercised by the CLI test when the toolchain is present (Task 3) and in CI and the image (Task 4).

**Known deviations, to ledger at execution.** `--migrate` is not implemented; a newer schema is refused with an upgrade message (no older-schema migrations exist yet). `--template` applies to one output kind per invocation. DOCX diagrams are PNG, not SVG, for Word compatibility. The Python `graphviz` binding from spec 12.1 is replaced by a direct `dot` subprocess (one fewer dependency, same binary). The local toolchain could not be installed; real conversions are verified in the Docker image and in CI.

**Type consistency checked.** `prepare_markdown(md, diagrams, image_dir, *, image_format, render)` consumed by `export_markdown`; `export_markdown(..., render=, pandoc=, runner=)` consumed by `export_engagement`; `ExportItem.status` literals used by the CLI colour map; `DiagramSet.diagrams` keyed by the marker names `context`, `modules`, `integration` in both templates and `_sources`.
