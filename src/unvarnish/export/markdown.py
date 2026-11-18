from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from unvarnish.export.graphviz import render_with_dot, to_dot
from unvarnish.render.diagram import Diagram

DIAGRAM_MARKER = "<!-- unvarnish-diagram: {name} -->"
DIAGRAM_BLOCK_RE = re.compile(
    r"<!--\s*unvarnish-diagram:\s*(?P<name>[a-z0-9_-]+)\s*-->[ \t]*\r?\n(?:[ \t]*\r?\n)*"
    r"```mermaid[^\n]*\n.*?\r?\n```", re.DOTALL)
LEFTOVER_RE = re.compile(r"^```mermaid", re.MULTILINE)
ORPHAN_MARKER_RE = re.compile(r"^[ \t]*<!--\s*unvarnish-diagram:[^\n]*?-->[ \t]*\r?\n?",
                              re.MULTILINE)
# Screen readers read an image's alt text aloud, so it is a sentence, never the internal name.
ALT_TEXT = {
    "context": "Context diagram: who uses the tool and the systems it connects to",
    "modules": "Module map: how the files depend on each other",
    "integration": "Integration map: the systems each tool connects to",
}


def diagram_alt_text(name: str, diagram: Diagram) -> str:
    """Human alt text for a diagram image: a known sentence, else one built from its title."""
    text = ALT_TEXT.get(name) or f"Diagram: {diagram.title}"
    return re.sub(r"[\[\]\\\r\n]+", " ", text).strip()


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
        return f"![{diagram_alt_text(name, d)}]({image_dir.name}/{path.name})"

    out = DIAGRAM_BLOCK_RE.sub(replace, md)
    out = ORPHAN_MARKER_RE.sub("", out)  # pandoc reads raw HTML as text, so drop stray markers
    leftover = len(LEFTOVER_RE.findall(out))
    if leftover:  # a hand edit or an old template override: say so instead of shipping source
        failures.append(f"{leftover} Mermaid block{'s' if leftover != 1 else ''} without an "
                        "unvarnish-diagram marker was left as text")
    return out, failures
