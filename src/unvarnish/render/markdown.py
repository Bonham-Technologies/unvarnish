from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from jinja2 import (
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
    StrictUndefined,
    TemplateRuntimeError,
    nodes,
)
from jinja2.ext import Extension

from unvarnish.artifacts import hash_inputs
from unvarnish.util.plural import is_are, plural, pluralize

PROSE_TAG_RE = re.compile(r"{%-?\s*prose\s+[\"']([a-z_][a-z0-9_]*)[\"']\s*-?%}")


class ProseExtension(Extension):
    """`{% prose "name" %}` renders `prose["name"]`, a model-written block, or fails loudly."""

    tags = {"prose"}

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        name = parser.parse_expression()
        call = self.call_method("_lookup", [name, nodes.Name("prose", "load")], lineno=lineno)
        return nodes.Output([call], lineno=lineno)

    @staticmethod
    def _lookup(name: str, prose) -> str:
        if not isinstance(prose, dict) or name not in prose:
            raise TemplateRuntimeError(f"unknown prose block {name!r}")
        return cap_headings(prose[name])


def prose_block_names(env: Environment, template_name: str) -> list[str]:
    """Prose block names a template references, in first-seen order."""
    assert env.loader is not None
    source, _, _ = env.loader.get_source(env, template_name)
    return list(dict.fromkeys(PROSE_TAG_RE.findall(source)))


def fmt_int(v: int | None) -> str:
    return "—" if v is None else f"{v:,}"


def pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


FIRST_SENTENCE_RE = re.compile(r"^(.+?[.!?])(?=\s+[A-Z(\"'])", re.S)


LIST_CAP = 60  # rows of a model-written list shown in a document


def more(seq, n: int = LIST_CAP) -> str:
    """"(+N more in the analysis files)" when a capped list was cut, else ""."""
    extra = len(list(seq)) - n
    return f"(+{extra} more in the analysis files)" if extra > 0 else ""


def first_sentence(text: str | None) -> str:
    """The first sentence, for table cells; text without a sentence break is returned whole."""
    text = " ".join((text or "").split())
    m = FIRST_SENTENCE_RE.match(text)
    return m.group(1) if m else text


def cell(v: object) -> str:
    """Model text made safe for a Markdown table cell: one line, pipes escaped."""
    if v is None:
        return ""
    text = " ".join(str(v).split())
    return text.replace("|", "\\|")


# A line that would open a block: an ATX heading, a blockquote, a bullet, a fence, a table row,
# a link reference or footnote definition. Ordered-list markers are handled apart (the
# backslash goes before their "." or ")").
BLOCK_START_RE = re.compile(r"(?:#{1,6}(?=\s|$)|>|[-*+](?=\s|$)|`{3,}|~{3,}|\||\[[^\]]*\]:)")
ORDERED_RE = re.compile(r"(\d{1,9})([.)])(?=\s|$)")
# A thematic break, a setext underline, or a table delimiter row.
RULE_LINE_RE = re.compile(r"(?:[-*_](?:\s*[-*_]){2,}|=+|-+|[\s|:-]*-[\s|:-]*\|[\s|:-]*"
                          r"|[\s|:-]*\|[\s|:-]*-[\s|:-]*)\s*$")
ATX_RE = re.compile(r"(#{1,6})(?=\s|$)")


def inert_block(v: object) -> str:
    """Model text made safe as a paragraph (UNVAR-76): no line can open a heading, table,
    fence, blockquote, thematic break, list or definition. Each line loses its indentation
    (no indented code block) and gets a backslash before a block marker, so the words still
    show and inline emphasis, code spans and links still work."""
    if v is None:
        return ""
    out: list[str] = []
    for raw in str(v).splitlines():
        line = raw.lstrip()
        if not line:
            out.append("")
            continue
        ordered = ORDERED_RE.match(line)
        if ordered:
            line = f"{ordered.group(1)}\\{line[len(ordered.group(1)):]}"
        elif BLOCK_START_RE.match(line) or RULE_LINE_RE.match(line):
            line = "\\" + line
        out.append(line)
    return "\n".join(out)


def cap_headings(text: str, top: int = 3) -> str:
    """Prose with every heading above level `top` made literal, so a model-written block
    cannot open a section of the document's own outline (UNVAR-76). Deeper headings, lists
    and the rest of the Markdown are left alone."""
    out: list[str] = []
    prev = ""
    for raw in text.splitlines():
        line = raw.lstrip()
        atx = ATX_RE.match(line)
        if atx and len(atx.group(1)) < top:
            raw = "\\" + line
        elif prev.strip() and re.fullmatch(r"\s*(?:=+|-+)\s*", raw):
            raw = "\\" + line  # a setext underline would make the line above a heading
        out.append(raw)
        prev = raw
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def code_span(v: object) -> str:
    """Model text as an inline code span; backticks inside would end the span early."""
    if v is None or v == "":
        return ""
    return "`" + " ".join(str(v).split()).replace("`", "'") + "`"


def make_env(override_dirs: Sequence[Path] = ()) -> Environment:
    loaders = [FileSystemLoader(str(d)) for d in override_dirs if d.is_dir()]
    loaders.append(PackageLoader("unvarnish.render", "templates"))
    env = Environment(
        loader=ChoiceLoader(loaders),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        extensions=[ProseExtension],
    )
    env.filters["fmt_int"] = fmt_int
    env.filters["pct"] = pct
    env.filters["cell"] = cell
    env.filters["inert_block"] = inert_block
    env.filters["first_sentence"] = first_sentence
    env.filters["cap"] = lambda seq, n=LIST_CAP: list(seq)[:n]
    env.globals["more"] = more
    env.globals["LIST_CAP"] = LIST_CAP
    env.filters["code_span"] = code_span
    env.filters["plural"] = plural
    env.filters["pluralize"] = pluralize
    env.filters["is_are"] = is_are
    return env


def render_document(env: Environment, template_name: str, context: dict) -> str:
    return env.get_template(template_name).render(**context)


def template_source_hash(env: Environment, template_name: str) -> str:
    assert env.loader is not None
    source, _, _ = env.loader.get_source(env, template_name)
    return hash_inputs([template_name, source])
