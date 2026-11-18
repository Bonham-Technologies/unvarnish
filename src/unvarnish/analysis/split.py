from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from unvarnish.analysis.metrics import SCRIPT_RE, STYLE_RE
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.analysis.treesitter import (
    FUNCTION_NODE_TYPES,
    _is_test_runner_callback,
    _node_name,
    get_parser,
)
from unvarnish.schemas.analysis import Unit, UnitKind

CLASS_NODE_TYPES: dict[str, set[str]] = {
    "python": {"class_definition"},
    "javascript": {"class_declaration", "class"},
    "typescript": {"class_declaration", "abstract_class_declaration", "interface_declaration"},
    "tsx": {"class_declaration", "abstract_class_declaration", "interface_declaration"},
    "go": {"type_declaration"},
    "rust": {"impl_item", "struct_item", "enum_item", "trait_item", "mod_item"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration"},
    "c_sharp": {"class_declaration", "interface_declaration", "struct_declaration",
                "namespace_declaration"},
    "kotlin": {"class_declaration", "object_declaration"},
    "ruby": {"class", "module"},
    "php": {"class_declaration", "interface_declaration", "trait_declaration"},
    "swift": {"class_declaration", "protocol_declaration"},
    "scala": {"class_definition", "object_definition", "trait_definition"},
}


@dataclass
class Span:
    kind: UnitKind
    name: str | None
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int


def unit_id(path: str, line_start: int, line_end: int, split_method: str,
            byte_start: int = 0, byte_end: int = 0) -> str:
    key = f"{path}|{line_start}|{line_end}|{split_method}|{byte_start}|{byte_end}".encode()
    return hashlib.sha1(key).hexdigest()[:12]  # noqa: S324 - identifier, not security


def _line_of(source: bytes, byte_offset: int) -> int:
    return source.count(b"\n", 0, byte_offset) + 1


# --- structural -----------------------------------------------------------

def _definition_kind(node: Any, language: str, source: bytes) -> UnitKind | None:
    if node.type in CLASS_NODE_TYPES.get(language, set()):
        return UnitKind.class_def
    if node.type in FUNCTION_NODE_TYPES.get(language, set()) and not _is_test_runner_callback(
        node, source
    ):
        parent = node.parent
        while parent is not None:
            if parent.type in CLASS_NODE_TYPES.get(language, set()):
                return UnitKind.method
            parent = parent.parent
        return UnitKind.function
    return None


def _leaf_spans(
    node: Any, language: str, source: bytes, unit_tokens: int
) -> list[tuple[Any, UnitKind | None]]:
    """Top-level children, descending into definitions that are too large on their own."""
    out: list[tuple[Any, UnitKind | None]] = []
    for child in node.children:
        kind = _definition_kind(child, language, source)
        size = estimate_tokens(source[child.start_byte:child.end_byte])
        if size > unit_tokens and child.children and kind is not None:
            body = child.child_by_field_name("body") or child
            inner = _leaf_spans(body, language, source, unit_tokens)
            if len(inner) > 1:
                out.extend(inner)
                continue
        out.append((child, kind))
    return out


def structural_spans(source: bytes, language: str, unit_tokens: int) -> list[Span] | None:
    parser = get_parser(language)
    if parser is None:
        return None
    tree = parser.parse(source)
    leaves = _leaf_spans(tree.root_node, language, source, unit_tokens)
    spans: list[Span] = []
    group: list[tuple[Any, UnitKind | None]] = []

    def flush() -> None:
        nonlocal group
        if not group:
            return
        first, last = group[0][0], group[-1][0]
        if len(group) == 1 and group[0][1] is not None:
            kind, name = group[0][1], _node_name(first, source)
        else:
            kind, name = UnitKind.group, None
        spans.append(Span(kind=kind, name=name, byte_start=first.start_byte,
                          byte_end=last.end_byte, line_start=first.start_point.row + 1,
                          line_end=last.end_point.row + 1))
        group = []

    for node, kind in leaves:
        size = estimate_tokens(source[node.start_byte:node.end_byte])
        if size > unit_tokens:
            flush()
            spans.extend(window_spans(source[node.start_byte:node.end_byte], unit_tokens,
                                      base_byte=node.start_byte,
                                      base_line=node.start_point.row + 1))
            continue
        # measure the real span (including whitespace between nodes), not the sum of node sizes
        if group and estimate_tokens(source[group[0][0].start_byte:node.end_byte]) > unit_tokens:
            flush()
        group.append((node, kind))
    flush()
    return spans


# --- windowing --------------------------------------------------------------

def window_spans(source: bytes, unit_tokens: int, overlap: float = 0.10,
                 base_byte: int = 0, base_line: int = 1) -> list[Span]:
    if not source:
        return []
    target = max(unit_tokens * 3, 64)
    step = max(int(target * (1 - overlap)), 32)
    spans: list[Span] = []
    start = 0
    n = len(source)
    while start < n:
        end = min(start + target, n)
        if end < n:
            nl = source.rfind(b"\n", start, end)
            if nl > start:
                end = nl + 1
        spans.append(Span(
            kind=UnitKind.window, name=None, byte_start=base_byte + start,
            byte_end=base_byte + end,
            line_start=base_line + source.count(b"\n", 0, start),
            line_end=base_line + source.count(b"\n", 0, max(end - 1, start)),
        ))
        if end >= n:
            break
        nxt = start + step
        nl = source.rfind(b"\n", start, nxt)
        start = nl + 1 if nl > start else nxt
    return spans


# --- html -------------------------------------------------------------------

def html_spans(source: bytes, unit_tokens: int) -> list[Span]:
    spans: list[Span] = []
    regions: list[tuple[int, int, UnitKind]] = []
    for m in SCRIPT_RE.finditer(source):
        regions.append((m.start(1), m.end(1), UnitKind.script_block))
    for m in STYLE_RE.finditer(source):
        regions.append((m.start(1), m.end(1), UnitKind.style_block))
    regions.sort()
    # A <style> inside a <script type="text/template"> (or the reverse) is part of the outer
    # block; splitting it again would analyse the same bytes twice.
    outer: list[tuple[int, int, UnitKind]] = []
    for r in regions:
        if outer and r[0] < outer[-1][1]:
            continue
        outer.append(r)
    regions = outer
    cursor = 0
    for start, end, kind in regions:
        if start > cursor and source[cursor:start].strip():
            spans.extend(_markup(source, cursor, start, unit_tokens))
        body = source[start:end]
        base_line = _line_of(source, start)
        if kind == UnitKind.script_block:
            inner = structural_spans(body, "javascript", unit_tokens) or []
            if inner:
                for s in inner:
                    spans.append(Span(kind=UnitKind.script_block, name=s.name,
                                      byte_start=start + s.byte_start,
                                      byte_end=start + s.byte_end,
                                      line_start=base_line + s.line_start - 1,
                                      line_end=base_line + s.line_end - 1))
                cursor = end
                continue
        for w in window_spans(body, unit_tokens, base_byte=start, base_line=base_line):
            spans.append(Span(kind=kind, name=None, byte_start=w.byte_start, byte_end=w.byte_end,
                              line_start=w.line_start, line_end=w.line_end))
        cursor = end
    if cursor < len(source) and source[cursor:].strip():
        spans.extend(_markup(source, cursor, len(source), unit_tokens))
    spans.sort(key=lambda s: s.byte_start)
    return spans


def _markup(source: bytes, start: int, end: int, unit_tokens: int) -> list[Span]:
    body = source[start:end]
    return [
        Span(kind=UnitKind.markup, name=None, byte_start=w.byte_start, byte_end=w.byte_end,
             line_start=w.line_start, line_end=w.line_end)
        for w in window_spans(body, unit_tokens, base_byte=start, base_line=_line_of(source, start))
    ]


# --- entry point ------------------------------------------------------------

def split_file(source: bytes, path: str, language: str | None, unit_tokens: int, *,
               tool: str, generated: bool = False) -> list[Unit]:
    method = "structural"
    if language == "html":
        spans: list[Span] | None = html_spans(source, unit_tokens)
    else:
        spans = structural_spans(source, language, unit_tokens) if language else None
    if spans is None:
        if estimate_tokens(source) <= unit_tokens:
            last_line = source.count(b"\n") + (0 if source.endswith(b"\n") else 1)
            spans = [Span(kind=UnitKind.file, name=None, byte_start=0, byte_end=len(source),
                          line_start=1, line_end=max(last_line, 1))]
        else:
            spans = window_spans(source, unit_tokens)
            method = "windowed"
    units: list[Unit] = []
    for s in spans:
        split_method = "windowed" if s.kind == UnitKind.window else method
        units.append(Unit(
            id=unit_id(path, s.line_start, s.line_end, split_method, s.byte_start, s.byte_end),
            tool=tool, module_id=path,
            path=path, language=language, kind=s.kind, name=s.name,
            line_start=s.line_start, line_end=s.line_end, byte_start=s.byte_start,
            byte_end=s.byte_end,
            token_estimate=estimate_tokens(source[s.byte_start:s.byte_end]),
            split_method=split_method, generated=generated,
        ))
    return units
