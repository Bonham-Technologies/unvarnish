from __future__ import annotations

import re
from pathlib import Path

from unvarnish.analysis.treesitter import MAX_PARSE_BYTES, get_parser, tree_metrics
from unvarnish.schemas.inventory import FileMetrics, HtmlBreakdown

SCRIPT_RE = re.compile(rb"<script\b[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
STYLE_RE = re.compile(rb"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)


def count_lines(data: bytes) -> int:
    if not data:
        return 0
    n = data.count(b"\n")
    if not data.endswith(b"\n"):
        n += 1
    return n


def count_lines_in_file(path: Path, chunk: int = 1 << 20) -> int:
    """Line count without loading the file into memory."""
    n = 0
    last = b""
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            n += block.count(b"\n")
            last = block[-1:]
    if last and last != b"\n":
        n += 1
    return n


def html_breakdown(data: bytes) -> tuple[HtmlBreakdown, bytes]:
    scripts = [m.group(1) for m in SCRIPT_RE.finditer(data)]
    styles = [m.group(1) for m in STYLE_RE.finditer(data)]
    script_bytes = sum(len(s) for s in scripts)
    style_bytes = sum(len(s) for s in styles)
    script_lines = sum(count_lines(s.strip(b"\n")) for s in scripts)
    style_lines = sum(count_lines(s.strip(b"\n")) for s in styles)
    total_lines = count_lines(data)
    bd = HtmlBreakdown(
        markup_lines=max(total_lines - script_lines - style_lines, 0),
        script_lines=script_lines,
        style_lines=style_lines,
        markup_bytes=max(len(data) - script_bytes - style_bytes, 0),
        script_bytes=script_bytes,
        style_bytes=style_bytes,
        script_blocks=len(scripts),
        style_blocks=len(styles),
    )
    return bd, b"\n".join(scripts)


def _treesitter_metrics(source: bytes, language: str, line_offset: int = 0) -> dict:
    """Metrics for one parse. `line_offset` maps row 0 of `source` to a file line (1-based)."""
    parser = get_parser(language)
    if parser is None or len(source) > MAX_PARSE_BYTES:
        return {}
    found = tree_metrics(parser.parse(source), language, source)
    longest = max(found.spans, key=lambda s: s[2] - s[1], default=None)
    return {
        "functions": len(found.spans),
        "max_function_lines": (longest[2] - longest[1] + 1) if longest else 0,
        "max_function_name": longest[0] if longest else None,
        "max_function_start": (longest[1] + line_offset) if longest else None,
        "max_function_end": (longest[2] + line_offset) if longest else None,
        "max_nesting": found.max_nesting,
        "comment_lines": found.comment_lines,
    }


def _merge_block_metrics(blocks: list[dict]) -> dict:
    if not blocks:
        return {}
    longest = max(blocks, key=lambda b: b["max_function_lines"])
    return {
        "functions": sum(b["functions"] for b in blocks),
        "max_function_lines": longest["max_function_lines"],
        "max_function_name": longest["max_function_name"],
        "max_function_start": longest["max_function_start"],
        "max_function_end": longest["max_function_end"],
        "max_nesting": max(b["max_nesting"] for b in blocks),
        "comment_lines": sum(b["comment_lines"] for b in blocks),
    }


def compute_metrics(path: Path, relpath: str, language: str | None) -> FileMetrics:
    size = path.stat().st_size
    if size > MAX_PARSE_BYTES:
        return FileMetrics(path=relpath, lines=count_lines_in_file(path), bytes=size,
                           metrics_method="lines")
    data = path.read_bytes()
    base = {"path": relpath, "lines": count_lines(data), "bytes": len(data)}

    if language == "html":
        bd, _ = html_breakdown(data)
        blocks = []
        for m in SCRIPT_RE.finditer(data):
            # row 0 of the block is the file line where the block content starts
            offset = data.count(b"\n", 0, m.start(1))
            ts = _treesitter_metrics(m.group(1), "javascript", line_offset=offset)
            if ts:
                blocks.append(ts)
        merged = _merge_block_metrics(blocks)
        return FileMetrics(
            **base, html=bd, metrics_method="treesitter" if merged else "lines", **merged
        )

    ts = _treesitter_metrics(data, language) if language else {}
    if ts:
        return FileMetrics(**base, metrics_method="treesitter", **ts)
    return FileMetrics(**base, metrics_method="lines")
