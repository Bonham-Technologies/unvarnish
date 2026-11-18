from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import regex

from unvarnish.artifacts import read_artifact
from unvarnish.ask.index import AskIndex
from unvarnish.engagement import Engagement
from unvarnish.phases.base import source_missing_reason
from unvarnish.phases.ingest import load_tool_meta, resolve_source_root
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import SEVERITY_ORDER, Category, Finding, Severity, Verification
from unvarnish.schemas.inventory import Census
from unvarnish.schemas.rollup import Module, module_file_id
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import ToolModel
from unvarnish.schemas.verify import ModelFindings

TOOL_SPECS: dict[str, str] = {
    "search_index": "search_index(query, tool?) - BM25 over unit purposes, module summaries, "
                    "findings, and capabilities; returns ids, kinds, and snippets",
    "get_unit": "get_unit(id) - one analysed unit of code: path, lines, extraction, findings",
    "get_module": "get_module(id) - one file's rollup: summary, responsibilities, dependencies",
    "get_tool": "get_tool(name) - the tool model: purpose, actors, entry points, stores, "
                "external systems, capabilities, business rules",
    "get_findings": "get_findings(tool?, category?, severity?) - findings with evidence",
    "grep_source": "grep_source(pattern, tool, max_results) - regex over the tool's source, "
                   "skipping excluded files; returns path, line, text",
}
MAX_HITS = 8
MAX_FINDINGS = 40
MAX_GREP = 50
MAX_LINE_CHARS = 200
MAX_TEXT_CHARS = 1500
GREP_LINE_CHARS = 2_000
RESULT_CHARS = 12_000
ID_RE = re.compile(r"^[0-9a-f]{12,16}$")  # unit and module ids; never a path fragment
MAX_PATTERN_EXPANSION = 20_000  # 10x a searched line; ~15 MB compiled at worst
_REPEAT = re.compile(r"\{(\d*)(?:,\d*)?\}")
log = logging.getLogger("unvarnish.ask")


def _pattern_expansion(pattern: str) -> int:
    """Over-estimate how many nodes `regex` builds when it compiles `pattern`.

    `regex` writes out each repeat's minimum count, so nested minimums multiply and
    `a{4294967294}` exhausts memory at compile time, before any search timeout applies.
    Every item counts once and a repeat multiplies the item before it by its minimum.
    """
    stack = [[0, 0]]  # per open group: [cost so far, cost of the last item]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        item = 1
        if c == "\\":
            i += 2
            if pattern[i - 1:i] in ("p", "P", "N") and pattern[i:i + 1] == "{":
                close = pattern.find("}", i)  # \p{L}, \N{name}: the braces are not a repeat
                i = n if close < 0 else close + 1
        elif c == "[":
            i += 1
            if pattern[i:i + 1] == "^":
                i += 1
            if pattern[i:i + 1] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
        elif c == "(":
            stack.append([0, 0])
            i += 1
            continue
        elif c == ")" and len(stack) > 1:
            item = max(stack.pop()[0], 1)
            i += 1
        elif c == "{" and (m := _REPEAT.match(pattern, i)):
            cur, times = stack[-1], max(int(m.group(1) or 0), 1)
            cur[0] += cur[1] * (times - 1)
            cur[1] *= times
            i = m.end()
            if cur[0] > MAX_PATTERN_EXPANSION:
                return cur[0]
            continue
        else:
            i += 1
        stack[-1][0] += item
        stack[-1][1] = item
    return sum(frame[0] for frame in stack)


def _clip(v: Any) -> Any:
    if isinstance(v, str):
        return redact_text(v if len(v) <= MAX_TEXT_CHARS else v[:MAX_TEXT_CHARS] + "…")
    if isinstance(v, list):
        return [_clip(x) for x in v]
    if isinstance(v, dict):
        return {k: _clip(x) for k, x in v.items()}
    return v


def _finding_view(tool: str, f: Finding) -> dict:
    d = f.model_dump(mode="json", include={"id", "category", "severity", "title", "summary",
                                           "impact", "remediation", "source", "verification",
                                           "evidence"})
    d["tool"] = tool
    return d


class AskTools:
    def __init__(self, eng: Engagement, index: AskIndex) -> None:
        self.eng = eng
        self.index = index
        self.tools = eng.tool_names()

    # --- helpers -----------------------------------------------------------
    def _unknown_tool(self, name: str) -> dict:
        return {"error": f"unknown tool {name!r}; known: {', '.join(self.tools)}"}

    def _findings_for(self, tool: str) -> list[Finding]:
        p = self.eng.tool_paths(tool)
        out: list[Finding] = []
        if p.scanner_findings.exists():
            out += read_artifact(p.scanner_findings, ScannerFindings).data.findings
        if p.model_findings.exists():
            out += [f for f in read_artifact(p.model_findings, ModelFindings).data.findings
                    if f.verification != Verification.rejected]
        return out

    # --- tools ---------------------------------------------------------------
    def search_index(self, query: str, tool: str | None = None) -> dict:
        if tool is not None and tool not in self.tools:
            return self._unknown_tool(tool)
        hits = self.index.search(query, tool=tool, k=MAX_HITS)
        return _clip({"hits": [h.model_dump() for h in hits]})

    def get_unit(self, id: str) -> dict:  # noqa: A002 - the spec's argument name
        if not ID_RE.match(id):
            return {"error": f"invalid unit id {id!r}: ids are 12-16 hex characters"}
        for tool in self.tools:
            path = self.eng.tool_paths(tool).unit_dir / f"{id}.json"
            if path.exists():
                r = read_artifact(path, UnitResult).data
                return _clip({
                    "id": r.unit.id, "tool": tool, "path": r.unit.path,
                    "lines": [r.unit.line_start, r.unit.line_end], "kind": r.unit.kind.value,
                    "name": r.unit.name, "extraction": r.extraction.model_dump(mode="json"),
                    "findings": [_finding_view(tool, f) for f in r.findings],
                })
        return {"error": f"no unit with id {id!r}"}

    def get_module(self, id: str) -> dict:  # noqa: A002
        for tool in self.tools:
            d = self.eng.tool_paths(tool).module_dir
            candidates = [d / f"{module_file_id(id)}.json"]  # a file path
            if ID_RE.match(id):
                candidates.insert(0, d / f"{id}.json")  # a module id
            for path in candidates:
                if path.exists():
                    m = read_artifact(path, Module).data
                    return _clip({
                        "id": m.id, "tool": tool, "path": m.path, "unit_ids": m.unit_ids,
                        "summary": m.rollup.summary,
                        "responsibilities": m.rollup.responsibilities,
                        "interface": m.rollup.interface,
                        "dependencies_in": m.rollup.dependencies_in,
                        "dependencies_out": m.rollup.dependencies_out,
                        "findings": [_finding_view(tool, f) for f in m.findings],
                    })
        return {"error": f"no module with id or path {id!r}"}

    def get_tool(self, name: str) -> dict:
        if name not in self.tools:
            return self._unknown_tool(name)
        p = self.eng.tool_paths(name)
        if not p.tool_model.exists():
            return {"error": f"tool {name!r} has no tool model (model analysis not run or "
                             "failed); use get_findings and grep_source"}
        tm = read_artifact(p.tool_model, ToolModel).data
        return _clip(tm.model_dump(mode="json", exclude={
            "findings", "usage", "backend", "model", "prompt_version", "attempts",
            "dropped_findings"}))

    def get_findings(self, tool: str | None = None, category: str | None = None,
                     severity: str | None = None) -> dict:
        if tool is not None and tool not in self.tools:
            return self._unknown_tool(tool)
        if category is not None and category not in {c.value for c in Category}:
            return {"error": f"unknown category {category!r}; known: "
                             f"{', '.join(c.value for c in Category)}"}
        if severity is not None and severity not in {s.value for s in Severity}:
            return {"error": f"unknown severity {severity!r}; known: "
                             f"{', '.join(s.value for s in Severity)}"}
        rows: list[dict] = []
        for t in ([tool] if tool else self.tools):
            for f in self._findings_for(t):
                if category and f.category.value != category:
                    continue
                if severity and f.severity.value != severity:
                    continue
                rows.append(_finding_view(t, f))
        rows.sort(key=lambda r: (SEVERITY_ORDER[Severity(r["severity"])], r["tool"]))
        truncated = len(rows) > MAX_FINDINGS
        return _clip({"findings": rows[:MAX_FINDINGS], "total": len(rows),
                      "truncated": truncated})

    def grep_source(self, pattern: str, tool: str, max_results: int = 20) -> dict:
        if tool not in self.tools:
            return self._unknown_tool(tool)
        if isinstance(pattern, str) and _pattern_expansion(pattern) > MAX_PATTERN_EXPANSION:
            return {"error": "pattern too large; use smaller repeat counts"}
        try:
            rx = regex.compile(pattern)  # re's syntax, plus a per-call timeout
        except (regex.error, ValueError, TypeError) as exc:
            return {"error": f"invalid regex: {exc}"}
        max_results = max(1, min(int(max_results), MAX_GREP))
        p = self.eng.tool_paths(tool)
        if not p.census.exists():
            return {"error": f"tool {tool!r} has not been inventoried; run `unvarnish run`"}
        census = read_artifact(p.census, Census).data
        meta = load_tool_meta(p)
        root = resolve_source_root(self.eng, meta)
        if source_missing_reason(root, meta) is not None:  # not "no matches" (UNVAR-31)
            return {"error": f"the source of tool {tool!r} does not exist any more; answer "
                             "from the analysis (get_findings, get_unit, get_module)"}
        matches: list[dict] = []
        searched = 0
        truncated = slow = False
        deadline = time.monotonic() + self.eng.config.ask.grep_timeout_s
        for rec in census.files:
            if rec.excluded or rec.classification == "binary":
                continue
            searched += 1
            try:
                text = (root / rec.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.split("\n"), start=1):
                line = line[:GREP_LINE_CHARS]  # a minified line is not searched past this
                left = deadline - time.monotonic()  # file reads spend the budget too
                try:
                    if left <= 0:
                        raise TimeoutError
                    hit = rx.search(line, timeout=left)
                except TimeoutError:
                    slow = truncated = True
                    break
                if hit:
                    if len(matches) >= max_results:
                        truncated = True
                        break
                    matches.append({"path": rec.path, "line": n,
                                    "text": redact_text(line.strip()[:MAX_LINE_CHARS])})
            if truncated:
                break
        result = {"matches": matches, "searched_files": searched, "truncated": truncated}
        return {"error": "pattern too slow; simplify it", **result} if slow else result

    # --- dispatch --------------------------------------------------------------
    REQUIRED = {"search_index": ("query",), "get_unit": ("id",), "get_module": ("id",),
                "get_tool": ("name",), "get_findings": (), "grep_source": ("pattern", "tool")}

    def dispatch(self, name: str, args: dict) -> dict:
        if name not in TOOL_SPECS:
            return {"error": f"unknown tool {name!r}; known: {', '.join(TOOL_SPECS)}"}
        missing = [a for a in self.REQUIRED[name] if not args.get(a)]
        if missing:
            return {"error": f"{name} needs {', '.join(missing)}"}
        allowed = {"search_index": {"query", "tool"}, "get_unit": {"id"}, "get_module": {"id"},
                   "get_tool": {"name"}, "get_findings": {"tool", "category", "severity"},
                   "grep_source": {"pattern", "tool", "max_results"}}[name]
        kwargs = {k: v for k, v in args.items() if k in allowed and v not in (None, "")}
        try:
            result = getattr(self, name)(**kwargs)
        except (ValueError, TypeError) as exc:
            return {"error": f"{name}: bad arguments: {exc}"}
        except Exception as exc:  # a tool failure is a result for the model, never a crash
            log.exception("ask tool %s failed", name)
            return {"error": f"{name} failed: {type(exc).__name__}: {exc}"[:500]}
        encoded = json.dumps(result, ensure_ascii=False)
        if len(encoded) > RESULT_CHARS:
            result = {**result, "note": f"result truncated to {RESULT_CHARS} characters"}
            encoded = json.dumps(result, ensure_ascii=False)[:RESULT_CHARS]
            return {"truncated_json": encoded}
        return result
