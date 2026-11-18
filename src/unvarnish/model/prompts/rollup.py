from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from pydantic import BaseModel

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.prompts.effort import EFFORT_GUIDE
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import Category, Severity
from unvarnish.schemas.rollup import ModuleDigest, ModuleRollup
from unvarnish.schemas.toolmodel import DirectoryRollup, ToolRollup

ROLLUP_PROMPT_VERSION = "2026-11-10.1"  # module rollup prompt; bump when it changes
TOOL_ROLLUP_PROMPT_VERSION = "2026-11-10.1"  # directory and tool rollup prompts
UNIT_TEXT_CHARS = 1200
UNITS_PER_MODULE = 200
LIST_CAP = 12
DIRECTORY_MAX_TOKENS = 16_000  # a chunk summary over hundreds of files
TOOL_MAX_TOKENS = 32_000  # module map, capabilities, rules, flows for a whole tool


@cache
def _system(template_name: str, schema_cls: type[BaseModel]) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath(template_name)
                .read_text(encoding="utf-8"))
    cats = ", ".join(c.value for c in Category)
    sevs = ", ".join(s.value for s in Severity)
    schema = json.dumps(strict_schema(schema_cls), indent=1, sort_keys=True)
    return (template.replace("{{CATEGORIES}}", cats).replace("{{SEVERITIES}}", sevs)
            .replace("{{EFFORT}}", EFFORT_GUIDE).replace("{{SCHEMA}}", schema))


def build_module_rollup_system() -> str:
    return _system("rollup_module_system.md", ModuleRollup)


def build_directory_rollup_system() -> str:
    return _system("rollup_directory_system.md", DirectoryRollup)


def build_tool_rollup_system() -> str:
    return _system("rollup_tool_system.md", ToolRollup)


def _join(items: Sequence[str]) -> str:
    return "; ".join(items[:LIST_CAP]) + (f"; (+{len(items) - LIST_CAP} more)"
                                         if len(items) > LIST_CAP else "")


def unit_text(r: UnitResult) -> str:
    u, e = r.unit, r.extraction
    label = u.kind.value + (f" {u.name}" if u.name else "")
    window = " (window)" if u.split_method == "windowed" else ""
    lines = [f"### {label}, lines {u.line_start}-{u.line_end}{window}", e.purpose]
    if e.interface:
        lines.append("interface: " + _join(e.interface))
    if e.external_calls:
        lines.append("external: " + _join([f"{c.system} ({c.kind}): {c.detail}"
                                           for c in e.external_calls]))
    if e.data_read:
        lines.append("reads: " + _join(e.data_read))
    if e.data_written:
        lines.append("writes: " + _join(e.data_written))
    if e.auth_behaviour:
        lines.append("auth: " + e.auth_behaviour)
    if e.error_handling:
        lines.append("errors: " + e.error_handling)
    if e.risks:
        lines.append("risks: " + _join(e.risks))
    if r.findings:
        lines.append("findings already recorded: " + _join([
            f"{f.title} [{f.severity}] lines {f.evidence[0].line_start}-{f.evidence[0].line_end}"
            for f in r.findings]))
    return "\n".join(lines)[:UNIT_TEXT_CHARS]


def build_module_message(path: str, language: str | None, file_lines: int,
                         units: Sequence[UnitResult], frameworks: Sequence[str],
                         max_tokens: int | None = None) -> str:
    """The module rollup input. With `max_tokens`, units are added only while they fit, so a
    very large file on a small-context server is summarised from its first units instead of
    failing."""
    parts = [f"File: {path}", f"Language: {language or 'unknown'}", f"Lines: {file_lines}",
             f"Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}",
             f"Units analysed: {len(units)}", ""]
    used = estimate_tokens("\n".join(parts)) + 40  # room for the omission note
    shown = 0
    for r in units[:UNITS_PER_MODULE]:
        text = unit_text(r)
        cost = estimate_tokens(text) + 1
        if max_tokens is not None and used + cost > max_tokens:
            break
        parts += [text, ""]
        used += cost
        shown += 1
    omitted = len(units) - shown
    if omitted:
        why = "omitted to fit the model's context" if shown < min(len(units), UNITS_PER_MODULE) \
            else "more units omitted"
        parts.append(f"(+{omitted} {why})")
    return "\n".join(parts)


def build_module_rollup_request(path: str, language: str | None, file_lines: int,
                                units: Sequence[UnitResult], frameworks: Sequence[str],
                                effort: str | None, system: str | None = None,
                                max_input_tokens: int | None = None) -> CompletionRequest:
    return CompletionRequest(
        system=system or build_module_rollup_system(),
        messages=[Message(role="user", content=build_module_message(
            path, language, file_lines, units, frameworks, max_tokens=max_input_tokens))],
        schema_name="ModuleRollup", effort=effort, cache_system=True,
    )


def digest_text(d: ModuleDigest) -> str:
    bits = [f"- {d.path} ({d.language or '?'}, {d.lines} lines, {d.units} units): "
            f"{d.summary[:400]}"]
    if d.responsibilities:
        bits.append("  responsibilities: " + _join(d.responsibilities))
    if d.interface:
        bits.append("  interface: " + _join(d.interface))
    if d.dependencies_out:
        bits.append("  depends on: " + _join(d.dependencies_out))
    if d.external_systems:
        bits.append("  external: " + _join(d.external_systems))
    if d.data_read or d.data_written:
        bits.append(f"  data: reads {_join(d.data_read) or '-'}; "
                    f"writes {_join(d.data_written) or '-'}")
    if d.findings:
        bits.append(f"  findings: {d.findings}")
    return "\n".join(bits)


def build_directory_rollup_request(prefix: str, digests: Sequence[ModuleDigest],
                                   effort: str | None,
                                   system: str | None = None) -> CompletionRequest:
    body = (f"Path prefix: {prefix or '(repository root)'}\nFiles: {len(digests)}\n\n"
            + "\n".join(digest_text(d) for d in digests))
    return CompletionRequest(system=system or build_directory_rollup_system(),
                             messages=[Message(role="user", content=body)],
                             schema_name="DirectoryRollup", effort=effort, cache_system=True,
                             max_tokens=DIRECTORY_MAX_TOKENS)


class ToolFacts(BaseModel):
    tool: str
    languages: dict[str, int]
    frameworks: list[str]
    files_analysed: int
    source_lines: int
    commits: int | None = None
    authors: int | None = None
    first_commit: str | None = None
    last_commit: str | None = None


def facts_text(f: ToolFacts) -> str:
    langs = ", ".join(f"{k} {v:,} lines" for k, v in
                      sorted(f.languages.items(), key=lambda kv: -kv[1])[:8]) or "unknown"
    history = (f"{f.commits:,} commits by {f.authors} author(s), {f.first_commit} to "
               f"{f.last_commit}" if f.commits is not None else "no git history")
    return (f"Tool: {f.tool}\nLanguages: {langs}\n"
            f"Frameworks: {', '.join(f.frameworks) if f.frameworks else 'none detected'}\n"
            f"Files analysed: {f.files_analysed:,}; source lines: {f.source_lines:,}\n"
            f"History: {history}")


def chunk_text(prefix: str, n_files: int, dr: DirectoryRollup) -> str:
    lines = [f"## Chunk {prefix or '(repository root)'} ({n_files} files)", dr.summary]
    if dr.responsibilities:
        lines.append("responsibilities: " + _join(dr.responsibilities))
    if dr.entry_points:
        lines.append("entry points: " + _join([f"{e.name} [{e.kind}] in {e.module}"
                                               for e in dr.entry_points]))
    if dr.data_stores:
        lines.append("data stores: " + _join([f"{s.name} [{s.kind}]" for s in dr.data_stores]))
    if dr.external_systems:
        lines.append("external systems: " + _join([f"{s.name} [{s.kind}, {s.direction}]"
                                                   for s in dr.external_systems]))
    if dr.notable_modules:
        lines.append("notable modules:")
        lines.extend(f"- {m.path}: {m.role}" + (f" (depends on {_join(m.depends_on)})"
                                                if m.depends_on else "")
                     for m in dr.notable_modules)
    if dr.risks:
        lines.append("risks: " + _join(dr.risks))
    if dr.candidate_findings:
        lines.append("findings: " + _join([f"{c.title} [{c.severity}]"
                                           for c in dr.candidate_findings]))
    return "\n".join(lines)


def build_tool_rollup_request(facts: ToolFacts, digests: Sequence[ModuleDigest],
                              chunks: Sequence[tuple[str, int, DirectoryRollup]],
                              effort: str | None, system: str | None = None) -> CompletionRequest:
    parts = [facts_text(facts), ""]
    if chunks:
        n = len(chunks)
        parts.append(f"The tool was summarised in {n} directory chunk{'s' if n != 1 else ''}:")
        parts.append("")
        for prefix, n_files, dr in chunks:
            parts.append(chunk_text(prefix, n_files, dr))
            parts.append("")
    else:
        parts.append("Files:")
        parts.extend(digest_text(d) for d in digests)
    return CompletionRequest(system=system or build_tool_rollup_system(),
                             messages=[Message(role="user", content="\n".join(parts))],
                             schema_name="ToolRollup", effort=effort, cache_system=True,
                             max_tokens=TOOL_MAX_TOKENS)
