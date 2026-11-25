from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.prompts.effort import EFFORT_GUIDE
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.analysis import Unit, UnitExtraction
from unvarnish.schemas.finding import Category, Severity

PROMPT_VERSION = "2026-11-10.1"  # bump whenever the system prompt or unit message changes
NEIGHBOURHOOD_MAX = 8
NEIGHBOURHOOD_CHARS = 200
ROUTE_NOTE = (
    "Scanner note: no authentication check was found near the route handler at line {line} "
    "(a heuristic). Confirm whether it is protected (middleware, a wrapper, a check in the "
    "body); if it is not and it reads or changes data, report it as a candidate finding."
)
AI_NOTE = (
    "Scanner note: line {line} calls a model or defines a tool for one (a heuristic). Check "
    "what reaches the prompt (request input mixed into instructions is a prompt-injection "
    "path) and what the code does with the answer or the tool calls (code execution, a "
    "shell, SQL, file or data changes); report a candidate finding if either is unsafe."
)
GENERATED_INSTRUCTION = (
    "This unit comes from a generated or minified file. Report only purpose and external_calls; "
    "leave the other lists empty and candidate_findings empty unless a credential is visible."
)


@cache
def build_system_prompt(categories: tuple[str, ...] | None = None) -> str:
    template = (
        resources.files("unvarnish.model.prompts")
        .joinpath("extract_system.md")
        .read_text(encoding="utf-8")
    )
    cats = ", ".join(categories or tuple(c.value for c in Category))
    sevs = ", ".join(s.value for s in Severity)
    schema = json.dumps(strict_schema(UnitExtraction), indent=1, sort_keys=True)
    return (template.replace("{{CATEGORIES}}", cats).replace("{{SEVERITIES}}", sevs)
            .replace("{{EFFORT}}", EFFORT_GUIDE).replace("{{SCHEMA}}", schema))


def build_unit_message(unit: Unit, source: str, *, frameworks: Sequence[str],
                       neighbourhood: Sequence[str], scanner_notes: Sequence[str] = ()) -> str:
    label = unit.kind.value + (f" {unit.name}" if unit.name else "")
    parts = [
        f"File: {unit.path}",
        f"Unit: {label}, lines {unit.line_start}-{unit.line_end}",
        f"Language: {unit.language or 'unknown'}",
        f"Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}",
    ]
    if unit.split_method == "windowed":
        parts.append("Note: this is a window of a larger region; boundaries may cut constructs.")
    if unit.generated:
        parts.append(GENERATED_INSTRUCTION)
    if neighbourhood:
        parts.append("Neighbouring units already analysed (purpose only):")
        for n in list(neighbourhood)[-NEIGHBOURHOOD_MAX:]:
            parts.append(f"- {n[:NEIGHBOURHOOD_CHARS]}")
    parts.extend(scanner_notes)
    parts.append("Source:")
    parts.append(source)
    return "\n".join(parts)


def build_extract_request(unit: Unit, source: str, *, frameworks: Sequence[str],
                          neighbourhood: Sequence[str], effort: str | None,
                          system: str | None = None,
                          scanner_notes: Sequence[str] = ()) -> CompletionRequest:
    return CompletionRequest(
        system=system or build_system_prompt(),
        messages=[Message(role="user", content=build_unit_message(
            unit, source, frameworks=frameworks, neighbourhood=neighbourhood,
            scanner_notes=scanner_notes))],
        schema_name="UnitExtraction", effort=effort, cache_system=True,
    )
