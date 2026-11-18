from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.ask.index import AskIndex
from unvarnish.ask.tools import TOOL_SPECS
from unvarnish.engagement import Engagement
from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.structured import strict_schema

ASK_PROMPT_VERSION = "2026-10-17.1"  # bump whenever ask_system.md changes
ASK_MAX_TOKENS = 4000


def engagement_summary(eng: Engagement, index: AskIndex) -> str:
    lines = [f"Client: {eng.config.client or 'unknown'}. Tools under review:"]
    for tool in eng.tool_names():
        docs = [d for d in index.docs if d.tool == tool]
        kinds = {k: sum(1 for d in docs if d.kind == k)
                 for k in ("unit", "module", "finding", "capability")}
        has_model = any(d.kind == "tool" for d in docs)
        lines.append(f"- {tool}: {kinds['unit']} analysed units, {kinds['module']} modules, "
                     f"{kinds['finding']} findings, {kinds['capability']} capabilities"
                     + ("" if has_model else " (no tool model: scanner analysis only)"))
    return "\n".join(lines)


@cache
def _template() -> str:
    return (resources.files("unvarnish.model.prompts").joinpath("ask_system.md")
            .read_text(encoding="utf-8"))


def build_ask_system(summary: str, max_calls: int) -> str:
    from unvarnish.ask.loop import AskStep  # local import: loop imports this module

    tools = "\n".join(f"- {spec}" for spec in TOOL_SPECS.values())
    schema = json.dumps(strict_schema(AskStep), indent=1, sort_keys=True)
    return (_template().replace("{{ENGAGEMENT}}", summary).replace("{{TOOLS}}", tools)
            .replace("{{MAX_CALLS}}", str(max_calls)).replace("{{SCHEMA}}", schema))


def build_ask_request(system: str, messages: Sequence[Message],
                      effort: str | None) -> CompletionRequest:
    return CompletionRequest(system=system, messages=list(messages), schema_name="AskStep",
                             max_tokens=ASK_MAX_TOKENS, effort=effort, cache_system=True,
                             schema_in_system=True)
