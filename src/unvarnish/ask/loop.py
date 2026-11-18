from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.ask.index import AskIndex
from unvarnish.ask.tools import AskTools
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend, BackendError, Message, ModelRefusal
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.model.prompts.ask import (
    ASK_MAX_TOKENS,
    build_ask_request,
    build_ask_system,
    engagement_summary,
)
from unvarnish.model.structured import StructuredOutputError, complete_structured
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.ask")
ToolName = Literal["search_index", "get_unit", "get_module", "get_tool", "get_findings",
                   "grep_source"]
PREVIEW_CHARS = 300
HEX_ID_RE = re.compile(r"\b(?:cap:)?[0-9a-f]{12,16}\b")
PATH_RE = re.compile(r"(?<![\w/])([\w.\-]+(?:/[\w.\-]+)*\.[A-Za-z0-9]+)(:\d+(?:-\d+)?)?")
TOOL_REF_RE = re.compile(r"\btool:([a-z0-9][a-z0-9_-]*)")
NO_ANSWER = "The model did not produce an answer within the tool-call limit."
ELIDED = "[result elided to fit the context window]"
WINDOW_HEADROOM = 0.9  # keep the conversation plus the reply under this share of the window


def result_message(name: str, args: dict, result: dict, left: int) -> str:
    return (f"Result of {name}({json.dumps(args)}):\n"
            f'<tool_result name="{name}">\n{json.dumps(result, ensure_ascii=False)}\n'
            f"</tool_result>\n\n{left} tool call{'s' if left != 1 else ''} left.")


def fit_to_window(system: str, messages: list[Message], window: int) -> bool:
    """Elide the oldest tool results until the next call fits; False when nothing more can go."""
    limit = int(window * WINDOW_HEADROOM) - ASK_MAX_TOKENS

    def size() -> int:
        return estimate_tokens(system) + sum(estimate_tokens(m.content) for m in messages)

    while size() > limit:
        victim = next((m for m in messages if m.role == "user" and m.content.startswith("Result of")
                       and ELIDED not in m.content), None)
        if victim is None:
            return False
        head, _, tail = victim.content.partition("\n")
        left_note = tail.rsplit("\n\n", 1)[-1]
        victim.content = f"{head}\n{ELIDED}\n\n{left_note}"
    return True


class AskStep(BaseModel):
    """One turn of the loop: a tool call or the final answer."""

    action: Literal["call", "answer"]
    tool: ToolName | None = None
    query: str | None = None
    tool_name: str | None = None  # a tool under review
    id: str | None = None
    category: str | None = None
    severity: str | None = None
    pattern: str | None = None
    max_results: int | None = None
    answer: str | None = None
    citations: list[str] = Field(default_factory=list)


class StepRecord(BaseModel):
    kind: Literal["call", "answer", "error"]
    tool: str | None = None
    args: dict = Field(default_factory=dict)
    result_preview: str | None = None
    usage: Usage = Field(default_factory=Usage)


class AskResult(BaseModel):
    question: str
    answer: str
    citations: list[str] = Field(default_factory=list)
    verified: bool = False
    completed: bool = False
    steps: list[StepRecord] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    tool_filter: str | None = None
    stopped_for_budget: bool = False


def call_args(step: AskStep, tool_filter: str | None) -> tuple[str, dict]:
    name = step.tool or ""
    under_review = tool_filter or step.tool_name  # the consultant's --tool wins
    args: dict = {}
    if name == "search_index":
        args = {"query": step.query, "tool": under_review}
    elif name in ("get_unit", "get_module"):
        args = {"id": step.id}
    elif name == "get_tool":
        args = {"name": under_review}
    elif name == "get_findings":
        args = {"tool": under_review, "category": step.category, "severity": step.severity}
    elif name == "grep_source":
        args = {"pattern": step.pattern, "tool": under_review, "max_results": step.max_results}
    return name, {k: v for k, v in args.items() if v is not None}


def find_citations(text: str, explicit: Sequence[str], index: AskIndex) -> list[str]:
    """Ids and paths that exist in the index, from the explicit list and the answer text."""
    ids = {d.id for d in index.docs}
    paths = {d.path for d in index.docs if d.path}
    tool_refs = {f"tool:{d.tool}" for d in index.docs}
    found: list[str] = []

    def keep(c: str) -> None:
        if c not in found:
            found.append(c)

    candidates = list(explicit)
    candidates += HEX_ID_RE.findall(text)
    candidates += [f"tool:{t}" for t in TOOL_REF_RE.findall(text)]
    candidates += [p + (ln or "") for p, ln in PATH_RE.findall(text)]
    for c in candidates:
        c = c.strip().strip("`'\"")
        if c in ids or c in tool_refs:
            keep(c)
            continue
        if f"cap:{c}" in ids:  # get_tool returns bare capability ids
            keep(f"cap:{c}")
            continue
        c = re.sub(r"^(\./|/)", "", c)
        path = c.split(":", 1)[0]
        if path in paths and re.fullmatch(r"[^:]+(?::\d+(?:-\d+)?)?", c):
            keep(c)
    return found


def _preview(result: dict) -> str:
    text = json.dumps(result, ensure_ascii=False)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS - 1] + "…"


def run_question(eng: Engagement, backend: Backend, tools: AskTools, index: AskIndex,
                 question: str, *, tool_filter: str | None = None, budget: BudgetTracker,
                 effort: str | None, max_calls: int) -> AskResult:
    system = build_ask_system(engagement_summary(eng, index), max_calls)
    opening = question if tool_filter is None else f"{question}\n(Restrict to tool {tool_filter}.)"
    messages: list[Message] = [Message(role="user", content=opening)]
    result = AskResult(question=question, answer="", tool_filter=tool_filter)
    calls = 0
    forced = False
    window = backend.capabilities.context_window
    while True:
        try:
            budget.check()
        except BudgetExceeded:
            result.answer = "Budget cap reached before an answer was produced."
            result.stopped_for_budget = True
            return result
        if not fit_to_window(system, messages, window):
            if forced:
                result.answer = NO_ANSWER
                result.steps.append(StepRecord(kind="error", result_preview=NO_ANSWER))
                return result
            calls = max_calls  # out of room: the next turn must be the answer
        try:
            res = complete_structured(backend, build_ask_request(system, messages, effort),
                                      AskStep)
        except (ModelRefusal, StructuredOutputError) as exc:
            result.steps.append(StepRecord(kind="error", result_preview=str(exc)[:PREVIEW_CHARS]))
            result.answer = f"No answer: {exc}"
            return result
        except BackendError as exc:
            if getattr(exc, "fatal", False):
                raise
            result.steps.append(StepRecord(kind="error", result_preview=str(exc)[:PREVIEW_CHARS]))
            result.answer = f"No answer: {exc}"
            return result
        result.usage = result.usage + res.usage
        budget.add(res.usage)
        step = res.parsed
        if step.action == "call" and not step.tool and calls < max_calls:
            calls += 1  # an invalid call costs a call, not the forced-answer turn
            result.steps.append(StepRecord(kind="error", result_preview="call with no tool",
                                           usage=res.usage))
            messages += [
                Message(role="assistant", content=res.raw_text),
                Message(role="user", content=(
                    "That call did not name a tool. Name a tool from the list, or answer.")),
            ]
            continue
        if step.action == "call" and step.tool and calls < max_calls:
            name, args = call_args(step, tool_filter)
            tool_result = tools.dispatch(name, args)
            calls += 1
            result.steps.append(StepRecord(kind="call", tool=name, args=args,
                                           result_preview=_preview(tool_result),
                                           usage=res.usage))
            left = max_calls - calls
            messages += [
                Message(role="assistant", content=res.raw_text),
                Message(role="user", content=result_message(name, args, tool_result, left)),
            ]
            continue
        if step.action == "call":
            if not forced:
                forced = True
                messages += [
                    Message(role="assistant", content=res.raw_text),
                    Message(role="user", content=(
                        'You have no tool calls left. Answer now with action "answer" from '
                        "what you have, citing the ids or paths you relied on.")),
                ]
                continue
            result.answer = NO_ANSWER
            result.steps.append(StepRecord(kind="error", result_preview=NO_ANSWER,
                                           usage=res.usage))
            return result
        answer = redact_text((step.answer or "").strip())
        result.answer = answer or "(empty answer)"
        result.citations = find_citations(answer, step.citations, index)
        result.verified = bool(result.citations)
        result.completed = True
        result.steps.append(StepRecord(kind="answer", usage=res.usage,
                                       result_preview=answer[:PREVIEW_CHARS]))
        return result


def session_name(started: datetime) -> str:
    """Session file names to the millisecond, so two sessions never share a file."""
    return f"{started.strftime('%Y%m%d-%H%M%S')}-{started.microsecond // 1000:03d}.md"


def write_session(eng: Engagement, results: Sequence[AskResult], started: datetime) -> Path:
    eng.ask_sessions_dir.mkdir(parents=True, exist_ok=True)
    path = eng.ask_sessions_dir / session_name(started)
    lines = [f"# Ask session {started.strftime('%Y-%m-%d %H:%M UTC')}", ""]
    for i, r in enumerate(results, start=1):
        lines += [f"## Q{i}. {redact_text(r.question)}"
                  + (f" (tool: {r.tool_filter})" if r.tool_filter else ""),
                  "", r.answer, ""]
        if r.verified:
            lines.append("Citations: " + ", ".join(f"`{c}`" for c in r.citations))
        elif r.completed:
            lines.append("**Unverified: no citations.**")
        else:
            lines.append("**No answer produced.**")
        calls = [s for s in r.steps if s.kind == "call"]
        if calls:
            lines += ["", "Tool calls:"]
            lines += [f"- `{s.tool}` {json.dumps(s.args)}" for s in calls]
        lines += ["", f"Tokens: {r.usage.total():,}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
