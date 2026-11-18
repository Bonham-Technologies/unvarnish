from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

from unvarnish.model.base import (
    Backend,
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    Message,
)
from unvarnish.model.budget import BudgetExceeded, BudgetTracker
from unvarnish.scanners.secrets import redact_text
from unvarnish.schemas.analysis import FailureRecord
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.prose")
PROSE_PROMPT_VERSION = "2026-10-18.1"  # bump whenever prose_system.md, tones, or blocks change
FALLBACK = "_No model-written text for this section: {reason}._"
FENCE_RE = re.compile(r"^```[a-z]*\n(.*?)\n```$", re.DOTALL)
NUMBER_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen "
    "fifteen sixteen seventeen eighteen nineteen twenty".split())}
COUNT_RE = re.compile(
    r"\b(\d+|" + "|".join(NUMBER_WORDS) + r")[\s-]+(critical|high|medium|low|info)\b", re.I)

TONE_INSTRUCTIONS = {
    "direct": (
        "State problems plainly and quantify where possible. Never hedge or soften a scanner "
        "finding. When describing a high or critical finding, do not use minimising words such "
        "as minor, simply, just, slight, or only. Avoid jargon. Say what will happen if nothing "
        "changes."
    ),
    "measured": (
        "State problems accurately with their likelihood and context, and quantify where "
        "possible. Do not minimise high or critical findings, but acknowledge uncertainty where "
        "the facts are incomplete. Avoid jargon."
    ),
}


@dataclass(frozen=True)
class ProseBlock:
    name: str
    instruction: str
    max_words: int


BLOCKS: dict[str, ProseBlock] = {b.name: b for b in (
    ProseBlock("executive_summary", (
        "Write the executive summary for leadership in two to four short paragraphs. First, what "
        "the tool is and who uses it. Then the headline risks, worst first, with the counts of "
        "critical and high findings and what each headline risk means in business terms. Finish "
        "with the consequence of leaving the tool as it is."), 350),
    ProseBlock("purpose_and_users", (
        "Write one or two paragraphs on what the tool does, who the actors are, and how they "
        "reach it. Name the actors and entry points from the facts."), 250),
    ProseBlock("deployment", (
        "Write one paragraph on where and how the tool runs and what it assumes about its "
        "environment, drawn from the deployment assumptions, internal stack, and external "
        "systems. State which assumptions would break it if wrong."), 200),
    ProseBlock("build_history", (
        "Write one paragraph on how the tool was built, from the history facts: over how long, "
        "by how many people, how concentrated the authorship is, how large the commits are, and "
        "what the AI tooling indicators suggest. Neutral: this is evidence, not judgement."), 180),
    ProseBlock("open_questions", (
        "Write the open questions for stakeholder interviews as a numbered list, one line each, "
        "at most twelve. Draw them from the open questions, the implicit capabilities, the "
        "business rules found in code, and anything not analysed. Each question must be "
        "answerable by a person who owns or uses the tool."), 300),
    ProseBlock("tools_reviewed", (
        "Write one paragraph per tool, in the order given, each starting with the tool's name: "
        "what it is for, who uses it, how big it is, and whether it was model-analysed. Flag "
        "any tool that was not model-analysed so the reader knows its row in the matrix is "
        "missing."), 600),
    ProseBlock("consolidation_proposal", (
        "Write the consolidation proposal in three or four short paragraphs from the facts: "
        "what one tool would have to do (the union of capabilities), which current approach "
        "to keep for each contested capability and why, the gaps and conflicts between the "
        "tools, and the questions to settle before designing. State plainly that this is a "
        "starting point for the consultant's architecture work, not a design."), 450),
)}


@cache
def build_prose_system(tone: str) -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath("prose_system.md")
                .read_text(encoding="utf-8"))
    return template.replace("{{TONE}}", TONE_INSTRUCTIONS[tone])


PROSE_MAX_TOKENS = 2000
TRUNCATED = {"max_tokens", "length"}  # Anthropic and OpenAI-compatible stop reasons


def build_prose_request(block: ProseBlock, facts: dict, tone: str,
                        effort: str | None, max_tokens: int = PROSE_MAX_TOKENS
                        ) -> CompletionRequest:
    body = (f"{block.instruction}\nKeep it under {block.max_words} words.\n\nFacts (JSON):\n"
            + json.dumps(facts, ensure_ascii=False, indent=1, default=str))
    return CompletionRequest(system=build_prose_system(tone),
                             messages=[Message(role="user", content=body)],
                             schema_name="prose", output_schema=None, max_tokens=max_tokens,
                             effort=effort, cache_system=True)


def count_mismatches(text: str, facts: dict) -> list[str]:
    """Severity counts stated in the text ("eight medium") that the facts contradict. Smaller
    models miscount; the tables beside the prose come from data and stay right."""
    by_sev = (facts.get("findings") or {}).get("by_severity") if isinstance(facts, dict) else None
    if not isinstance(by_sev, dict):
        return []
    out: list[str] = []
    for word, sev in COUNT_RE.findall(text):
        n = int(word) if word.isdigit() else NUMBER_WORDS[word.lower()]
        actual = int(by_sev.get(sev.lower(), 0))
        item = f"{word} {sev.lower()} (facts: {actual})"
        if n != actual and item not in out:
            out.append(item)
    return out


def clean_prose(text: str) -> str:
    text = text.strip()
    m = FENCE_RE.match(text)
    return m.group(1).strip() if m else text


@dataclass
class ProseResult:
    text: dict[str, str] = field(default_factory=dict)
    usage: Usage = field(default_factory=Usage)
    failures: list[FailureRecord] = field(default_factory=list)
    stopped_for_budget: bool = False


def generate_prose(backend: Backend | None, requested: dict[str, dict], *, tone: str,
                   effort: str | None, budget: BudgetTracker) -> ProseResult:
    """Fill each requested block; every failure except an outage becomes a fallback sentence."""
    out = ProseResult()
    for name, facts in requested.items():
        block = BLOCKS.get(name)
        if block is None:
            out.text[name] = FALLBACK.format(reason=f"unknown prose block {name!r}")
            out.failures.append(FailureRecord(phase="render", unit_id=name,
                                              error=f"unknown prose block {name!r}"))
            continue
        if backend is None:
            out.text[name] = FALLBACK.format(reason="no model configured")
            continue
        try:
            budget.check()
        except BudgetExceeded:
            out.text[name] = FALLBACK.format(reason=budget.stop_reason)
            out.stopped_for_budget = True
            continue
        try:
            resp = backend.complete(build_prose_request(block, facts, tone, effort))
        except BudgetExceeded:  # interrupted while waiting for a model slot
            out.text[name] = FALLBACK.format(reason=budget.stop_reason)
            out.stopped_for_budget = True
            continue
        except BackendUnavailable:
            raise
        except BackendError as exc:
            out.text[name] = FALLBACK.format(reason="model call failed")
            out.failures.append(FailureRecord(phase="render", unit_id=name,
                                              error=str(exc)[:500]))
            continue
        out.usage = out.usage + resp.usage
        budget.add(resp.usage)
        if resp.stop_reason in TRUNCATED and resp.refusal_category is None:
            try:  # cut off mid-sentence: once more with twice the room
                longer = backend.complete(build_prose_request(block, facts, tone, effort,
                                                              2 * PROSE_MAX_TOKENS))
            except BudgetExceeded:  # interrupted: no cut-off text, no failure to record
                out.text[name] = FALLBACK.format(reason=budget.stop_reason)
                out.stopped_for_budget = True
                continue
            except BackendUnavailable:
                raise
            except BackendError:
                longer = None
            if longer is not None:
                out.usage = out.usage + longer.usage
                budget.add(longer.usage)
                if longer.text.strip() and longer.refusal_category is None:
                    resp = longer
            if resp.stop_reason in TRUNCATED:
                out.failures.append(FailureRecord(phase="render", unit_id=name,
                                                  error="prose cut off at the token limit"))
        if resp.refusal_category is not None or not resp.text.strip():
            reason = "model refused" if resp.refusal_category else "model returned empty text"
            out.text[name] = FALLBACK.format(reason=reason)
            out.failures.append(FailureRecord(phase="render", unit_id=name, error=reason))
            continue
        text = clean_prose(resp.text)
        wrong = count_mismatches(text, facts)
        if wrong:
            req = build_prose_request(block, facts, tone, effort)
            req.messages += [Message(role="assistant", content=text), Message(
                role="user", content=("Your text states counts that the facts contradict: "
                                      + "; ".join(wrong) + ". Rewrite it using exactly the "
                                      "counts in the facts."))]
            try:
                retry = backend.complete(req)
            except BudgetExceeded:  # interrupted: no misstated counts, no failure to record
                out.text[name] = FALLBACK.format(reason=budget.stop_reason)
                out.stopped_for_budget = True
                continue
            except BackendUnavailable:
                raise
            except BackendError:
                retry = None
            if retry is not None:
                out.usage = out.usage + retry.usage
                budget.add(retry.usage)
                if retry.refusal_category is None and retry.text.strip():
                    text = clean_prose(retry.text)
            still = count_mismatches(text, facts)
            if still:
                out.failures.append(FailureRecord(
                    phase="render", unit_id=name,
                    error="prose may misstate counts: " + "; ".join(still)))
        out.text[name] = redact_text(text)
        log.debug("prose %s: %d tokens", name, resp.usage.total())
    return out
