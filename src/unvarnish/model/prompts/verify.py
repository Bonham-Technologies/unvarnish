from __future__ import annotations

import json
from collections.abc import Sequence
from functools import cache
from importlib import resources

from unvarnish.model.base import CompletionRequest, Message
from unvarnish.model.prompts.effort import EFFORT_GUIDE
from unvarnish.model.structured import strict_schema
from unvarnish.schemas.finding import Finding
from unvarnish.schemas.verify import Verdict

VERIFY_PROMPT_VERSION = "2026-11-10.1"  # bump whenever the verification prompt changes


@cache
def build_verify_system() -> str:
    template = (resources.files("unvarnish.model.prompts").joinpath("verify_system.md")
                .read_text(encoding="utf-8"))
    return (template.replace("{{EFFORT}}", EFFORT_GUIDE)
            .replace("{{SCHEMA}}", json.dumps(strict_schema(Verdict), indent=1, sort_keys=True)))


def build_verify_request(finding: Finding, excerpts: Sequence[str], effort: str | None,
                         system: str | None = None) -> CompletionRequest:
    band = (f"{finding.effort}" + (f" ({finding.effort_note})" if finding.effort_note else "")
            if finding.effort else "not estimated")
    body = (f"Claim: {finding.title}\nCategory: {finding.category}\n"
            f"Severity claimed: {finding.severity}\nSummary: {finding.summary}\n"
            f"Impact: {finding.impact}\nEffort claimed: {band}\n\nEvidence:\n\n"
            + "\n\n".join(excerpts))
    return CompletionRequest(system=system or build_verify_system(),
                             messages=[Message(role="user", content=body)],
                             schema_name="Verdict", max_tokens=1024, effort=effort,
                             cache_system=True)
