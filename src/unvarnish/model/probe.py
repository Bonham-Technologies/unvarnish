from __future__ import annotations

import secrets
from collections.abc import Callable

from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.model.base import Backend, CompletionRequest, Message
from unvarnish.schemas.cost import Usage

FILLER = "This sentence is filler for a context-length check and carries no information. "
PROBE_CAP_TOKENS = 30_000  # enough to catch the common 2k/4k/8k/16k server defaults


def probe_context(backend: Backend, target_tokens: int,
                  on_usage: Callable[[Usage], None] | None = None) -> tuple[bool, str]:
    """Send a prompt of about `target_tokens` with a code word at its start and ask for it
    back. A server that silently truncates long prompts (Ollama defaults to 4,096 tokens)
    loses the start and cannot answer. `on_usage` receives the call's token usage so the caller
    can record the spend."""
    word = f"ZEBRA-{secrets.randbelow(9000) + 1000}"
    head = f"The code word is {word}. Remember it; you will be asked for it at the end.\n"
    question = "\nWhat is the code word? Reply with the code word only."
    per_line = estimate_tokens(FILLER)
    filler = FILLER * max(0, (target_tokens - estimate_tokens(head + question)) // per_line)
    req = CompletionRequest(system="Answer the question at the end briefly.",
                            messages=[Message(role="user", content=head + filler + question)],
                            max_tokens=50, cache_system=False)
    resp = backend.complete(req)
    if on_usage is not None:
        on_usage(resp.usage)
    seen = resp.usage.input_tokens or 0
    if word in resp.text:
        return True, f"answered from a {target_tokens:,}-token prompt"
    return False, (f"the server did not see the start of a {target_tokens:,}-token prompt "
                   f"(it reported {seen:,} prompt tokens), so it is probably truncating to "
                   f"its own context length; raise it (Ollama: OLLAMA_CONTEXT_LENGTH, vLLM: "
                   f"--max-model-len) or lower capabilities.context_window")
