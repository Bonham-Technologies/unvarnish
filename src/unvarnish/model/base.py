from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import BaseModel, Field

from unvarnish.config import BackendCapabilities
from unvarnish.schemas.cost import Usage


class Message(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class CompletionRequest(BaseModel):
    system: str
    messages: list[Message]
    output_schema: dict | None = None
    schema_name: str = "output"
    max_tokens: int = 8000
    temperature: float | None = None
    effort: str | None = None
    cache_system: bool = True
    schema_in_system: bool = False  # the system prompt already shows the schema


class CompletionResponse(BaseModel):
    text: str
    usage: Usage = Field(default_factory=Usage)
    model: str
    stop_reason: str | None = None
    refusal_category: str | None = None
    cached: bool = False


class Backend(Protocol):
    name: str
    model: str
    capabilities: BackendCapabilities

    def complete(self, req: CompletionRequest) -> CompletionResponse: ...


class BackendError(Exception):
    pass


class BackendConfigError(BackendError):
    fatal = True  # propagates through the phase runner: nothing can proceed


class BackendUnavailable(BackendError):
    fatal = True


def display_url(url: str | None) -> str:
    """A base URL safe to print: scheme, host, port and path, never user info or a query."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url or "")
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:
        return "(unparseable URL)"
    if not parts.scheme or not host:
        return "(unparseable URL)"
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{port}{parts.path}".rstrip("/")


log = logging.getLogger("unvarnish.model")


def retry_rate_limited[T](
    call: Callable[[], T], *, is_rate_limit: Callable[[Exception], bool],
    retry_after: Callable[[Exception], float | None], retries: int,
    sleep: Callable[[float], None] = time.sleep, name: str = "",
) -> T:
    """Call `call`, backing off on rate limits up to `retries` times, then re-raise."""
    for attempt in range(retries + 1):
        try:
            return call()
        except Exception as exc:
            if not is_rate_limit(exc) or attempt >= retries:
                raise
            hinted = retry_after(exc)
            delay = (hinted if hinted is not None else min(60.0, 2.0 ** attempt))
            delay += random.uniform(0, 1)  # noqa: S311 - jitter, not security
            log.warning("%s: rate limited, retry %d/%d in %.1fs", name, attempt + 1, retries, delay)
            sleep(delay)
    raise AssertionError("unreachable")


def header_retry_after(exc: Exception) -> float | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    raw = headers.get("retry-after")
    try:
        return max(0.0, float(raw)) if raw is not None else None
    except ValueError:
        return None


class ModelRefusal(BackendError):
    def __init__(self, category: str | None, message: str = "model refused the request") -> None:
        super().__init__(f"{message} (category: {category or 'unknown'})")
        self.category = category
