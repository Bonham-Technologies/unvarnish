from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
    header_retry_after,
    retry_rate_limited,
)
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.model")


class AnthropicBackend:
    def __init__(self, name: str, model: str, api_key: str | None, base_url: str | None,
                 capabilities: BackendCapabilities, max_retries: int = 3,
                 rate_limit_retries: int = 8,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        import anthropic

        self.name = name
        self.model = model
        self.capabilities = capabilities
        self._rate_limit_retries = rate_limit_retries
        self._sleep = sleep
        kwargs: dict[str, Any] = {"max_retries": max_retries}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)

    @staticmethod
    def timeout_for(max_tokens: int) -> float:
        """Seconds to allow a non-streaming call: ten minutes, or longer for big outputs."""
        return max(600.0, max_tokens * 0.05)

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        import anthropic

        system: list[dict[str, Any]] = [{"type": "text", "text": req.system}]
        if req.cache_system:
            system[0]["cache_control"] = {"type": "ephemeral"}
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": req.max_tokens,
            "system": system,
            "messages": [m.model_dump() for m in req.messages],
        }
        output_config: dict[str, Any] = {}
        if req.output_schema is not None and self.capabilities.json_schema:
            output_config["format"] = {"type": "json_schema", "schema": req.output_schema}
        if req.effort:
            output_config["effort"] = req.effort
        if output_config:
            kwargs["output_config"] = output_config
        if req.temperature is not None:
            # The anthropic SDK's Messages.create has no temperature argument; passing one
            # raises TypeError before the request is sent (UNVAR-69). Drop it here; the
            # OpenAI-compatible backend still honours it.
            log.debug("%s: temperature %s dropped; the Anthropic backend does not send it",
                      self.name, req.temperature)
        # The SDK refuses a non-streaming call whose max_tokens implies more than ten minutes
        # of output unless a timeout is given explicitly. Long structured outputs (the tool
        # rollup) are legitimate here, so give each call a timeout that scales with its size.
        kwargs["timeout"] = self.timeout_for(req.max_tokens)

        try:
            resp = retry_rate_limited(
                lambda: self._client.messages.create(**kwargs),
                is_rate_limit=lambda e: isinstance(e, anthropic.RateLimitError),
                retry_after=header_retry_after, retries=self._rate_limit_retries,
                sleep=self._sleep, name=self.name,
            )
        except anthropic.BadRequestError as exc:
            raise BackendError(f"{self.name}: bad request: {exc.message}") from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError,
                anthropic.NotFoundError) as exc:
            raise BackendUnavailable(f"{self.name}: {exc.message}") from exc
        except anthropic.RateLimitError as exc:
            raise BackendUnavailable(
                f"{self.name}: still rate limited after {self._rate_limit_retries} retries: "
                f"{exc.message}"
            ) from exc
        except anthropic.InternalServerError as exc:
            raise BackendUnavailable(f"{self.name}: gave up after retries: {exc.message}") from exc
        except anthropic.APITimeoutError as exc:
            # One slow request is that unit's failure, not the run's.
            raise BackendError(
                f"{self.name}: no reply within {kwargs['timeout']:.0f}s") from exc
        except anthropic.APIConnectionError as exc:
            raise BackendUnavailable(f"{self.name}: connection failed: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise BackendUnavailable(f"{self.name}: HTTP {exc.status_code}: {exc.message}") from exc

        u = resp.usage
        usage = Usage(
            input_tokens=u.input_tokens or 0, output_tokens=u.output_tokens or 0,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
        )
        refusal: str | None = None
        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            refusal = (getattr(details, "category", None) or "unknown") if details else "unknown"
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return CompletionResponse(text=text, usage=usage, model=resp.model,
                                  stop_reason=resp.stop_reason, refusal_category=refusal)
