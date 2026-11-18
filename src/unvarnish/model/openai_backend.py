from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from unvarnish.analysis.tokens import estimate_tokens
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

PROMPT_ESTIMATE_PAD = 1.25   # the estimate is character-based; code tokenises denser
CONTEXT_MARGIN = 512
MIN_OUTPUT_TOKENS = 1024
DEFAULT_TIMEOUT_S = 1800.0  # on-prem servers on modest hardware are slow; the SDK default is 600


class OpenAICompatibleBackend:
    """Any endpoint speaking the OpenAI chat-completions protocol: vLLM, Ollama, Azure, gateways."""

    def __init__(self, name: str, model: str, api_key: str, base_url: str,
                 capabilities: BackendCapabilities, max_retries: int = 3,
                 rate_limit_retries: int = 8, timeout_s: float | None = None,
                 extra_body: dict[str, Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        from openai import OpenAI

        self.name = name
        self.model = model
        self.capabilities = capabilities
        self._rate_limit_retries = rate_limit_retries
        self._max_retries = max_retries
        self._timeout_s = timeout_s or DEFAULT_TIMEOUT_S
        self._max_param = capabilities.max_tokens_param
        self._extra_body = extra_body
        self._sleep = sleep
        # The SDK would retry a timeout too, repeating the slowest work a server has; retries
        # for dropped connections and server errors are done in _create instead.
        self._client = OpenAI(api_key=api_key, base_url=base_url, max_retries=0,
                              timeout=self._timeout_s)

    def _fit_max_tokens(self, req: CompletionRequest) -> int:
        """The output allowance, clamped so prompt plus output fits the server's context.
        vLLM and OpenRouter reject a request whose prompt and max_tokens exceed the window
        (a 32k server refused the tool rollup's 32,000-token allowance); Ollama truncates."""
        text = req.system + "".join(m.content or "" for m in req.messages)
        prompt = int(estimate_tokens(text) * PROMPT_ESTIMATE_PAD) + CONTEXT_MARGIN
        room = self.capabilities.context_window - prompt
        return min(req.max_tokens, max(MIN_OUTPUT_TOKENS, room))

    def _create(self, kwargs: dict[str, Any]) -> Any:
        import openai

        for attempt in range(self._max_retries + 1):
            try:
                return self._client.chat.completions.create(**kwargs)
            except openai.APITimeoutError:
                raise
            except (openai.APIConnectionError, openai.InternalServerError):
                if attempt == self._max_retries:
                    raise
                self._sleep(2.0 * 2 ** attempt)
        raise AssertionError("unreachable")

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        import openai

        messages: list[dict[str, Any]] = [{"role": "system", "content": req.system}]
        messages += [m.model_dump() for m in req.messages]
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages,
                                  self._max_param: self._fit_max_tokens(req)}
        if self._extra_body:
            kwargs["extra_body"] = self._extra_body
        if req.temperature is not None:
            kwargs["temperature"] = req.temperature
        if req.output_schema is not None and self.capabilities.json_schema:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": req.schema_name, "schema": req.output_schema,
                                "strict": True},
            }
        try:
            resp = retry_rate_limited(
                lambda: self._create(kwargs),
                is_rate_limit=lambda e: isinstance(e, openai.RateLimitError),
                retry_after=header_retry_after, retries=self._rate_limit_retries,
                sleep=self._sleep, name=self.name,
            )
        except openai.BadRequestError as exc:
            if "max_completion_tokens" in str(exc.message) and self._max_param == "max_tokens":
                self._max_param = "max_completion_tokens"  # remembered for later requests
                return self.complete(req)
            raise BackendError(f"{self.name}: bad request: {exc.message}") from exc
        except (openai.AuthenticationError, openai.PermissionDeniedError,
                openai.NotFoundError) as exc:
            raise BackendUnavailable(f"{self.name}: {exc.message}") from exc
        except openai.RateLimitError as exc:
            raise BackendUnavailable(
                f"{self.name}: still rate limited after {self._rate_limit_retries} retries: "
                f"{exc.message}"
            ) from exc
        except openai.InternalServerError as exc:
            raise BackendUnavailable(f"{self.name}: gave up after retries: {exc.message}") from exc
        except openai.APITimeoutError as exc:
            # One unit too slow for this server is that unit's failure, not the run's.
            raise BackendError(
                f"{self.name}: no reply within {self._timeout_s:.0f}s; raise "
                f"backends.{self.name}.timeout_s for this server") from exc
        except openai.APIConnectionError as exc:
            raise BackendUnavailable(f"{self.name}: connection failed: {exc}") from exc
        except openai.APIStatusError as exc:
            raise BackendUnavailable(f"{self.name}: HTTP {exc.status_code}: {exc.message}") from exc

        choice = resp.choices[0]
        text = choice.message.content or ""
        refusal = getattr(choice.message, "refusal", None)
        u = resp.usage
        cached = 0
        if u is not None and getattr(u, "prompt_tokens_details", None) is not None:
            cached = getattr(u.prompt_tokens_details, "cached_tokens", 0) or 0
        usage = Usage(
            input_tokens=(u.prompt_tokens if u else 0) or 0,
            output_tokens=(u.completion_tokens if u else 0) or 0,
            cache_read_tokens=cached,
        )
        return CompletionResponse(text=text, usage=usage, model=resp.model or self.model,
                                  stop_reason=choice.finish_reason,
                                  refusal_category="refusal" if refusal else None)
