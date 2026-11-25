from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import (
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    CompletionResponse,
    display_url,
    header_retry_after,
    retry_rate_limited,
)
from unvarnish.model.batch import BatchResult, BatchRetryLater
from unvarnish.schemas.cost import Usage

log = logging.getLogger("unvarnish.model")


class AnthropicBackend:
    def __init__(self, name: str, model: str, api_key: str | None, base_url: str | None,
                 capabilities: BackendCapabilities, max_retries: int = 3,
                 rate_limit_retries: int = 8,
                 sleep: Callable[[float], None] = time.sleep, batch: bool = False,
                 client: Any = None) -> None:
        import anthropic

        self.name = name
        self.model = model
        self.capabilities = capabilities
        self.batch = batch  # verify and prose go through the Message Batches API (UNVAR-94)
        self._rate_limit_retries = rate_limit_retries
        self._sleep = sleep
        self.sleep = sleep  # how a batch poll waits; injected so tests never really sleep
        if client is None:
            kwargs: dict[str, Any] = {"max_retries": max_retries}
            if api_key:
                kwargs["api_key"] = api_key
            if base_url:
                kwargs["base_url"] = base_url
            client = anthropic.Anthropic(**kwargs)
        self._client = client
        self._base_url = str(self._client.base_url)

    @staticmethod
    def timeout_for(max_tokens: int) -> float:
        """Seconds to allow a non-streaming call: ten minutes, or longer for big outputs."""
        return max(600.0, max_tokens * 0.05)

    def _params(self, req: CompletionRequest) -> dict[str, Any]:
        """The Messages API parameters for `req`, the same for a call and a batch request."""
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
        return kwargs

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        import anthropic

        kwargs = self._params(req)
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
            raise BackendUnavailable(
                f"{self.name}: connection to {display_url(self._base_url)} failed: {exc}"
            ) from exc
        except anthropic.APIStatusError as exc:
            raise BackendUnavailable(f"{self.name}: HTTP {exc.status_code}: {exc.message}") from exc

        return self._response(resp)

    def _response(self, resp: Any) -> CompletionResponse:
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

    # --- Message Batches (UNVAR-94) ----------------------------------------------------
    @contextmanager
    def _batch_errors(self, what: str) -> Iterator[None]:
        """The batch endpoints' errors as backend errors: an outage or a bad key stops the
        run, anything else is this batch's problem and the phase falls back to calls."""
        import anthropic

        try:
            yield
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise BackendUnavailable(f"{self.name}: {what}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise BackendUnavailable(
                f"{self.name}: {what}: connection to {display_url(self._base_url)} failed: "
                f"{exc}") from exc
        except anthropic.InternalServerError as exc:
            raise BackendUnavailable(f"{self.name}: {what}: gave up after retries: "
                                     f"{exc.message}") from exc
        except anthropic.RateLimitError as exc:  # the batch is fine: ask again later
            raise BatchRetryLater(f"{self.name}: {what}: HTTP 429: {exc.message}") from exc
        except anthropic.APIStatusError as exc:
            raise BackendError(f"{self.name}: {what}: HTTP {exc.status_code}: "
                               f"{exc.message}") from exc

    def submit_batch(self, items: list[tuple[str, CompletionRequest]]) -> str:
        """Create one message batch; each item is (custom_id, request). Returns its id."""
        requests = [{"custom_id": custom_id, "params": self._params(req)}
                    for custom_id, req in items]
        with self._batch_errors("batch submission"):
            batch = self._client.messages.batches.create(requests=requests)
        return batch.id

    def batch_ended(self, batch_id: str) -> bool:
        with self._batch_errors(f"batch {batch_id}"):
            batch = self._client.messages.batches.retrieve(batch_id)
        counts = getattr(batch, "request_counts", None)
        if counts is not None:
            log.info("%s: batch %s %s: %s processing, %s succeeded, %s errored, %s expired",
                     self.name, batch_id, batch.processing_status, counts.processing,
                     counts.succeeded, counts.errored, counts.expired)
        return batch.processing_status == "ended"

    def batch_results(self, batch_id: str) -> Iterator[BatchResult]:
        with self._batch_errors(f"batch {batch_id} results"):
            for item in self._client.messages.batches.results(batch_id):
                result = item.result
                if result.type == "succeeded":
                    yield BatchResult(custom_id=item.custom_id,
                                      response=self._response(result.message))
                elif result.type == "errored":
                    err = getattr(result.error, "error", None)
                    detail = (f"{getattr(err, 'type', 'error')}: {getattr(err, 'message', '')}"
                              if err is not None else "unknown error")
                    yield BatchResult(custom_id=item.custom_id, error=f"errored: {detail}")
                else:  # canceled or expired
                    yield BatchResult(custom_id=item.custom_id, error=result.type)
