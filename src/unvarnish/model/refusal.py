from __future__ import annotations

import logging

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import Backend, CompletionRequest, CompletionResponse

log = logging.getLogger("unvarnish.model")


class RefusalRetryBackend:
    """Retries a refused request once on the same model, then once on a fallback model.

    Safety classifiers sometimes refuse benign review material (Opus refused ESCAPESUITE's
    capability list as "cyber"; the same request passed on a second try). The response
    returned carries the usage of every call made."""

    def __init__(self, primary: Backend, fallback: Backend | None = None) -> None:
        self.primary = primary
        self.fallback = fallback

    @property
    def name(self) -> str:
        return self.primary.name

    @property
    def model(self) -> str:
        return self.primary.model

    @property
    def capabilities(self) -> BackendCapabilities:
        return self.primary.capabilities

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        resp = self.primary.complete(req)
        usage = resp.usage
        attempts = [(self.primary, "retry")]
        if self.fallback is not None:
            attempts.append((self.fallback, "fallback"))
        for backend, label in attempts:
            if resp.refusal_category is None:
                break
            log.warning("%s: refused (%s); %s on %s", self.primary.name,
                        resp.refusal_category, label, backend.model)
            resp = backend.complete(req)
            usage = usage + resp.usage
        return resp.model_copy(update={"usage": usage})
