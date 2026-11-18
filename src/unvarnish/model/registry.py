from __future__ import annotations

import os

from unvarnish.config import BackendConfig, EngagementConfig, ModelRef
from unvarnish.engagement import Engagement
from unvarnish.model.base import Backend, BackendConfigError


class NoModelConfigured(BackendConfigError):
    pass


def resolve_model_ref(config: EngagementConfig, phase: str) -> ModelRef | None:
    return config.models.phases.get(phase) or config.models.default


def load_api_key(cfg: BackendConfig, name: str) -> str | None:
    if cfg.api_key_env:
        value = os.environ.get(cfg.api_key_env)
        if not value:
            raise BackendConfigError(
                f"backend {name!r}: environment variable {cfg.api_key_env} is not set"
            )
        return value
    if cfg.api_key_keychain:
        try:
            import keyring  # optional dependency
        except ImportError as exc:
            raise BackendConfigError(
                f"backend {name!r}: api_key_keychain needs the 'keyring' package"
            ) from exc
        value = keyring.get_password(cfg.api_key_keychain, name)
        if not value:
            raise BackendConfigError(
                f"backend {name!r}: no password in keychain service {cfg.api_key_keychain!r}"
            )
        return value
    return None


def build_backend(name: str, cfg: BackendConfig, model: str,
                  rate_limit_retries: int = 8) -> Backend:
    key = load_api_key(cfg, name)
    if cfg.type == "anthropic":
        from unvarnish.model.anthropic_backend import AnthropicBackend

        return AnthropicBackend(name=name, model=model, api_key=key, base_url=cfg.base_url,
                                capabilities=cfg.capabilities,
                                rate_limit_retries=rate_limit_retries)
    from unvarnish.model.openai_backend import OpenAICompatibleBackend

    if not cfg.base_url:
        raise BackendConfigError(f"backend {name!r}: openai_compatible needs base_url")
    return OpenAICompatibleBackend(name=name, model=model, api_key=key or "none",
                                   base_url=cfg.base_url, capabilities=cfg.capabilities,
                                   rate_limit_retries=rate_limit_retries,
                                   timeout_s=cfg.timeout_s, extra_body=cfg.extra_body)


def resolve_backend(eng: Engagement, phase: str) -> Backend:
    ref = resolve_model_ref(eng.config, phase)
    if ref is None:
        raise NoModelConfigured("no model configured: set models.default in engagement.yaml")
    cfg = eng.config.backends.get(ref.backend)
    if cfg is None:
        known = ", ".join(eng.config.backends) or "none"
        raise BackendConfigError(
            f"model for {phase!r} names backend {ref.backend!r}; known: {known}"
        )
    backend = build_backend(ref.backend, cfg, ref.model,
                            rate_limit_retries=eng.config.pipeline.rate_limit_retries)
    fallback = None
    fb = eng.config.models.refusal_fallback
    if fb is not None and (fb.backend, fb.model) != (ref.backend, ref.model):
        fb_cfg = eng.config.backends.get(fb.backend)
        if fb_cfg is None:
            raise BackendConfigError(f"models.refusal_fallback names unknown backend "
                                     f"{fb.backend!r}")
        fallback = build_backend(fb.backend, fb_cfg, fb.model,
                                 rate_limit_retries=eng.config.pipeline.rate_limit_retries)
    from unvarnish.model.cache import CachingBackend
    from unvarnish.model.limit import LimitedBackend, limiter_for
    from unvarnish.model.refusal import RefusalRetryBackend

    # Below the cache: cache hits take no slot, and refusals (never cached) are retried
    # inside the slot. The limiter is shared by every tool of the engagement.
    limiter = limiter_for(str(eng.root.resolve()), eng.config.pipeline.concurrency)
    return CachingBackend(LimitedBackend(RefusalRetryBackend(backend, fallback), limiter),
                          eng.cache_dir / "responses")
