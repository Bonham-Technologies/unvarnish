from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from unvarnish.config import BackendCapabilities
from unvarnish.model.base import Backend, CompletionRequest, CompletionResponse
from unvarnish.schemas.cost import Usage

CACHE_SCHEMA_VERSION = "1"


def cache_key(backend_name: str, model: str, req: CompletionRequest) -> str:
    payload = {"v": CACHE_SCHEMA_VERSION, "backend": backend_name, "model": model,
               "request": req.model_dump(mode="json")}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


class CachingBackend:
    """Content-addressed cache in front of a backend. A hit costs nothing and is marked cached."""

    def __init__(self, inner: Backend, cache_dir: Path) -> None:
        self.inner = inner
        self.cache_dir = cache_dir

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def model(self) -> str:
        return self.inner.model

    @property
    def capabilities(self) -> BackendCapabilities:
        return self.inner.capabilities

    def key(self, req: CompletionRequest) -> str:
        return cache_key(self.inner.name, self.inner.model, req)

    def _path(self, req: CompletionRequest) -> Path:
        return self.cache_dir / f"{self.key(req)}.json"

    def has(self, req: CompletionRequest) -> bool:
        return self._path(req).exists()

    def store(self, key: str, resp: CompletionResponse) -> bool:
        """Keep `resp` as the reply to the request whose key is `key`, unless it is a refusal,
        empty, or cut off: those are never cached. True when it was kept."""
        truncated = resp.stop_reason in ("max_tokens", "length")
        if resp.refusal_category is not None or not resp.text.strip() or truncated:
            return False
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self.cache_dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(resp.model_dump_json())
        os.replace(tmp_name, self.cache_dir / f"{key}.json")
        return True

    def complete(self, req: CompletionRequest) -> CompletionResponse:
        path = self._path(req)
        if path.exists():
            stored = CompletionResponse.model_validate_json(path.read_text(encoding="utf-8"))
            return stored.model_copy(update={"cached": True, "usage": Usage()})
        resp = self.inner.complete(req)
        self.store(self.key(req), resp)
        return resp

    def forget(self, reqs: Iterable[CompletionRequest]) -> int:
        """Drop cached responses for `reqs` (a conversation that ended in failure)."""
        n = 0
        for req in reqs:
            path = self._path(req)
            if path.exists():
                path.unlink()
                n += 1
        return n


def clear_cache(cache_dir: Path) -> int:
    if not cache_dir.exists():
        return 0
    n = 0
    for p in list(cache_dir.glob("*.json")) + list(cache_dir.glob("*.tmp")):
        p.unlink()
        if p.suffix == ".json":
            n += 1
    return n
