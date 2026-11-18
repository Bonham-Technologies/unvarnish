from __future__ import annotations

BYTES_PER_TOKEN = 3  # conservative for source code; real tokenizers average ~3.5


def estimate_tokens(data: bytes | str) -> int:
    n = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
    return max(1, n // BYTES_PER_TOKEN)
