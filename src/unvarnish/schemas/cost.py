from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from unvarnish.config import Prices


def priced(prices: Prices | dict[str, Prices] | None, model: str) -> Prices | None:
    """The price that applies to one model: the single price, or that model's entry."""
    if prices is None or isinstance(prices, Prices):
        return prices
    return prices.get(model)


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )

    def total(self) -> int:
        return (self.input_tokens + self.output_tokens + self.cache_read_tokens
                + self.cache_write_tokens)

    def usd(self, p: Prices) -> float:
        """Cache tokens at their own rates when configured, else at the input rate."""
        read = p.cache_read_per_mtok if p.cache_read_per_mtok is not None else p.input_per_mtok
        write = (p.cache_write_per_mtok if p.cache_write_per_mtok is not None
                 else p.input_per_mtok)
        return (self.input_tokens * p.input_per_mtok + self.output_tokens * p.output_per_mtok
                + self.cache_read_tokens * read + self.cache_write_tokens * write) / 1e6


class CostEntry(BaseModel):
    tool: str
    phase: str
    backend: str
    model: str
    usage: Usage
    at: datetime


class CostLedger(BaseModel):
    entries: list[CostEntry] = Field(default_factory=list)

    def total(self) -> Usage:
        acc = Usage()
        for e in self.entries:
            acc = acc + e.usage
        return acc

    def by_phase(self) -> dict[str, Usage]:
        out: dict[str, Usage] = {}
        for e in self.entries:
            out[e.phase] = out.get(e.phase, Usage()) + e.usage
        return out

    def unpriced(self, prices: Prices | dict[str, Prices] | None) -> list[str]:
        return sorted({e.model for e in self.entries if priced(prices, e.model) is None})

    def estimate_usd(self, prices: Prices | dict[str, Prices] | None) -> float | None:
        """Total cost, each entry at its own model's price; None if any model is unpriced."""
        if prices is None or self.unpriced(prices):
            return None
        return sum(e.usage.usd(priced(prices, e.model)) for e in self.entries)  # type: ignore[arg-type]
