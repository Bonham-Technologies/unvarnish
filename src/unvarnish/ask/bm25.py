from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

TOKEN_RE = re.compile(r"[a-z0-9_]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class BM25:
    """Okapi BM25 over pre-tokenised documents; small, pure Python, no dependency."""

    def __init__(self, docs: Sequence[Sequence[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.doc_len = [len(d) for d in docs]
        self.avg_len = (sum(self.doc_len) / len(docs)) if docs else 0.0
        self.tf = [Counter(d) for d in docs]
        df: Counter[str] = Counter()
        for counts in self.tf:
            df.update(counts.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def score(self, query_tokens: Sequence[str]) -> list[float]:
        scores = [0.0] * len(self.tf)
        for term in query_tokens:
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i, counts in enumerate(self.tf):
                tf = counts.get(term)
                if not tf:
                    continue
                norm = 1 - self.b + self.b * (self.doc_len[i] / self.avg_len if self.avg_len else 0)
                scores[i] += idf * tf * (self.k1 + 1) / (tf + self.k1 * norm)
        return scores
