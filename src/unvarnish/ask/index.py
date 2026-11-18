from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from unvarnish.artifacts import hash_files, read_artifact, write_artifact
from unvarnish.ask.bm25 import BM25, tokenize
from unvarnish.engagement import Engagement
from unvarnish.schemas.analysis import UnitResult
from unvarnish.schemas.finding import Finding, Verification
from unvarnish.schemas.rollup import Module
from unvarnish.schemas.scan import ScannerFindings
from unvarnish.schemas.toolmodel import RequirementsInventory, ToolModel
from unvarnish.schemas.verify import ModelFindings

log = logging.getLogger("unvarnish.ask")
SNIPPET_CHARS = 240
Kind = Literal["unit", "module", "tool", "finding", "capability"]


class IndexDoc(BaseModel):
    id: str
    kind: Kind
    tool: str
    path: str | None = None
    text: str
    snippet: str


class Hit(BaseModel):
    id: str
    kind: Kind
    tool: str
    path: str | None
    score: float
    snippet: str


def _snip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= SNIPPET_CHARS else text[:SNIPPET_CHARS - 1] + "…"


class AskIndex(BaseModel):
    docs: list[IndexDoc] = Field(default_factory=list)
    inputs_hash: str = ""

    def search(self, query: str, tool: str | None = None, k: int = 8) -> list[Hit]:
        docs = [d for d in self.docs if tool is None or d.tool == tool]
        if not docs:
            return []
        cache = self.__dict__.setdefault("_bm25", {})  # built once per tool filter, not per query
        if tool not in cache:
            cache[tool] = BM25([tokenize(d.text) for d in docs])
        scores = cache[tool].score(tokenize(query))
        ranked = sorted(zip(scores, docs, strict=True), key=lambda p: -p[0])
        return [Hit(id=d.id, kind=d.kind, tool=d.tool, path=d.path, score=round(s, 3),
                    snippet=d.snippet) for s, d in ranked[:k] if s > 0]


def _finding_doc(tool: str, f: Finding) -> IndexDoc:
    text = f"{f.title}. {f.summary} {f.impact}"
    return IndexDoc(id=f.id, kind="finding", tool=tool, path=f.evidence[0].path, text=text,
                    snippet=_snip(f"{f.title} [{f.severity}, {f.source}]: {f.summary}"))


def _tool_docs(eng: Engagement, tool: str) -> list[IndexDoc]:
    p = eng.tool_paths(tool)
    docs: list[IndexDoc] = []
    for path in sorted(p.unit_dir.glob("*.json")) if p.unit_dir.exists() else []:
        try:
            r = read_artifact(path, UnitResult).data
        except Exception:
            continue
        label = f"{r.unit.path}:{r.unit.line_start}-{r.unit.line_end}"
        text = f"{label} {r.unit.name or ''} {r.extraction.purpose} " + " ".join(
            r.extraction.interface + r.extraction.risks)
        docs.append(IndexDoc(id=r.unit.id, kind="unit", tool=tool, path=r.unit.path, text=text,
                             snippet=_snip(f"{label}: {r.extraction.purpose}")))
    for path in sorted(p.module_dir.glob("*.json")) if p.module_dir.exists() else []:
        try:
            m = read_artifact(path, Module).data
        except Exception:
            continue
        text = f"{m.path} {m.rollup.summary} " + " ".join(m.rollup.responsibilities)
        docs.append(IndexDoc(id=m.id, kind="module", tool=tool, path=m.path, text=text,
                             snippet=_snip(f"{m.path}: {m.rollup.summary}")))
    if p.tool_model.exists():
        try:
            tm = read_artifact(p.tool_model, ToolModel).data
            text = f"{tool} {tm.purpose} " + " ".join(a.name for a in tm.actors) + " " + " ".join(
                tm.internal_stack + tm.deployment_assumptions)
            docs.append(IndexDoc(id=f"tool:{tool}", kind="tool", tool=tool, path=None, text=text,
                                 snippet=_snip(f"{tool}: {tm.purpose}")))
        except Exception:
            log.warning("index: unreadable tool.json for %s", tool)
    if p.capabilities.exists():
        try:
            req = read_artifact(p.capabilities, RequirementsInventory).data
            for c in req.capabilities:
                label = f"{c.actor} can {c.action} {c.object}"
                docs.append(IndexDoc(
                    id=f"cap:{c.id}", kind="capability", tool=tool,
                    path=c.evidence[0].path if c.evidence else None,
                    text=f"{label}. {c.description}", snippet=_snip(f"{label}: {c.description}")))
        except Exception:
            log.warning("index: unreadable capabilities.json for %s", tool)
    if p.scanner_findings.exists():
        try:
            for f in read_artifact(p.scanner_findings, ScannerFindings).data.findings:
                docs.append(_finding_doc(tool, f))
        except Exception:
            log.warning("index: unreadable scanner-findings.json for %s", tool)
    if p.model_findings.exists():
        try:
            for f in read_artifact(p.model_findings, ModelFindings).data.findings:
                if f.verification != Verification.rejected:
                    docs.append(_finding_doc(tool, f))
        except Exception:
            log.warning("index: unreadable findings.json for %s", tool)
    return docs


def index_inputs(eng: Engagement) -> list[Path]:
    out: list[Path] = []
    for tool in eng.tool_names():
        p = eng.tool_paths(tool)
        out += [p.extract_state, p.modules_index, p.tool_model, p.capabilities,
                p.model_findings, p.scanner_findings]
    return out


def build_index(eng: Engagement) -> AskIndex:
    docs: list[IndexDoc] = []
    for tool in eng.tool_names():
        docs.extend(_tool_docs(eng, tool))
    return AskIndex(docs=docs, inputs_hash=hash_files(index_inputs(eng)))


def load_or_build_index(eng: Engagement) -> tuple[AskIndex, bool]:
    """The cached index when its inputs are unchanged, else a fresh build (and True)."""
    current = hash_files(index_inputs(eng))
    if eng.index_file.exists():
        try:
            cached = read_artifact(eng.index_file, AskIndex).data
            if cached.inputs_hash == current:
                return cached, False
        except Exception:
            log.warning("ask index unreadable; rebuilding")
    index = build_index(eng)
    write_artifact(eng.index_file, index, produced_by="ask", inputs_hash=current)
    log.info("ask index built: %d documents", len(index.docs))
    return index, True
