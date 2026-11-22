from __future__ import annotations

import logging
import re
from pathlib import Path

from unvarnish.analysis.languages import Classification
from unvarnish.analysis.split import split_file
from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.config import EngagementConfig
from unvarnish.model.registry import resolve_model_ref
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.schemas.analysis import SkippedFile, Unit, UnitsIndex
from unvarnish.schemas.inventory import Census, FileRecord
from unvarnish.util.plural import plural

log = logging.getLogger("unvarnish.split")

MAX_SPLIT_BYTES = 5_000_000
# Files that describe no behaviour: patterns, licences, crawler hints, editor and version pins,
# and shell or REPL history.
NO_BEHAVIOUR_NAMES = {"robots.txt", "sitemap.xml", ".editorconfig", ".nvmrc", ".node-version",
                      ".python-version", ".ruby-version", ".tool-versions", "copying",
                      ".gitattributes", ".mailmap"}
NO_BEHAVIOUR_RE = re.compile(
    r"^(?:\..*ignore|licen[cs]e(?:\.\w+)?|copying\.\w+|\.rhistory|\.\w+_(?:repl_)?history)$", re.I)


def describes_no_behaviour(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name.lower() in NO_BEHAVIOUR_NAMES or bool(NO_BEHAVIOUR_RE.match(name))


SPLIT_CLASSES = {Classification.source, Classification.test, Classification.config,
                 Classification.docs, Classification.generated}


def resolve_unit_tokens(config: EngagementConfig) -> int:
    ref = resolve_model_ref(config, "extract")
    if ref is not None:
        backend = config.backends.get(ref.backend)
        if backend is not None and backend.unit_tokens:
            return backend.unit_tokens
    return config.pipeline.unit_tokens


def split_records(ctx: ToolContext, records: list[FileRecord]) -> tuple[UnitsIndex, list[str]]:
    """Split the census's files into units, reading the source and writing nothing; the
    failures are one line per file that could not be split."""
    unit_tokens = resolve_unit_tokens(ctx.config)
    units: list[Unit] = []
    modules: dict[str, list[str]] = {}
    skipped: list[SkippedFile] = []
    failures: list[str] = []
    for rec in records:
        if (rec.excluded or rec.classification not in SPLIT_CLASSES
                or describes_no_behaviour(rec.path)):
            continue
        if rec.bytes > MAX_SPLIT_BYTES:
            skipped.append(SkippedFile(path=rec.path,
                                       reason=f"larger than {MAX_SPLIT_BYTES:,} bytes"))
            continue
        try:
            source = (ctx.source_root / rec.path).read_bytes()
            file_units = split_file(
                source, rec.path, rec.language, unit_tokens, tool=ctx.tool,
                generated=rec.classification == Classification.generated,
            )
        except Exception as exc:  # one bad file never kills a run
            failures.append(f"{rec.path}: split failed: {exc!r}")
            skipped.append(SkippedFile(path=rec.path, reason=f"split failed: {exc!r}"))
            continue
        units.extend(file_units)
        modules[rec.path] = [u.id for u in file_units]
    return UnitsIndex(tool=ctx.tool, unit_tokens=unit_tokens, units=units, modules=modules,
                      skipped=skipped), failures


class SplitPhase:
    name = "split"
    reads_source = True  # fails when the source is gone (UNVAR-31)
    depends_on = ("inventory",)  # the census

    def inputs_hash(self, ctx: ToolContext) -> str:
        return hash_inputs([hash_files([ctx.paths.census]), str(resolve_unit_tokens(ctx.config))])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.units_index]

    def run(self, ctx: ToolContext) -> PhaseResult:
        census = read_artifact(ctx.paths.census, Census).data
        index, failures = split_records(ctx, census.files)
        units, modules, skipped = index.units, index.modules, index.skipped
        write_artifact(ctx.paths.units_index, index, produced_by=self.name,
                       inputs_hash=self.inputs_hash(ctx))
        log.info("split %s: %s across %s (%d skipped)", ctx.tool, plural(len(units), "unit"),
                 plural(len(modules), "file"), len(skipped))
        return PhaseResult(
            phase=self.name, status=PhaseStatus.ok, failures=failures,
            message=(f"{plural(len(units), 'unit')} in {plural(len(modules), 'file')}, "
                     f"{len(skipped)} skipped"),
        )
