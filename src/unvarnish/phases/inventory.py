from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath

from unvarnish.analysis import eol, treesitter, vulndata
from unvarnish.analysis.advisories import lookup_dependencies
from unvarnish.analysis.dependencies import parse_manifests
from unvarnish.analysis.languages import (
    Classification,
    Excluder,
    classify,
    detect_language,
    is_binary,
)
from unvarnish.analysis.licences import attach_licences
from unvarnish.analysis.metrics import compute_metrics, count_lines_in_file
from unvarnish.artifacts import (
    digest_file,
    hash_inputs,
    hash_tree,
    walk_files,
    write_artifact,
)
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext, missing_source
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    FileRecord,
    Metrics,
)
from unvarnish.util.env import env_flag
from unvarnish.util.gitcmd import GitError, git, is_git_repo
from unvarnish.util.plural import plural

SAMPLE_BYTES = 8192
METRICS_CLASSES = {Classification.source, Classification.test}


def tracked_files(ctx: ToolContext) -> set[str] | None:
    """The paths in the tool's git index, relative to its source root, or None when there is
    no index to consult: a --files pile (even one copied with a .git inside), a linked folder
    without its own .git, or an index git can't read. Then .gitignore applies as written."""
    root = ctx.source_root
    if ctx.meta.origin_kind == "files" or not is_git_repo(root):
        return None
    try:
        out = git(["ls-files", "-z"], cwd=root)
    except GitError:  # an untrusted or broken repo: keep the .gitignore-only behaviour
        return None
    return set(filter(None, out.split("\0")))


def file_record(path: Path, rel_str: str, excluder: Excluder) -> tuple[FileRecord, bool]:
    """One file's census record and whether it is binary. Raises OSError if unreadable."""
    rel = PurePosixPath(rel_str)
    size = path.stat().st_size
    with path.open("rb") as fh:
        sample = fh.read(SAMPLE_BYTES)
    binary = is_binary(sample)
    lines = 0 if binary else count_lines_in_file(path)
    language = None if binary else detect_language(rel, sample)
    reason = excluder.reason(rel)
    return FileRecord(
        path=rel.as_posix(), bytes=size, lines=lines, language=language,
        classification=classify(rel, language, sample), excluded=reason is not None,
        exclusion_reason=reason,
    ), binary


def census_files(root: Path, tracked: set[str] | None = None) -> list[FileRecord]:
    """The census's file records for the source as it is now, without metrics, manifests or
    advisories, and without writing anything: what split reads, for a dry run's estimate.
    `tracked` is the git index (`tracked_files`), so the records match the real inventory's."""
    excluder = Excluder(root, tracked)
    records: list[FileRecord] = []
    for path, rel_str in walk_files(root)[0]:
        try:
            records.append(file_record(path, rel_str, excluder)[0])
        except OSError:
            continue
    return records


class InventoryPhase:
    name = "inventory"
    depends_on: tuple[str, ...] = ()  # reads only the source tree
    reads_source = True

    def inputs_hash(self, ctx: ToolContext) -> str:
        return self._hash(ctx, _previous_gaps(ctx), eol.bundle_date(), vulndata.bundle_date())

    def retry_pending(self, ctx: ToolContext) -> bool:
        """A census from before its content digest (UNVAR-34) reruns once: the phases after it
        are stale anyway under the new artifact hash, so they rerun once, with the digest."""
        try:
            raw = json.loads(ctx.paths.census.read_text(encoding="utf-8"))
            return not raw["data"].get("content_digest")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return False  # missing or unreadable: the hash check decides

    def _hash(self, ctx: ToolContext, gaps: list[str], eol_date: str | None = None,
              vuln_date: str | None = None) -> str:
        # The advisory lookup depends on whether osv-scanner is installed and on its options,
        # so installing it or changing them makes the inventory stale. Tracking or untracking a
        # gitignored file changes what is excluded without touching the tree (UNVAR-28).
        deps_options = json.dumps(ctx.config.scanners.get("dependencies", {}), sort_keys=True)
        tracked = tracked_files(ctx)
        index = "no-index" if tracked is None else hash_inputs(sorted(tracked))
        parts = [hash_tree(ctx.source_root), deps_options,
                 "osv" if shutil.which("osv-scanner") else "no-osv",
                 "off" if env_flag("UNVARNISH_DISABLE_OSV") else "on", index]
        # A grammar missing last time and on disk now makes the inventory stale, so a rerun
        # after `unvarnish grammars fetch` measures with it. Nothing missing adds nothing, so
        # the hash of a complete inventory is what it always was (UNVAR-45).
        recovered = [g for g in gaps if treesitter.grammar_cached(g)]
        if recovered:
            parts.append("grammars-now:" + ",".join(recovered))
        # A refreshed end-of-life bundle makes the inventory, and so the scan, stale. Without a
        # bundle nothing is added, so an engagement's hash stays what it was (UNVAR-43).
        if eol_date:
            parts.append("eol:" + eol_date)
        # Likewise the exploit data bundle, which marks the advisories (UNVAR-90).
        if vuln_date:
            parts.append("vulndata:" + vuln_date)
        # Online, the lookup also reads licences (UNVAR-93), so an online inventory from
        # before them reruns once; offline adds nothing and its hash is what it was.
        if ctx.config.scanners.get("dependencies", {}).get("offline", True) is False:
            parts.append("licences")
        return hash_inputs(parts)

    def outputs(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.census, ctx.paths.metrics, ctx.paths.dependencies]

    def run(self, ctx: ToolContext) -> PhaseResult:
        root = ctx.source_root
        missing = missing_source(ctx)
        if missing is not None:  # fail, so no later phase rewrites anything from an empty tree
            return PhaseResult(phase=self.name, status=PhaseStatus.failed, message=missing)
        excluder = Excluder(root, tracked_files(ctx))
        tracked_ignored: list[str] = []
        records: list[FileRecord] = []
        metrics = []
        totals = CensusTotals()
        languages: dict[str, int] = {}
        measured: dict[str, int] = {}  # files measured, by the grammar they need
        failures: list[str] = []
        digest = hashlib.sha256()  # the tree's content, which a touch leaves alone (UNVAR-34)

        files, totals.symlinks_skipped = walk_files(root)
        for path, rel_str in files:
            try:
                rec, binary = file_record(path, rel_str, excluder)
                digest.update(f"{rel_str}\0{digest_file(path)}\0".encode())
            except OSError as exc:
                failures.append(f"{rel_str}: {exc}")
                continue
            size, lines, language, classification = (rec.bytes, rec.lines, rec.language,
                                                     rec.classification)
            # only files analysed because of the index: a tracked build/bundle.js is still
            # excluded as build output, and the findings document says these were analysed
            if not rec.excluded and excluder.tracked_despite_gitignore(PurePosixPath(rel_str)):
                tracked_ignored.append(rec.path)
            records.append(rec)
            totals.files += 1
            totals.bytes += size
            totals.lines += lines
            totals.by_classification[classification] = (
                totals.by_classification.get(classification, 0) + 1
            )
            if rec.excluded:
                totals.excluded_files += 1
                totals.excluded_bytes += size
                continue
            if classification == Classification.source and language:
                languages[language] = languages.get(language, 0) + lines
            if classification in METRICS_CLASSES and not binary:
                if language:
                    grammar = "javascript" if language == "html" else language
                    measured[grammar] = measured.get(grammar, 0) + 1
                try:
                    metrics.append(compute_metrics(path, rec.path, language))
                except Exception as exc:  # one bad file never kills a run
                    failures.append(f"{rec.path}: metrics failed: {exc!r}")

        deps, frameworks, manifest_failures = parse_manifests(root, records)
        failures.extend(manifest_failures)
        gaps = sorted(g for g in measured if treesitter.grammar_unavailable(g))
        census = Census(tool=ctx.tool, files=records, totals=totals, languages=languages,
                        frameworks=frameworks, failures=failures,
                        tracked_despite_gitignore=tracked_ignored, grammars_unavailable=gaps,
                        notes=[grammar_note(g, measured[g]) for g in gaps],
                        content_digest=digest.hexdigest())
        eol_date = eol.bundle_date()
        h = self._hash(ctx, gaps, eol_date, vulndata.bundle_date())
        write_artifact(ctx.paths.census, census, produced_by=self.name, inputs_hash=h)
        write_artifact(ctx.paths.metrics, Metrics(tool=ctx.tool, files=metrics),
                       produced_by=self.name, inputs_hash=h)
        options = dict(ctx.config.scanners.get("dependencies", {}))
        checked, advisories, note, packages = lookup_dependencies(root, options)
        advisories, exploit_date, exploit_note = vulndata.annotate(advisories)
        if packages is not None:
            deps = attach_licences(deps, packages)
        # Offline needs no note: the option says why, and the artifact stays as it was.
        offline = options.get("offline", True) is not False
        licences_note = None if packages is not None or offline else note or "not looked up"
        write_artifact(ctx.paths.dependencies,
                       Dependencies(tool=ctx.tool, dependencies=deps, advisories_checked=checked,
                                    advisories=advisories, advisories_note=note,
                                    eol_data_date=eol_date,
                                    exploit_data_date=exploit_date,
                                    exploit_data_note=exploit_note,
                                    licences_checked=packages is not None,
                                    licences_note=licences_note,
                                    packages=packages or []),
                       produced_by=self.name, inputs_hash=h)
        message = f"{plural(totals.files, 'file')}, {len(metrics)} measured"
        if gaps:
            message += f"; no tree-sitter grammar for {', '.join(gaps)}"
        return PhaseResult(phase=self.name, status=PhaseStatus.ok, failures=failures,
                           message=message)


def grammar_note(language: str, files: int) -> str:
    """The findings document's line for a grammar that could not be loaded (UNVAR-45)."""
    reason = treesitter.grammar_unavailable(language)
    return (f"No tree-sitter grammar for {language} ({reason}): "
            f"{plural(files, 'file')} measured by line counts only, without function lengths, "
            f"nesting, or structural units; {treesitter.FETCH_HINT}.")


def _previous_gaps(ctx: ToolContext) -> list[str]:
    """The grammars the last inventory ran without, read from its census; [] if none."""
    try:
        raw = json.loads(ctx.paths.census.read_text(encoding="utf-8"))
        return list(raw["data"].get("grammars_unavailable") or [])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return []
