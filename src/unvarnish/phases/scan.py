from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from unvarnish.artifacts import hash_files, hash_inputs, read_artifact, write_artifact
from unvarnish.phases.base import PhaseResult, PhaseStatus, ToolContext
from unvarnish.scanners import load_scanners
from unvarnish.scanners.ai_usage import NAME as AI_USAGE
from unvarnish.scanners.base import ScanContext, Scanner
from unvarnish.scanners.effort import EFFORT_RULES
from unvarnish.scanners.sensitive_data import NAME as SENSITIVE_DATA
from unvarnish.schemas.finding import SEVERITY_ORDER, Finding
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings, SkippedScanner
from unvarnish.util.plural import plural

# Bump when scanner summaries, notes or detection rules change, so a scan written by an
# earlier version reruns once (deterministic, no model calls) instead of rendering the old
# text or findings (UNVAR-57, UNVAR-67, UNVAR-81, UNVAR-82, UNVAR-90, UNVAR-91, UNVAR-92,
# UNVAR-93, UNVAR-100).
SCANNER_TEXT_VERSION = "2026-11-26.2"

# Scanners that build an inventory artifact, which the scan phase writes beside the findings
# (UNVAR-91, UNVAR-100): scanner name -> ToolPaths attribute.
INVENTORIES = {AI_USAGE: "ai_usage", SENSITIVE_DATA: "sensitive_data"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.evidence[0].path,
                       f.evidence[0].line_start or 0, f.title),
    )


class ScanPhase:
    name = "scan"
    reads_source = True  # fails when the source is gone (UNVAR-31)
    depends_on = ("inventory", "git")  # census, metrics, dependencies, git

    def __init__(self, scanners: Sequence[Scanner] | None = None) -> None:
        self._scanners = list(scanners) if scanners is not None else None

    def scanners(self) -> list[Scanner]:
        return self._scanners if self._scanners is not None else load_scanners()

    def _artifacts(self, ctx: ToolContext) -> list[Path]:
        return [ctx.paths.census, ctx.paths.metrics, ctx.paths.git, ctx.paths.dependencies]

    def inputs_hash(self, ctx: ToolContext) -> str:
        names = [s.name for s in self.scanners()]
        options = json.dumps({n: ctx.config.scanners.get(n, {}) for n in names}, sort_keys=True)
        # The band table (UNVAR-42): a scan from before the bands, or of other bands, reruns.
        bands = json.dumps(EFFORT_RULES, sort_keys=True)
        # What a scanner reads outside the source, such as sast's rule files (UNVAR-89).
        extra = [digest(dict(ctx.config.scanners.get(s.name, {})), ctx.engagement.root)
                 for s in self.scanners()
                 if (digest := getattr(s, "inputs_digest", None)) is not None]
        return hash_inputs([hash_files(self._artifacts(ctx)), ",".join(names), options, bands,
                            SCANNER_TEXT_VERSION, *[e for e in extra if e]])

    def outputs(self, ctx: ToolContext) -> list[Path]:
        # An inventory is written only when its scanner is registered (UNVAR-91, UNVAR-100).
        names = {s.name for s in self.scanners()}
        return [ctx.paths.scanner_findings,
                *[getattr(ctx.paths, attr) for name, attr in INVENTORIES.items()
                  if name in names]]

    def run(self, ctx: ToolContext) -> PhaseResult:
        census = read_artifact(ctx.paths.census, Census).data
        metrics = read_artifact(ctx.paths.metrics, Metrics).data
        git = read_artifact(ctx.paths.git, GitStats).data
        deps = read_artifact(ctx.paths.dependencies, Dependencies).data

        findings: list[Finding] = []
        skipped: list[SkippedScanner] = []
        notes: list[str] = []
        run_names: list[str] = []
        inventories: dict[str, object] = {}
        for scanner in self.scanners():
            run_names.append(scanner.name)
            sctx = ScanContext(
                tool=ctx.tool, source_root=ctx.source_root, census=census, metrics=metrics,
                git=git, dependencies=deps,
                options=dict(ctx.config.scanners.get(scanner.name, {})),
                engagement_root=ctx.engagement.root,
            )
            try:
                findings.extend(scanner.run(sctx))
                if scanner.name in INVENTORIES and sctx.inventory is not None:
                    inventories[scanner.name] = sctx.inventory
            except Exception as exc:  # a broken scanner is recorded, never fatal
                skipped.append(SkippedScanner(name=scanner.name, error=repr(exc)))
            notes.extend(getattr(scanner, "notes", None) or [])

        # Each inventory (the AI services, UNVAR-91; sensitive data, UNVAR-100) is absent when
        # its scanner did not run or failed, which the documents show as "not checked", never
        # as an empty inventory.
        for name, attr in INVENTORIES.items():
            path = getattr(ctx.paths, attr)
            if name in inventories:
                write_artifact(path, inventories[name], produced_by=self.name,
                               inputs_hash=self.inputs_hash(ctx))
            else:
                path.unlink(missing_ok=True)
        out = ScannerFindings(tool=ctx.tool, findings=sort_findings(findings), skipped=skipped,
                              scanners_run=run_names, notes=notes)
        write_artifact(ctx.paths.scanner_findings, out, produced_by=self.name,
                       inputs_hash=self.inputs_hash(ctx))
        return PhaseResult(
            phase=self.name, status=PhaseStatus.ok,
            message=(f"{plural(len(findings), 'finding')} from "
                     f"{plural(len(run_names) - len(skipped), 'scanner')}"),
            failures=[f"{s.name}: {s.error}" for s in skipped],
        )
