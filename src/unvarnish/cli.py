from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from unvarnish.analysis.delta import BaselineError, load_baseline
from unvarnish.artifacts import read_artifact, write_artifact
from unvarnish.ask.index import load_or_build_index
from unvarnish.ask.loop import run_question, session_name, write_session
from unvarnish.ask.tools import AskTools
from unvarnish.config import (
    ConfigError,
    EngagementConfig,
    Prices,
    UnsupportedSchemaVersion,
    has_key,
    read_yaml,
    redact_secrets,
    scanner_option_problems,
    unknown_keys,
    user_config_path,
)
from unvarnish.engagement import Engagement, EngagementError, NotAnEngagement
from unvarnish.export.exporter import DATA_FORMATS, DOC_NAMES, FORMATS, export_engagement
from unvarnish.export.tools import ToolsMissing
from unvarnish.lock import EngagementLock, EngagementLocked
from unvarnish.model.base import (
    Backend,
    BackendConfigError,
    BackendError,
    BackendUnavailable,
    CompletionRequest,
    Message,
)
from unvarnish.model.budget import BudgetTracker, load_ledger, record_cost
from unvarnish.model.cache import CachingBackend, clear_cache
from unvarnish.model.estimate import estimate_plan
from unvarnish.model.limit import allow_new_calls, stop_new_calls
from unvarnish.model.probe import PROBE_CAP_TOKENS, probe_context
from unvarnish.model.registry import NoModelConfigured, resolve_backend, resolve_model_ref
from unvarnish.model.structured import complete_structured
from unvarnish.phases import default_phases
from unvarnish.phases.base import (
    PhaseRunner,
    PhaseStatus,
    build_context,
    is_fresh,
    load_run_record,
    missing_source,
    record_run,
)
from unvarnish.phases.compare import (
    ENGAGEMENT_TOOL,
    EngagementContext,
    comparison_phases,
    run_comparison,
)
from unvarnish.phases.ingest import IngestError, ingest_tool, load_tool_meta
from unvarnish.scanners import load_scanners
from unvarnish.schemas.analysis import ExtractState, UnitExtraction
from unvarnish.schemas.cost import CostEntry, Usage, priced
from unvarnish.schemas.delta import DELTA_SCHEMA_VERSION, BaselineSnapshot
from unvarnish.schemas.rollup import ModulesIndex
from unvarnish.schemas.verify import ModelFindings
from unvarnish.util.env import env_flag
from unvarnish.util.logging import setup_run_logging
from unvarnish.util.plural import plural, pluralize

app = typer.Typer(
    name="unvarnish",
    help="Unattended vetting of vibe-coded internal tools.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        from unvarnish import __version__

        console.print(f"unvarnish {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit.", callback=_version_callback, is_eager=True
    ),
) -> None:
    """Unvarnish: the unvarnished truth about internally built software."""


@app.command()
def init(
    directory: Path = typer.Argument(..., help="Directory to create the engagement in."),
    client: str | None = typer.Option(None, "--client", help="Client name."),
    consultant: str | None = typer.Option(None, "--consultant", help="Your firm's name."),
) -> None:
    """Create a new engagement workspace."""
    try:
        eng = Engagement.create(directory, client=client, consultant=consultant)
    except EngagementError as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    console.print(f"Created engagement at [bold]{escape(str(eng.root))}[/bold]")
    console.print("Next: [cyan]unvarnish add <name> --repo <url|path>[/cyan] from inside it.")


ENGAGEMENT_MOUNT = "/engagement"


def _warn_unmounted() -> None:
    """In the Docker image, an engagement folder that is not mounted vanishes with the
    container."""
    if env_flag("UNVARNISH_IN_DOCKER") and not os.path.ismount(ENGAGEMENT_MOUNT):
        err_console.print(f"[yellow]warning:[/yellow] {ENGAGEMENT_MOUNT} is not mounted, so "
                          "everything written will be lost when the container exits; add "
                          f"-v <your engagement folder>:{ENGAGEMENT_MOUNT}", soft_wrap=True)


def _print_errors(problems: list[str]) -> None:
    """One `error:` line per problem; redacted, and escaped so a value like [t1 is shown, not
    eaten as markup."""
    for line in problems:
        err_console.print(f"[red]error:[/red] {escape(redact_secrets(line))}", soft_wrap=True,
                          highlight=False)


def _load_engagement(engagement: Path | None) -> Engagement:
    _warn_unmounted()
    try:
        return Engagement.find(engagement or Path.cwd())
    except ConfigError as exc:  # invalid YAML or values (UNVAR-50)
        _print_errors(exc.problems)
        raise typer.Exit(code=2) from exc
    except (NotAnEngagement, UnsupportedSchemaVersion) as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc


@contextmanager
def _engagement_lock(eng: Engagement, command: str) -> Iterator[None]:
    """Hold the engagement lock for a command that spends tokens or writes artifacts; a second
    such command on the same engagement exits 2 naming the holder. Read-only commands (status,
    cost, export, run --dry-run) never take it."""
    lock = EngagementLock(eng.lock_file, command=command,
                          stale_after=timedelta(minutes=eng.config.pipeline.lock_stale_minutes))
    try:
        stale = lock.acquire()
    except EngagementLocked as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True,
                          highlight=False)
        raise typer.Exit(code=2) from exc
    except OSError as exc:  # e.g. the file belongs to another user (a root container run)
        err_console.print(f"[red]error:[/red] cannot lock the engagement: "
                          f"{escape(str(exc))}", soft_wrap=True, highlight=False)
        raise typer.Exit(code=2) from exc
    if stale is not None:
        err_console.print(f"[yellow]warning:[/yellow] {escape(stale.describe())}",
                          soft_wrap=True, highlight=False)
    try:
        yield
    finally:  # normal exit, typer.Exit, an error, or Ctrl-C
        lock.release()


EngagementOption = typer.Option(
    None, "--engagement", "-e", help="Engagement directory (default: search upward from cwd)."
)


@app.command()
def add(
    name: str = typer.Argument(..., help="Tool name: lowercase, digits, - and _."),
    repo: str | None = typer.Option(None, "--repo", help="Git URL or local repo path."),
    files: Path | None = typer.Option(None, "--files", help="Directory of loose files."),
    branch: str | None = typer.Option(None, "--branch", help="Branch to check out."),
    link: bool = typer.Option(False, "--link", help="Record the path instead of copying."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Register a tool and ingest its source."""
    if (repo is None) == (files is None):
        err_console.print("[red]error:[/red] pass exactly one of --repo or --files")
        raise typer.Exit(code=2)
    eng = _load_engagement(engagement)
    origin = repo if repo is not None else str(files)
    kind = "link" if link else ("repo" if repo is not None else "files")
    try:
        meta = ingest_tool(eng, name, origin, kind, branch=branch)
    except (IngestError, ValueError) as exc:  # one line, so a path in it stays copyable
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True,
                          highlight=False)
        raise typer.Exit(code=2) from exc
    where = meta.source_path if kind == "link" else f"tools/{name}/source"
    console.print(f"Added [bold]{escape(name)}[/bold] ({kind}) at {escape(str(where))}")
    if meta.commit:
        console.print(f"  commit {meta.commit[:12]} on {meta.branch}")


def _select_tools(eng: Engagement, tools: list[str] | None) -> list[str]:
    known = eng.tool_names()
    if not known:
        err_console.print(
            "[red]error:[/red] no tools in this engagement; use [cyan]unvarnish add[/cyan] first"
        )
        raise typer.Exit(code=2)
    if not tools:
        return known
    unknown = [t for t in tools if t not in known]
    if unknown:
        err_console.print(
            f"[red]error:[/red] unknown {pluralize(len(unknown), 'tool')}: "
            f"{escape(', '.join(unknown))}; "
            f"known: {escape(', '.join(known))}"
        )
        raise typer.Exit(code=2)
    return list(tools)


MISSING_TOOL_YAML = "tool.yaml not found; remove it from engagement.yaml or add it again"


def _missing_tool_yaml(eng: Engagement, names: list[str]) -> list[str]:
    """The tools registered in engagement.yaml whose tools/<name>/tool.yaml is gone."""
    return [n for n in names if not eng.tool_paths(n).meta_file.exists()]


def _refuse_invalid_tools(eng: Engagement, names: list[str]) -> None:
    """A tool.yaml that is there but cannot be read stops the command before any work: one
    error line per problem, exit 2 (UNVAR-50). A missing one is _report_missing_tools's."""
    problems: list[str] = []
    for name in names:
        paths = eng.tool_paths(name)
        if paths.meta_file.exists():
            try:
                load_tool_meta(paths)
            except ConfigError as exc:
                problems += exc.problems
    if problems:
        _print_errors(problems)
        raise typer.Exit(code=2)


def _report_missing_tools(eng: Engagement, names: list[str]) -> list[str]:
    """Print one error line per named tool whose tool.yaml is gone; return those tools. A
    tool.yaml that is there but invalid stops the command first (exit 2)."""
    _refuse_invalid_tools(eng, names)
    missing = _missing_tool_yaml(eng, names)
    for name in missing:
        err_console.print(f"[red]error:[/red] {escape(name)}: {MISSING_TOOL_YAML}", soft_wrap=True)
    return missing


def _refuse_missing_tools(eng: Engagement, names: list[str]) -> None:
    """Commands that need every named tool intact: one line per missing tool, exit 2."""
    if _report_missing_tools(eng, names):
        raise typer.Exit(code=2)


def _prefixed(values, incomplete: str) -> list[str]:
    return [v for v in values if v.startswith(incomplete.lower())]


def _phase_names() -> list[str]:
    return [p.name for p in default_phases()]


def complete_phase(incomplete: str) -> list[str]:
    """Shell completion for `run --phase`: the pipeline's phase names."""
    return _prefixed(_phase_names(), incomplete)


def complete_format(incomplete: str) -> list[str]:
    """Shell completion for `export --format`."""
    return _prefixed((*FORMATS, *DATA_FORMATS, "all"), incomplete)


def complete_doc(incomplete: str) -> list[str]:
    """Shell completion for `export --doc`."""
    return _prefixed(DOC_NAMES, incomplete)


def _lower(value: str | list[str] | None) -> str | list[str] | None:
    """Option callback: phase, format and document names are lower case."""
    if value is None or isinstance(value, str):
        return value and value.lower()
    return [v.lower() for v in value]


@app.command()
def run(
    tools: list[str] | None = typer.Argument(None, help="Tools to run (default: all)."),
    phase: str | None = typer.Option(
        None, "--phase", autocompletion=complete_phase, callback=_lower,
        help=f"Run only this phase: {', '.join(_phase_names())}."),
    force: bool = typer.Option(False, "--force", help="Rerun phases even if fresh."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would run; change nothing."),
    baseline: Path | None = typer.Option(
        None, "--baseline",
        help="A previous review to compare with: its engagement folder, a tool folder, or a "
             "findings artifact. findings.md gains a 'Since the previous review' section."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detail on the console."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Run outstanding phases for one or more tools."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, tools)
    missing = _report_missing_tools(eng, names)
    names = [n for n in names if n not in missing]
    if not names:
        raise typer.Exit(code=2)
    snapshots = _resolve_baseline(baseline, names) if baseline is not None else None
    runner = PhaseRunner(default_phases())
    if dry_run:  # read-only, so it needs no engagement lock
        table = Table("tool", "phase", "status", "detail", title="dry run")
        tracker = BudgetTracker(eng.config.budget.max_tokens)
        for name in names:
            ctx = build_context(eng, name, budget=tracker)
            try:
                planned = runner.plan(ctx, force=force, only=phase)
            except ValueError as exc:  # unknown phase
                err_console.print(f"[red]error:[/red] {escape(str(exc))}")
                raise typer.Exit(code=2) from exc
            for p in planned:
                table.add_row(name, p.name, "would run", "")
            for p_name, est in estimate_plan(ctx, [p.name for p in planned]).items():
                if est is None:
                    table.add_row(name, p_name, "estimate",
                                  "run split first for a token estimate")
                    continue
                usage, note = est
                table.add_row(name, p_name, "estimate",
                              f"≈ {usage.total():,} tokens"
                              f"{_usd(usage, _phase_price(eng, p_name))} · {note}")
        if table.row_count:
            console.print(table)
        else:  # `phase` passed runner.plan's check, so it is a known name, safe as markup
            scope = " for the other tools" if missing else ""
            fresh = f"the {phase} phase is" if phase else "every phase is"
            console.print(f"Nothing to run{scope}: {fresh} fresh.")
        if missing:
            _report_missing_summary(missing, ran=False)
            raise typer.Exit(code=2)
        return
    with _engagement_lock(eng, "run"):
        if snapshots is not None:
            _write_baselines(eng, snapshots)
        _run_tools(eng, names, runner, phase=phase, force=force, verbose=verbose,
                   missing=missing)


def _resolve_baseline(path: Path, names: list[str]) -> dict[str, BaselineSnapshot | None]:
    """Each tool's previous review at `path`, read before anything runs; a baseline that
    cannot be used stops the run (exit 2) before any work."""
    try:
        snapshots = {name: load_baseline(path, name) for name in names}
    except BaselineError as exc:
        err_console.print(f"[red]error:[/red] baseline: {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    if not any(snapshots.values()):
        err_console.print(f"[red]error:[/red] baseline {escape(str(path))} has no findings for "
                          f"{escape(', '.join(names))}", soft_wrap=True)
        raise typer.Exit(code=2)
    for name, snap in snapshots.items():
        if snap is None:
            err_console.print(f"[yellow]warning:[/yellow] {escape(name)}: not in the baseline; no "
                              "comparison for it", soft_wrap=True)
    return snapshots


def _write_baselines(eng: Engagement, snapshots: dict[str, BaselineSnapshot | None]) -> None:
    """Snapshot the previous review into each tool's analysis/baseline.json before the phases
    run: later runs keep comparing with it, and a baseline taken from this engagement's own
    folder holds the results as they were. A new --baseline replaces the previous one, except
    one taken from the tool's own folder (UNVAR-48): a rerun would snapshot the results the
    first run just wrote, so the stored snapshot stays until its file is deleted."""
    for name, snap in snapshots.items():
        paths = eng.tool_paths(name)
        path = paths.baseline
        if snap is None:
            path.unlink(missing_ok=True)
        elif _is_own_folder(snap, paths.root) and _usable_snapshot(path):
            console.print(f"{name}: keeping the stored baseline; --baseline points into this "
                          f"tool's own folder. To take a new one, delete {escape(str(path))} "
                          "and rerun.", soft_wrap=True)
        elif not _same_snapshot(path, snap):
            write_artifact(path, snap, produced_by="baseline", inputs_hash="",
                           schema_version=DELTA_SCHEMA_VERSION)


def _is_own_folder(snap: BaselineSnapshot, tool_root: Path) -> bool:
    """`--baseline` resolved to this tool's own folder, or to an artifact inside it."""
    return Path(snap.info.source).is_relative_to(tool_root.resolve())


def _usable_snapshot(path: Path) -> bool:
    """The stored snapshot is one render can compare with. A missing, broken or old-schema
    file is replaced even from the own folder: render's failure says to rerun with
    --baseline, and keeping it would leave that advice with no effect."""
    try:
        return read_artifact(path, BaselineSnapshot).data.schema_version == DELTA_SCHEMA_VERSION
    except Exception:
        return False


def _same_snapshot(path: Path, snap: BaselineSnapshot) -> bool:
    """The snapshot on disk already holds `snap`: rewriting it would only change its timestamp,
    which the render phase hashes, so passing the same --baseline again would re-render."""
    try:
        return read_artifact(path, BaselineSnapshot).data == snap
    except Exception:  # missing or unreadable: write it
        return False


def _run_tools(eng: Engagement, names: list[str], runner: PhaseRunner, *, phase: str | None,
               force: bool, verbose: bool, missing: list[str]) -> None:
    """The real run, under the engagement lock. `missing` are the tools refused before the
    lock (no tool.yaml): reported after the others ran, exit 2."""
    log_path = setup_run_logging(eng, verbose)
    table = Table("tool", "phase", "status", "detail", title="run")
    any_failed = False
    any_stopped = False
    tracker = BudgetTracker(eng.config.budget.max_tokens)

    def run_tool(name: str) -> list:
        ctx = build_context(eng, name, budget=tracker)
        results = runner.run(ctx, force=force, only=phase)
        record_run(ctx, results)
        return results

    # Tools run in parallel; pipeline.concurrency still caps in-flight model calls across them.
    outcomes: dict[str, list | BaseException] = {}
    workers = max(1, min(eng.config.pipeline.parallel_tools, len(names)))
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tool")
    try:
        futures = {name: pool.submit(run_tool, name) for name in names}
        pending = set(futures.values())
        while pending:  # a timed wait, so Ctrl-C reaches this thread while tools run
            _, pending = wait(pending, timeout=0.1)
    except KeyboardInterrupt:
        # Ctrl-C reaches only this thread. Tell every phase to stop: calls in flight finish
        # and are recorded, nothing new starts, and stopped phases stay stale to resume.
        tracker.interrupt()
        stop_new_calls()
        err_console.print("Interrupted; waiting for model calls in flight to finish…")
        pool.shutdown(wait=True, cancel_futures=True)
        err_console.print("interrupted; rerun [cyan]unvarnish run[/cyan] to resume.")
        raise typer.Exit(code=130) from None
    finally:
        pool.shutdown(wait=True)
        allow_new_calls()  # the process may run again (tests, a notebook)
    for name, fut in futures.items():
        try:
            outcomes[name] = fut.result()
        except Exception as exc:  # reported below, in tool order
            outcomes[name] = exc
    for name in names:
        outcome = outcomes[name]
        if isinstance(outcome, ValueError):  # unknown phase
            err_console.print(f"[red]error:[/red] {escape(str(outcome))}")
            raise typer.Exit(code=2) from outcome
        if isinstance(outcome, (BackendConfigError, BackendUnavailable)):
            err_console.print(f"[red]error:[/red] {escape(name)}: {escape(str(outcome))}",
                              soft_wrap=True)
            raise typer.Exit(code=2) from outcome
        if isinstance(outcome, BaseException):
            raise outcome
        for r in outcome:
            colour = {"ok": "green", "skipped": "dim", "failed": "red", "stopped": "yellow"}[
                r.status
            ]
            detail = escape(r.message or "")
            if r.failures:
                detail += f" [yellow]({plural(len(r.failures), 'recorded failure')})[/yellow]"
                any_failed = True
            if r.status == PhaseStatus.failed:
                any_failed = True
            if r.status == PhaseStatus.stopped:
                any_stopped = True
            table.add_row(name, r.phase, f"[{colour}]{r.status}[/{colour}]", detail)
    console.print(table)
    console.print(f"Log: {escape(str(log_path))}")
    if any_stopped:
        err_console.print("Budget cap reached; rerun [cyan]unvarnish run[/cyan] to resume.")
        if missing:
            _report_missing_summary(missing, ran=True)
        raise typer.Exit(code=3)
    if missing:
        _report_missing_summary(missing, ran=True)
        if any_failed:
            err_console.print("Run also completed with recorded failures; see "
                              "[cyan]unvarnish status[/cyan].")
        raise typer.Exit(code=2)
    if any_failed:
        err_console.print(
            "Run completed with recorded failures; see [cyan]unvarnish status[/cyan]."
        )
        raise typer.Exit(code=1)


def _report_missing_summary(missing: list[str], *, ran: bool) -> None:
    err_console.print(
        f"{plural(len(missing), 'tool')} could not run: {escape(', '.join(missing))} "
        f"({MISSING_TOOL_YAML}); "
        + ("the others ran. " if ran else "") + "exit code 2.", soft_wrap=True)


@app.command()
def compare(
    force: bool = typer.Option(False, "--force", help="Rerun even if fresh."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detail on the console."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Compare every analysed tool: capability matrix, integration map, risk table, proposal."""
    eng = _load_engagement(engagement)
    _select_tools(eng, None)  # exits 2 when the engagement has no tools
    with _engagement_lock(eng, "compare"):
        _compare(eng, force=force, verbose=verbose)


def _compare(eng: Engagement, *, force: bool, verbose: bool) -> None:
    log_path = setup_run_logging(eng, verbose)
    try:
        results = run_comparison(eng, force=force,
                                 budget=BudgetTracker(eng.config.budget.max_tokens))
    except (BackendConfigError, BackendUnavailable) as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    table = Table("phase", "status", "detail", title="compare")
    any_failed = any_stopped = False
    for r in results:
        colour = {"ok": "green", "skipped": "dim", "failed": "red", "stopped": "yellow"}[r.status]
        detail = escape(r.message or "")
        if r.failures:
            detail += f" [yellow]({plural(len(r.failures), 'recorded failure')})[/yellow]"
            any_failed = True
        any_failed = any_failed or r.status == PhaseStatus.failed
        any_stopped = any_stopped or r.status == PhaseStatus.stopped
        table.add_row(r.phase, f"[{colour}]{r.status}[/{colour}]", detail)
    console.print(table)
    console.print(f"Log: {escape(str(log_path))}")
    if results and results[0].not_ready:
        err_console.print(f"[red]error:[/red] {escape(str(results[0].message))}")
        raise typer.Exit(code=2)
    if any_stopped:
        err_console.print("Budget cap reached; rerun [cyan]unvarnish compare[/cyan] to resume.")
        raise typer.Exit(code=3)
    if any_failed:
        err_console.print("Compare completed with recorded failures; see comparison/failures.json.")
        raise typer.Exit(code=1)


@app.command()
def export(
    tools: list[str] | None = typer.Argument(None, help="Tools to export (default: all)."),
    fmt: list[str] = typer.Option(
        ["all"], "--format", autocompletion=complete_format, callback=_lower,
        help=f"{', '.join((*FORMATS, *DATA_FORMATS))}, or all ({', '.join(FORMATS)}); "
             "repeat for several."),
    template: Path | None = typer.Option(None, "--template",
                                         help="A .docx reference (docx) or .css (html/pdf)."),
    doc: list[str] | None = typer.Option(
        None, "--doc", autocompletion=complete_doc, callback=_lower,
        help=f"{', '.join(DOC_NAMES)} (default: all)."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Convert the rendered documents to DOCX, HTML, or PDF, and findings to SARIF or CSV,
    under exports/."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, tools)
    _refuse_missing_tools(eng, names)
    formats = list(dict.fromkeys(fmt))
    if "all" in formats:  # the three documents; sarif and csv are only asked for by name
        formats = [*FORMATS, *(f for f in formats if f not in (*FORMATS, "all"))]
    known = (*FORMATS, *DATA_FORMATS)
    if any(f not in known for f in formats):
        bad = ", ".join(f for f in formats if f not in known)
        err_console.print(f"[red]error:[/red] unknown format {escape(repr(bad))}; "
                          "use docx, html, pdf, sarif, csv, or all")
        raise typer.Exit(code=2)
    unknown = [d for d in (doc or []) if d not in DOC_NAMES]
    if unknown:
        err_console.print(f"[red]error:[/red] unknown {pluralize(len(unknown), 'document')}: "
                          f"{escape(', '.join(unknown))}; known: {', '.join(DOC_NAMES)}")
        raise typer.Exit(code=2)
    if doc and "findings" not in doc and any(f in DATA_FORMATS for f in formats):
        # sarif and csv are written only from the findings document; refuse the whole request
        # (a mixed one too) before any conversion starts
        err_console.print("[red]error:[/red] sarif and csv come from the findings document; "
                          "add `--doc findings` or drop `--doc`", soft_wrap=True)
        raise typer.Exit(code=2)
    try:
        report = export_engagement(eng, formats=formats, docs=doc or None,
                                   tools=names if tools else None,
                                   template=template)
    except (ToolsMissing, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    table = Table("document", "tool", "format", "status", "detail", title="export")
    for col in table.columns:
        col.overflow = "fold"  # paths wrap instead of being cut with an ellipsis
    for i in report.items:
        colour = {"ok": "green", "skipped": "dim", "failed": "red"}[i.status]
        table.add_row(escape(i.doc), escape(i.tool), escape(i.fmt),
                      f"[{colour}]{i.status}[/{colour}]",
                      escape((i.path or i.detail) if i.status == "ok" else i.detail))
    console.print(table)
    for warning in report.warnings:
        err_console.print(f"[yellow]warning:[/yellow] {warning}", soft_wrap=True)
    for i in report.ok:
        if i.detail:  # diagram problems: the file exists but is missing something
            err_console.print(f"[yellow]warning:[/yellow] {escape(i.doc)}/{escape(i.tool)}/"
                              f"{escape(i.fmt)}: {escape(i.detail)}", soft_wrap=True)
    if not report.ok:
        if report.failed:
            n = len(report.failed)
            what = "The only conversion" if n == 1 else f"All {plural(n, 'conversion')}"
            err_console.print(f"{what} failed; see the table above and the log.")
        else:
            err_console.print("Nothing to export: run `unvarnish run` (and `compare`) first.")
        raise typer.Exit(code=1)
    console.print(f"{plural(len(report.ok), 'file')} written under exports/")
    if report.failed:
        err_console.print(f"{plural(len(report.failed), 'conversion')} failed; "
                          "see the table above.")
        raise typer.Exit(code=1)


@app.command()
def ask(
    question: str | None = typer.Argument(None, help="One question; omit for a session."),
    tool: str | None = typer.Option(None, "--tool", help="Restrict to one tool."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detail on the console."),
    engagement: Path | None = EngagementOption,
) -> None:
    """Ask questions about the analysed tools; answers cite artifact ids and file paths."""
    eng = _load_engagement(engagement)
    names = _select_tools(eng, None)
    if tool is not None and tool not in names:
        err_console.print(f"[red]error:[/red] unknown tool {escape(repr(tool))}; "
                          f"known: {escape(', '.join(names))}")
        raise typer.Exit(code=2)
    _refuse_missing_tools(eng, [tool] if tool is not None else names)
    try:
        backend = resolve_backend(eng, "ask")
    except NoModelConfigured as exc:
        err_console.print("[red]error:[/red] ask needs a model: set models.default in "
                          "engagement.yaml")
        raise typer.Exit(code=2) from exc
    except BackendConfigError as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    with _engagement_lock(eng, "ask"):
        _ask(eng, backend, question, tool=tool, verbose=verbose)


def _ask(eng: Engagement, backend, question: str | None, *, tool: str | None,
         verbose: bool) -> None:
    log_path = setup_run_logging(eng, verbose, prefix="ask")
    index, rebuilt = load_or_build_index(eng)
    if rebuilt:
        console.print(f"[dim]Index built: {len(index.docs)} documents.[/dim]")
    tools = AskTools(eng, index)
    ref = resolve_model_ref(eng.config, "ask")
    effort = ref.effort if ref else None
    budget = BudgetTracker(eng.config.budget.max_tokens)
    max_calls = eng.config.ask.max_tool_calls
    started = datetime.now(UTC)
    results = []
    any_unanswered = False
    stopped = False

    def one(q: str) -> None:
        nonlocal any_unanswered, stopped
        res = run_question(eng, backend, tools, index, q, tool_filter=tool, budget=budget,
                           effort=effort, max_calls=max_calls)
        results.append(res)
        write_session(eng, results, started)
        if res.usage.total():
            record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase="ask", backend=backend.name,
                                       model=backend.model, usage=res.usage,
                                       at=datetime.now(UTC)))
        console.print()
        console.print(escape(res.answer), soft_wrap=True)
        if res.verified:
            console.print("[dim]Citations:[/dim] " + escape(", ".join(res.citations)))
        elif res.completed:
            console.print("[yellow]Unverified: the answer cites no artifact ids or paths.[/yellow]")
        else:
            any_unanswered = True
        stopped = stopped or res.stopped_for_budget
        calls = sum(1 for s in res.steps if s.kind == "call")
        console.print(f"[dim]{plural(calls, 'tool call')}, {res.usage.total():,} tokens[/dim]")

    try:
        if question:
            one(question)
        else:
            console.print("Interactive session; type a question, or 'exit' to finish.")
            while True:
                try:
                    q = console.input("[bold]ask>[/bold] ").strip()
                except (EOFError, KeyboardInterrupt):
                    break  # Ctrl-D or Ctrl-C ends the session; it is still saved below
                if not q:
                    continue  # a blank line is not an answer to "exit?"
                if q.lower() in ("exit", "quit"):
                    break
                one(q)
                if stopped:
                    break
    except BackendUnavailable as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    if results:
        console.print(f"[dim]Session saved to ask-sessions/{session_name(started)}"
                      f" · log: {escape(str(log_path))}[/dim]")
    if stopped:
        err_console.print("Budget cap reached.")
        raise typer.Exit(code=3)
    if any_unanswered:
        raise typer.Exit(code=1)


def _phase_price(eng: Engagement, phase: str) -> Prices | None:
    ref = resolve_model_ref(eng.config, phase)
    return priced(eng.config.budget.prices, ref.model) if ref else None


def _usd(usage: Usage, prices: Prices | None) -> str:
    if prices is None:
        return ""
    return f" (≈ USD {usage.usd(prices):,.2f})"


@app.command()
def cost(engagement: Path | None = EngagementOption) -> None:
    """Tokens spent per tool and phase, with an upper-bound cost when prices are configured."""
    eng = _load_engagement(engagement)
    try:
        ledger = load_ledger(eng)
    except Exception as exc:  # a corrupt ledger is reported, never a traceback
        err_console.print(f"[red]cost ledger unreadable:[/red] {escape(str(eng.cost_file))} "
                          f"({type(exc).__name__}); delete it to start a new ledger")
        return
    prices = eng.config.budget.prices
    table = Table(title="cost ledger")
    for col in ("tool", "phase", "backend/model"):
        table.add_column(col, no_wrap=True)
    for col in ("input", "cache read", "cache write", "output"):
        table.add_column(col, justify="right")
    for e in ledger.entries:
        table.add_row(escape(e.tool), escape(e.phase), escape(f"{e.backend}/{e.model}"),
                      f"{e.usage.input_tokens:,}",
                      f"{e.usage.cache_read_tokens:,}", f"{e.usage.cache_write_tokens:,}",
                      f"{e.usage.output_tokens:,}")
    console.print(table)
    total = ledger.total()
    usd = ledger.estimate_usd(prices)
    cost_text = f" (≤ USD {usd:,.2f})" if usd is not None else ""
    console.print(f"Total: {total.total():,} tokens{cost_text}")
    if prices is not None and ledger.unpriced(prices):
        console.print(f"No price configured for: {escape(', '.join(ledger.unpriced(prices)))}")
    if eng.config.budget.max_tokens:
        console.print(f"Budget cap: {eng.config.budget.max_tokens:,} tokens per run")


@app.command()
def status(engagement: Path | None = EngagementOption) -> None:
    """Show phase progress for every tool, one row per phase."""
    eng = _load_engagement(engagement)
    _refuse_invalid_tools(eng, eng.tool_names())
    phases = default_phases()
    table = Table("tool", "phase", "state", title=f"status: {eng.config.client or eng.root.name}")
    for name in eng.tool_names():
        if name in _missing_tool_yaml(eng, [name]):
            table.add_row(name, "-", f"[red]missing[/red]: {MISSING_TOOL_YAML}",
                          end_section=True)
            continue
        ctx = build_context(eng, name)
        for p in phases:
            table.add_row(name, p.name, _safe_cell(p, ctx))
        try:
            record = load_run_record(ctx)
        except Exception:  # a corrupt record is reported, never fatal
            record = None
        if record is None:
            last = "[dim]never[/dim]"
        elif record.failures:
            last = f"[yellow]{plural(len(record.failures), 'failure')}[/yellow]"
        else:
            last = "[green]clean[/green]"
        table.add_row(name, "last run", last, end_section=True)
    ectx = EngagementContext(engagement=eng, budget=BudgetTracker(None))
    for p in comparison_phases():
        table.add_row("(engagement)", p.name, _safe_cell(p, ectx))
    console.print(table)


def _safe_cell(p, ctx) -> str:
    """A phase's status cell; an artifact that cannot be read shows as unreadable."""
    try:
        return _phase_cell(p, ctx)
    except Exception as exc:
        return f"[red]unreadable[/red] ({type(exc).__name__})"


def _phase_cell(p, ctx) -> str:
    if p.name == "inventory" and (missing := missing_source(ctx)) is not None:
        return f"[red]failed[/red]: {escape(missing)}"
    if p.name == "extract" and ctx.paths.extract_state.exists():
        st = read_artifact(ctx.paths.extract_state, ExtractState).data
        cell = f"{st.units_done}/{st.units_total} units"
        if st.stopped_for_budget:
            cell += " budget-stopped"
        if st.units_failed:
            cell += f" ({st.units_failed} failed)"
        colour = "yellow" if (st.stopped_for_budget or st.units_failed) else "green"
        return f"[{colour}]{cell}[/{colour}]"
    if p.name == "rollup_modules" and ctx.paths.modules_index.exists():
        mi = read_artifact(ctx.paths.modules_index, ModulesIndex).data
        cell = f"{len(mi.modules)} modules"
        if mi.failed:
            cell += f" ({len(mi.failed)} failed)"
        if mi.stopped_for_budget:
            cell += " budget-stopped"
        colour = "yellow" if (mi.failed or mi.stopped_for_budget) else "green"
        return f"[{colour}]{cell}[/{colour}]"
    if p.name == "verify" and ctx.paths.model_findings.exists():
        mf = read_artifact(ctx.paths.model_findings, ModelFindings).data
        cell = f"{len(mf.findings)} findings, {mf.verified} verified"
        if mf.unverified:
            cell += f" ({mf.unverified} unverified)"
        if mf.stopped_for_budget:
            cell += " budget-stopped"
        colour = "yellow" if (mf.unverified or mf.stopped_for_budget) else "green"
        return f"[{colour}]{cell}[/{colour}]"
    if p.name == "render" and ctx.paths.render_state.exists():
        n_docs = sum(1 for d in (ctx.paths.findings_doc, ctx.paths.architecture_doc,
                                 ctx.paths.requirements_doc) if d.exists())
        fresh = is_fresh(p, ctx)
        colour = "green" if fresh else "yellow"
        return f"[{colour}]{n_docs} docs{'' if fresh else ' (stale)'}[/{colour}]"
    outputs = p.outputs(ctx)
    if not all(o.exists() for o in outputs):
        return "[red]missing[/red]"
    if is_fresh(p, ctx):
        return "[green]fresh[/green]"
    return "[yellow]stale[/yellow]"


scanners_app = typer.Typer(help="Inspect scanners.", no_args_is_help=True)
app.add_typer(scanners_app, name="scanners")


@scanners_app.command("list")
def scanners_list(engagement: Path | None = EngagementOption) -> None:
    """List registered scanners and their effective options."""
    try:
        cfg = Engagement.find(engagement or Path.cwd()).config
    except NotAnEngagement:
        cfg = EngagementConfig()
    except ConfigError as exc:
        _print_errors(exc.problems)
        raise typer.Exit(code=2) from exc
    except UnsupportedSchemaVersion as exc:
        err_console.print(f"[red]error:[/red] {escape(str(exc))}", soft_wrap=True)
        raise typer.Exit(code=2) from exc
    table = Table("scanner", "category", "options")
    for s in load_scanners():
        opts = cfg.scanners.get(s.name, {})
        rendered = escape(", ".join(f"{k}={v}" for k, v in opts.items())) or "—"
        table.add_row(s.name, str(s.category), rendered)
    console.print(table)


grammars_app = typer.Typer(help="Tree-sitter grammars for code structure.",
                           no_args_is_help=True)
app.add_typer(grammars_app, name="grammars")


@grammars_app.command("fetch")
def grammars_fetch(
    cache_dir: Path | None = typer.Option(
        None, "--dir",
        help="Base directory for the grammars; set TREE_SITTER_LANGUAGE_PACK_CACHE_DIR to it "
             "when running. Default: the pack's cache (that variable, or ~/.cache)."),
    attempts: int = typer.Option(4, "--attempts", min=1, help="Download attempts."),
) -> None:
    """Download the grammars Unvarnish uses, so runs need no network for them."""
    from unvarnish.analysis import treesitter

    try:
        where, missing = treesitter.fetch_grammars(cache_dir, attempts=attempts)
    except treesitter.GrammarFetchError as exc:
        err_console.print(f"[red]error:[/red] grammar download failed, {escape(str(exc))}",
                          soft_wrap=True)
        raise typer.Exit(code=1) from exc
    total = len(treesitter.grammar_languages())
    console.print(f"{total - len(missing)} of {total} grammars in {escape(str(where))}",
                  soft_wrap=True)
    if missing:
        err_console.print(f"[red]error:[/red] still missing: {escape(', '.join(missing))}")
        raise typer.Exit(code=1)


@grammars_app.command("status")
def grammars_status() -> None:
    """Show which grammars are on disk, without downloading anything."""
    import tree_sitter_language_pack as pack

    from unvarnish.analysis import treesitter

    names = treesitter.grammar_languages()
    have = set(pack.downloaded_languages())
    missing = [n for n in names if n not in have]
    console.print(f"{len(names) - len(missing)} of {len(names)} grammars in "
                  f"{escape(str(pack.cache_dir()))}", soft_wrap=True)
    if missing:
        console.print(f"missing: {escape(', '.join(missing))}; run `unvarnish grammars fetch`",
                      soft_wrap=True)
        raise typer.Exit(code=1)


eol_app = typer.Typer(help="End-of-life dates for runtimes and frameworks.",
                      no_args_is_help=True)
app.add_typer(eol_app, name="eol")


@eol_app.command("refresh")
def eol_refresh(
    data_dir: Path | None = typer.Option(
        None, "--dir",
        help="Folder for endoflife.json; set UNVARNISH_EOL_DIR to it when running. Default: "
             "that variable, else $XDG_DATA_HOME/unvarnish/eol or ~/.local/share/unvarnish/eol."),
    attempts: int = typer.Option(4, "--attempts", min=1, help="Download attempts per product."),
) -> None:
    """Download end-of-life dates from endoflife.date, so runs check them offline."""
    from unvarnish.analysis import eol

    def unwritable(exc: OSError) -> typer.Exit:
        where = data_dir or eol.data_dir()
        err_console.print(f"[red]error:[/red] cannot write to {escape(str(where))}: "
                          f"{escape(exc.strerror or str(exc))}; choose a writable folder "
                          "with --dir", soft_wrap=True)
        return typer.Exit(code=1)

    try:
        eol.ensure_writable(data_dir)
    except OSError as exc:
        raise unwritable(exc) from exc
    try:
        bundle = eol.build_bundle(attempts=attempts)
    except eol.EolFetchError as exc:
        err_console.print(f"[red]error:[/red] end-of-life download failed, {escape(str(exc))}; "
                          "the previous bundle, if any, is unchanged", soft_wrap=True)
        raise typer.Exit(code=1) from exc
    try:
        path = eol.write_bundle(bundle, data_dir)
    except OSError as exc:
        raise unwritable(exc) from exc
    console.print(f"{len(bundle.products)} products, data dated {bundle.fetched.isoformat()}, "
                  f"in {escape(str(path))}", soft_wrap=True)


config_app = typer.Typer(help="Configuration commands.", no_args_is_help=True)
app.add_typer(config_app, name="config")
cache_app = typer.Typer(help="Model response cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


def _record_probe(eng: Engagement, backend: Backend, usage: Usage) -> None:
    """Probes spend real tokens: they belong in the ledger like every other call."""
    if usage.total():
        record_cost(eng, CostEntry(tool=ENGAGEMENT_TOOL, phase="config-check",
                                   backend=backend.name, model=backend.model, usage=usage,
                                   at=datetime.now(UTC)))


@config_app.command("check")
def config_check(
    engagement: Path | None = EngagementOption,
    probe: bool = typer.Option(True, "--probe/--no-probe",
                               help="Send a tiny request to each backend."),
    probe_context_flag: bool = typer.Option(
        False, "--probe-context",
        help="Also send a long prompt to check the server really accepts its context window "
             "(costs one large request per model)."),
) -> None:
    """Validate engagement.yaml and probe the configured model backends."""
    eng = _load_engagement(engagement)
    raw = yaml.safe_load(eng.config_file.read_text(encoding="utf-8")) or {}
    for key in unknown_keys(raw):
        err_console.print(f"[yellow]warning:[/yellow] unknown setting "
                          f"{escape(redact_secrets(repr(key)))} is ignored", highlight=False)
    # Scanner options are free-form, so loading accepts a wrong type; the scanner would then
    # fail on every run (UNVAR-50). Blamed like load_config: the user config only when it
    # alone sets the key.
    user_file = user_config_path()
    user_raw = (read_yaml(user_file, str(user_file)) or {}) if user_file.exists() else {}
    option_problems: list[str] = []
    for key, problem in scanner_option_problems(eng.config.scanners):
        only_user = not has_key(raw, key) and has_key(user_raw, key)
        option_problems.append(f"{user_file if only_user else eng.config_file.name}: {problem}")
    # "other phases" resolves to models.default: every phase without an override uses it.
    phases = ["extract", *[p for p in eng.config.models.phases if p != "extract"],
              "other phases"]
    table = Table("phase", "backend", "model", "json_schema", "tool_calling", "context", "probe")
    failed = bool(option_problems)
    errors: list[str] = list(option_problems)
    seen: set[tuple[str, str]] = set()
    for phase in phases:
        ref = resolve_model_ref(eng.config, phase)
        if ref is None:
            console.print(f"{escape(phase)}: no model configured (set models.default in "
                          "engagement.yaml)")
            continue
        if (ref.backend, ref.model) in seen:
            continue
        seen.add((ref.backend, ref.model))
        try:
            backend = resolve_backend(eng, phase)
            caps = backend.capabilities
            # A probe must reach the server: a cached reply says nothing about today's routing.
            live = backend.inner if isinstance(backend, CachingBackend) else backend
            result = "skipped"
            if probe:
                # Probe with the real extraction schema so unsupported keywords surface here,
                # not on the first unit of a long run.
                req = CompletionRequest(
                    system=("You describe code units as JSON. Set purpose to a short phrase, "
                            "keep every list empty, and set confidence to 0.5."),
                    messages=[Message(role="user", content="Unit: x = 1 (python, line 1)")],
                    max_tokens=1024, cache_system=False, effort="low",
                )
                checked = complete_structured(live, req, UnitExtraction)
                _record_probe(eng, live, checked.usage)
                result = "ok"  # a reply that parses against the schema is what we need
            if probe_context_flag:
                target = min(int(caps.context_window * 0.75), PROBE_CAP_TOKENS)
                ok, note = probe_context(live, target, partial(_record_probe, eng, live))
                result += " · context ok" if ok else " · [red]context truncated[/red]"
                if not ok:
                    failed = True
                    errors.append(f"{phase}: {note}")
            table.add_row(escape(phase), escape(ref.backend), escape(ref.model),
                          str(caps.json_schema),
                          str(caps.tool_calling), f"{caps.context_window:,}", result)
        except (BackendConfigError, BackendUnavailable, BackendError) as exc:
            failed = True
            table.add_row(escape(phase), escape(ref.backend), escape(ref.model), "-", "-", "-",
                          "[red]error[/red]")
            errors.append(f"{phase}: {exc}")
    console.print(table)
    _print_errors(errors)
    if failed:
        raise typer.Exit(code=2)


@cache_app.command("clear")
def cache_clear(
    engagement: Path | None = EngagementOption,
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Delete cached model responses."""
    eng = _load_engagement(engagement)
    if not yes and not typer.confirm("Delete all cached model responses?"):
        raise typer.Exit(code=1)
    n = clear_cache(eng.cache_dir / "responses")
    console.print(f"Removed {plural(n, 'cached response')}.")
