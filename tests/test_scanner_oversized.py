from pathlib import Path

from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.oversized_files import OversizedFilesScanner
from unvarnish.schemas.finding import Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import (
    Census,
    CensusTotals,
    Dependencies,
    FileMetrics,
    HtmlBreakdown,
    Metrics,
)


def _ctx(files: list[FileMetrics], options: dict | None = None) -> ScanContext:
    return ScanContext(
        tool="t", source_root=Path("."),
        census=Census(tool="t", files=[], totals=CensusTotals()),
        metrics=Metrics(tool="t", files=files),
        git=GitStats(tool="t", available=False),
        dependencies=Dependencies(tool="t", dependencies=[]),
        options=options or {"file_lines": 1500, "function_lines": 150, "html_script_lines": 500},
    )


def test_flags_oversized_file_and_function():
    fm = FileMetrics(path="app.py", lines=3010, bytes=1, functions=2, max_function_lines=3002,
                     max_function_name="process_everything", metrics_method="treesitter")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    titles = {f.title: f for f in findings}
    assert titles["Oversized file"].severity == Severity.high
    assert titles["Oversized file"].evidence[0].path == "app.py"
    assert "3,010" in titles["Oversized file"].summary
    assert titles["Very large function"].severity == Severity.high  # > 5x threshold
    assert "process_everything" in titles["Very large function"].summary


def test_function_just_over_threshold_is_medium():
    fm = FileMetrics(path="a.py", lines=200, bytes=1, functions=1, max_function_lines=160,
                     max_function_name="f", metrics_method="treesitter")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    assert [f.severity for f in findings] == [Severity.medium]


def test_html_inline_script_threshold():
    bd = HtmlBreakdown(markup_lines=100, script_lines=900, style_lines=50, markup_bytes=1,
                       script_bytes=1, style_bytes=1, script_blocks=3, style_blocks=1)
    fm = FileMetrics(path="index.html", lines=1050, bytes=1, html=bd, metrics_method="lines")
    findings = OversizedFilesScanner().run(_ctx([fm]))
    assert [f.title for f in findings] == ["Inline script in HTML exceeds threshold"]
    assert "900" in findings[0].summary and "3 script" in findings[0].summary


def test_nothing_flagged_under_thresholds():
    fm = FileMetrics(path="ok.py", lines=10, bytes=1, functions=1, max_function_lines=5,
                     max_function_name="f", metrics_method="treesitter")
    assert OversizedFilesScanner().run(_ctx([fm])) == []


# --- fixes from the whole-branch review -------------------------------------
def test_html_is_also_checked_for_file_and_function_size():
    bd = HtmlBreakdown(markup_lines=69000, script_lines=300, style_lines=0, markup_bytes=1,
                       script_bytes=1, style_bytes=1, script_blocks=1, style_blocks=0)
    fm = FileMetrics(path="dash.html", lines=69300, bytes=1, html=bd, functions=1,
                     max_function_lines=2000, max_function_name="init",
                     max_function_start=40, max_function_end=2039, metrics_method="treesitter")
    titles = {f.title for f in OversizedFilesScanner().run(_ctx([fm]))}
    assert {"Oversized file", "Very large function"} <= titles
    assert "Inline script in HTML exceeds threshold" not in titles


def test_oversized_function_evidence_carries_line_range():
    fm = FileMetrics(path="a.py", lines=400, bytes=1, functions=1, max_function_lines=160,
                     max_function_name="f", max_function_start=10, max_function_end=169,
                     metrics_method="treesitter")
    [finding] = OversizedFilesScanner().run(_ctx([fm]))
    assert finding.evidence[0].line_start == 10
    assert finding.evidence[0].line_end == 169
