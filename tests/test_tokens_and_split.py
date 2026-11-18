from unvarnish.analysis.split import (
    html_spans,
    split_file,
    structural_spans,
    unit_id,
    window_spans,
)
from unvarnish.analysis.tokens import estimate_tokens
from unvarnish.schemas.analysis import UnitKind

PY = b"".join([
    b"import os\n\n",
    b"def a():\n    return 1\n\n",
    b"def b():\n    return 2\n\n",
    b"class C:\n    def m(self):\n        return 3\n\n    def n(self):\n        return 4\n",
])


def test_estimate_tokens():
    assert estimate_tokens(b"") == 1
    assert estimate_tokens("x" * 300) == 100


def test_structural_groups_small_definitions():
    spans = structural_spans(PY, "python", unit_tokens=8000)
    assert len(spans) == 1 and spans[0].kind == UnitKind.group
    assert spans[0].line_start == 1 and spans[0].line_end == 14


def test_structural_splits_at_definition_boundaries():
    # unit_tokens small enough that each def becomes its own unit; class is split into methods
    spans = structural_spans(PY, "python", unit_tokens=12)
    kinds = [s.kind for s in spans]
    names = [s.name for s in spans]
    assert UnitKind.function in kinds and UnitKind.method in kinds
    assert "b" in names and "m" in names and "n" in names
    assert spans[0].kind == UnitKind.group and spans[0].line_start == 1  # import + a, grouped
    for prev, nxt in zip(spans, spans[1:], strict=False):
        assert nxt.byte_start >= prev.byte_end


def test_structural_returns_none_without_parser():
    assert structural_spans(b"x", "no-such-language", 100) is None


def test_window_spans_overlap_and_cover():
    src = b"".join(f"line {i}\n".encode() for i in range(100))  # ~700 bytes
    spans = window_spans(src, unit_tokens=50)  # ~150 bytes per window
    assert spans[0].byte_start == 0 and spans[-1].byte_end == len(src)
    assert all(s.kind == UnitKind.window for s in spans)
    assert len(spans) >= 4
    assert spans[1].byte_start < spans[0].byte_end
    assert spans[0].line_start == 1


def test_html_spans_separate_streams():
    from tests.conftest import HTML_SAMPLE

    spans = html_spans(HTML_SAMPLE.encode(), unit_tokens=8000)
    kinds = [s.kind for s in spans]
    assert kinds.count(UnitKind.script_block) == 2
    assert kinds.count(UnitKind.style_block) == 1
    assert UnitKind.markup in kinds
    render = next(s for s in spans if s.kind == UnitKind.script_block)
    assert render.line_start == 12 and render.line_end == 18


def test_split_file_python_and_windowed_fallback():
    units = split_file(PY, "pkg/a.py", "python", 8000, tool="t")
    assert len(units) == 1 and units[0].split_method == "structural"
    assert units[0].module_id == "pkg/a.py"
    assert units[0].id == unit_id("pkg/a.py", 1, 14, "structural", units[0].byte_start,
                                  units[0].byte_end)
    big = b"x = 1\n" * 20000  # 120 KB of statements, no definitions
    units = split_file(big, "big.py", "python", 2000, tool="t")
    assert len(units) > 10 and all(u.kind == UnitKind.group for u in units)
    assert all(u.token_estimate <= 2000 for u in units)
    assert units[0].line_start == 1 and units[-1].line_end == 20000
    long_line = b"a = [" + b"1," * 60000 + b"]\n"  # one 120 KB statement: must be windowed
    units = split_file(long_line, "one.py", "python", 2000, tool="t")
    assert len(units) > 10 and all(u.split_method == "windowed" for u in units)
    unknown = split_file(b"foo\nbar\n", "x.weird", None, 8000, tool="t")
    assert len(unknown) == 1 and unknown[0].kind == UnitKind.file


def test_split_file_marks_generated():
    units = split_file(b"var a=1;\n", "app.min.js", "javascript", 8000, tool="t", generated=True)
    assert units[0].generated is True


# --- fixes from the whole-branch review -------------------------------------
def test_single_line_file_windows_have_unique_ids():
    minified = b"var a=1;" * 40000  # 320 KB on one line
    units = split_file(minified, "app.min.js", "javascript", 2000, tool="t", generated=True)
    assert len(units) > 10
    assert len({u.id for u in units}) == len(units)
    html = b"<html><body><script>" + b"var b=2;" * 40000 + b"</script></body></html>\n"
    units = split_file(html, "dash.html", "html", 2000, tool="t")
    assert len({u.id for u in units}) == len(units) > 10
