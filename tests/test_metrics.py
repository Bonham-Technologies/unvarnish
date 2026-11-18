from pathlib import Path

from unvarnish.analysis.metrics import compute_metrics, count_lines, html_breakdown
from unvarnish.analysis.treesitter import get_parser

PY = b'''"""Module doc."""
import os

def small(a, b):
    # add
    return a + b


class Thing:
    def method(self, items):
        for i in items:
            if i:
                while True:
                    break
        return 1
'''

JS = b"""function outer() {
  const inner = () => {
    if (true) { return 1; }
  };
  return inner();
}
"""


def test_count_lines():
    assert count_lines(b"") == 0
    assert count_lines(b"a\n") == 1
    assert count_lines(b"a\nb") == 2
    assert count_lines(b"a\nb\n") == 2


def test_python_metrics(tmp_path: Path):
    f = tmp_path / "m.py"
    f.write_bytes(PY)
    m = compute_metrics(f, "m.py", "python")
    assert m.metrics_method == "treesitter"
    assert m.functions == 2
    assert m.max_function_name == "method"
    assert m.max_function_lines == 6
    assert m.max_nesting >= 3
    assert m.comment_lines >= 1
    assert m.lines == 15


def test_javascript_metrics(tmp_path: Path):
    f = tmp_path / "m.js"
    f.write_bytes(JS)
    m = compute_metrics(f, "m.js", "javascript")
    assert m.functions == 2
    assert m.max_function_name == "outer"
    assert m.max_function_lines == 6


def test_unknown_language_falls_back_to_lines(tmp_path: Path):
    f = tmp_path / "x.weird"
    f.write_bytes(b"one\ntwo\nthree\n")
    m = compute_metrics(f, "x.weird", None)
    assert m.metrics_method == "lines"
    assert m.lines == 3
    assert m.functions is None


def test_metrics_non_utf8_file(tmp_path: Path):
    f = tmp_path / "latin.py"
    f.write_bytes("# caf\xe9\ndef f():\n    return 1\n".encode("latin-1"))
    m = compute_metrics(f, "latin.py", "python")
    assert m.lines == 3
    assert m.functions == 1


def test_html_breakdown_counts_streams():
    from tests.conftest import HTML_SAMPLE

    bd, scripts = html_breakdown(HTML_SAMPLE.encode())
    assert bd.script_blocks == 2
    assert bd.style_blocks == 1
    assert bd.script_lines == 8
    assert bd.style_lines == 2
    assert bd.markup_lines + bd.script_lines + bd.style_lines <= count_lines(HTML_SAMPLE.encode())
    assert b"function render" in scripts


def test_html_metrics_parse_inline_scripts(tmp_path: Path):
    from tests.conftest import HTML_SAMPLE

    f = tmp_path / "index.html"
    f.write_text(HTML_SAMPLE)
    m = compute_metrics(f, "index.html", "html")
    assert m.html is not None
    assert m.functions == 2
    assert m.max_function_name == "render"


def test_huge_html_completes(huge_html: Path):
    m = compute_metrics(huge_html, "dashboard.html", "html")
    assert m.lines > 65_000
    assert m.html is not None
    assert m.html.script_blocks == 50
    assert m.html.script_lines > 60_000
    assert m.functions == 50
    assert m.max_function_lines > 1000


def test_get_parser_unknown_returns_none():
    assert get_parser("not-a-language") is None
    assert get_parser("python") is not None


# --- fixes from the whole-branch review -------------------------------------
def test_longest_function_span_recorded(tmp_path: Path):
    f = tmp_path / "m.py"
    f.write_bytes(PY)
    m = compute_metrics(f, "m.py", "python")
    assert (m.max_function_start, m.max_function_end) == (10, 15)


def test_html_function_span_maps_to_file_lines(tmp_path: Path):
    from tests.conftest import HTML_SAMPLE

    f = tmp_path / "index.html"
    f.write_text(HTML_SAMPLE)
    m = compute_metrics(f, "index.html", "html")
    assert m.max_function_name == "render"
    assert (m.max_function_start, m.max_function_end) == (12, 18)


# --- fixes from the first real-repo run (ESCAPESUITE) -----------------------
def test_test_runner_callbacks_are_not_functions(tmp_path: Path):
    f = tmp_path / "x.test.ts"
    f.write_bytes(b"""import { describe, it } from "vitest";
describe("suite", () => {
  it("does a thing", async () => {
    const helper = (n: number) => n + 1;
    expect(helper(1)).toBe(2);
  });
  test.each([1, 2])("case %i", (n) => {
    expect(n).toBeGreaterThan(0);
  });
});
function real(a: number) {
  return a * 2;
}
""")
    m = compute_metrics(f, "x.test.ts", "typescript")
    assert m.functions == 2  # `helper` and `real`; describe/it/test.each callbacks skipped
    assert m.max_function_name == "real"


# --- UNVAR-54: one walk gives what the three separate walks gave -------------
def _legacy_walk(root):
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        yield node, depth
        for child in reversed(node.children):
            stack.append((child, depth + 1))


def _legacy_metrics(tree, language: str, source: bytes):
    """The three walks inventory made before UNVAR-54, kept as the reference."""
    from unvarnish.analysis import treesitter as ts

    types = ts.FUNCTION_NODE_TYPES.get(language, set())
    spans = [(ts._node_name(n, source), n.start_point.row + 1, n.end_point.row + 1)
             for n, _ in _legacy_walk(tree.root_node)
             if n.type in types and not ts._is_test_runner_callback(n, source)]
    best, stack = 0, [(tree.root_node, 0)]
    while stack:
        node, depth = stack.pop()
        here = depth + (1 if node.type in ts.NESTING_NODE_TYPES else 0)
        best = max(best, here)
        stack.extend((child, here) for child in node.children)
    comments = sum(n.end_point.row - n.start_point.row + 1
                   for n, _ in _legacy_walk(tree.root_node) if n.type in ts.COMMENT_NODE_TYPES)
    return spans, best, comments


SAMPLES: dict[str, bytes] = {
    "python": PY,
    "javascript": JS + b"describe('s', () => { it('t', function () { if (a) {} }); });\n"
                       b"const o = { k: () => 1, m() { return 2; } }; /* a\n b */\n",
    "typescript": b"// c\nclass A { m(x: number): number { for (;;) { if (x) { return x; } } } }\n"
                  b"const f = (a: string) => a; function* g() { yield 1; }\n",
    "tsx": b"export const C = () => {\n  if (x) { return <div>{y.map((z) => <b>{z}</b>)}</div>; }\n"
           b"};\n",
    "go": b"package m\n// c\nfunc (s *S) M() { for { if x { f := func() {}; f() } } }\n"
          b"func F() int { switch { case true: return 1 }; return 0 }\n",
    "rust": b"/// doc\nfn f() { let c = |x| x + 1; if true { loop { match c(1) { _ => {} } } } }\n"
            b"impl S { fn m(&self) {} }\n",
    "java": b"class A { /* c */ A() {}\n"
            b"  void m() { Runnable r = () -> {}; if (x) { while (y) {} } } }\n",
    "c_sharp": b"class A { A() {} void M() { void L() {} if (x) { foreach (var i in y) {} } } }\n",
    "kotlin": b"// c\nfun f(x: Int): Int { if (x > 0) { return 1 }; return 0 }\n",
    "ruby": b"# c\nclass A\n  def m(x)\n    if x\n      1\n    end\n  end\n"
            b"  def self.s; end\nend\n",
    "php": b"<?php\n// c\nfunction f($x) { if ($x) { foreach ($x as $y) {} } }\n"
           b"class A { function m() {} }\n",
    "c": b"/* c */\nint f(int x) { if (x) { for (;;) { while (x) {} } } return 0; }\n",
    "cpp": b"// c\nint A::m() {\n  auto l = [](int x) { return x; };\n"
           b"  if (x) { return l(1); } return 0;\n}\n",
    "swift": b"// c\nfunc f(x: Int) -> Int { if x > 0 { return 1 }; return 0 }\n",
    "scala": b"// c\nobject O { def f(x: Int): Int = { if (x > 0) 1 else 0 } }\n",
    "lua": b"-- c\nfunction f(x) if x then for i=1,2 do end end end\nlocal g = function() end\n",
    "bash": b"# c\nf() { if true; then for i in 1; do :; done; fi; }\n",
    "css": b"/* c */\n.a { color: red; }\n@media (x) { .b { color: blue; } }\n",
}
BROKEN = b"function broken( { if (x { return\n// dangling\nconst y = () => {\n"


def _equivalence_cases():
    from unvarnish.analysis.treesitter import get_parser

    cases = [(lang, src) for lang, src in SAMPLES.items()]
    cases.append(("javascript", BROKEN))
    cases.append(("python", PY.replace(b"return 1", b"return (")))
    src_root = Path(__file__).resolve().parents[1] / "src"
    cases += [("python", p.read_bytes()) for p in sorted(src_root.rglob("*.py"))]
    return [(lang, src) for lang, src in cases if get_parser(lang) is not None]


def test_single_walk_matches_the_three_walks():
    from unvarnish.analysis.treesitter import get_parser, tree_metrics

    cases = _equivalence_cases()
    assert len({lang for lang, _ in cases}) >= 15  # the grammars are present: CI fetches them
    for language, source in cases:
        tree = get_parser(language).parse(source)
        got = tree_metrics(tree, language, source)
        assert (got.spans, got.max_nesting, got.comment_lines) == _legacy_metrics(
            tree, language, source), (language, source[:80])
