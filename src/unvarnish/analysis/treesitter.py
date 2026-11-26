from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MAX_PARSE_BYTES = 5_000_000

# Our language ids -> tree-sitter-language-pack names where they differ.
PACK_NAMES = {"c_sharp": "csharp"}
# Census languages the pack has no grammar for: never looked up, never reported missing.
NO_GRAMMAR = frozenset({"jupyter", "text"})
FETCH_HINT = "run `unvarnish grammars fetch` where GitHub is reachable, then rerun"

FUNCTION_NODE_TYPES: dict[str, set[str]] = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function",
                   "function_expression", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition", "arrow_function",
                   "function_expression", "generator_function_declaration"},
    "tsx": {"function_declaration", "method_definition", "arrow_function",
            "function_expression", "generator_function_declaration"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "rust": {"function_item", "closure_expression"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
    "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
    "kotlin": {"function_declaration"},
    "ruby": {"method", "singleton_method"},
    "php": {"function_definition", "method_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "swift": {"function_declaration"},
    "scala": {"function_definition"},
    "lua": {"function_declaration", "function_definition"},
    "bash": {"function_definition"},
}

NESTING_NODE_TYPES = {
    "block", "statement_block", "compound_statement", "class_body", "function_body",
    "if_statement", "for_statement", "for_in_statement", "for_of_statement", "while_statement",
    "do_statement", "try_statement", "switch_statement", "match_statement", "with_statement",
    "elif_clause", "else_clause", "except_clause", "case_clause",
}
COMMENT_NODE_TYPES = {"comment", "line_comment", "block_comment", "doc_comment"}

# Callbacks passed straight to these are test-suite structure, not functions worth measuring.
TEST_RUNNER_CALLEES = {"describe", "it", "test", "suite", "context", "bench", "beforeEach",
                       "afterEach", "beforeAll", "afterAll", "before", "after"}
CALLBACK_NODE_TYPES = {"arrow_function", "function_expression", "function"}


def _callee_root(node: Any, source: bytes) -> str | None:
    """Root identifier of a call's callee: `describe`, `it.skip`, `test.each(...)(...)`."""
    while node is not None and node.type in {"member_expression", "call_expression",
                                             "subscript_expression"}:
        node = node.child_by_field_name("object") or node.child_by_field_name("function")
    if node is not None and node.type == "identifier":
        return source[node.start_byte:node.end_byte].decode("utf-8", "replace")
    return None


def _is_test_runner_callback(node: Any, source: bytes) -> bool:
    if node.type not in CALLBACK_NODE_TYPES:
        return False
    args = node.parent
    if args is None or args.type != "arguments":
        return False
    call = args.parent
    if call is None or call.type != "call_expression":
        return False
    return _callee_root(call.child_by_field_name("function"), source) in TEST_RUNNER_CALLEES


def pack_name(language: str) -> str:
    return PACK_NAMES.get(language, language)


@cache
def grammar_languages() -> list[str]:
    """The pack grammars Unvarnish loads, one for each language the census detects.

    The pack (1.x) ships no grammars: it downloads them from GitHub on first use. This is the
    list `unvarnish grammars fetch` downloads ahead of time, for CI, the image and laptops."""
    from unvarnish.analysis.languages import EXTENSION_MAP, FILENAME_MAP, SHEBANG_MAP

    ids = set(EXTENSION_MAP.values()) | set(FILENAME_MAP.values()) | set(SHEBANG_MAP.values())
    return sorted({pack_name(i) for i in ids - NO_GRAMMAR})



def grammar_status() -> tuple[str, list[str], int]:
    """(the pack's cache folder, grammars not on disk, grammars Unvarnish uses), read from
    disk only: nothing is downloaded."""
    import tree_sitter_language_pack as pack

    names = grammar_languages()
    have = set(pack.downloaded_languages())
    return str(pack.cache_dir()), [n for n in names if n not in have], len(names)

# Grammars that failed to load in this process: our language id -> why. Shared by the threads
# of a parallel run, so each missing grammar is warned about once.
_unavailable: dict[str, str] = {}
_unavailable_lock = threading.Lock()


def grammar_unavailable(language: str) -> str | None:
    """Why `language`'s grammar failed to load in this process, or None if it never did."""
    return _unavailable.get(language)


def grammar_cached(language: str) -> bool:
    """Whether `language`'s grammar is in the pack's cache directory. Never downloads."""
    try:
        from tree_sitter_language_pack import downloaded_languages

        return pack_name(language) in downloaded_languages()
    except Exception:
        return False


def _note_unavailable(language: str, exc: Exception) -> None:
    reason = f"{type(exc).__name__}: {exc}"[:300]
    with _unavailable_lock:
        if language in _unavailable:
            return
        _unavailable[language] = reason
    log.warning("No tree-sitter grammar for %s (%s): its files are measured by line counts, "
                "without functions or structural units; %s.", language, reason, FETCH_HINT)


@cache
def get_parser(language: str) -> Any | None:
    """A parser for `language`, or None when it has no grammar or the grammar can't be loaded.

    A grammar not yet in the pack's cache is downloaded here; when that fails (no network, a
    GitHub outage) the failure is logged once and recorded for the census note (UNVAR-45)."""
    name = pack_name(language)
    if language in NO_GRAMMAR or name not in grammar_languages():
        return None
    try:
        import tree_sitter_language_pack as pack

        return pack.get_parser(name)  # type: ignore[arg-type]
    except Exception as exc:
        _note_unavailable(language, exc)
        return None


class GrammarFetchError(RuntimeError):
    pass


def fetch_grammars(cache_dir: str | Path | None = None, attempts: int = 4,
                   backoff: float = 5.0,
                   sleep: Callable[[float], None] = time.sleep) -> tuple[str, list[str]]:
    """Download every grammar in `grammar_languages()` into the pack's cache, retrying with
    exponential backoff. Returns the cache directory and the grammars still missing.

    `cache_dir` is the base directory (the pack's TREE_SITTER_LANGUAGE_PACK_CACHE_DIR);
    grammars already on disk are not downloaded again."""
    import tree_sitter_language_pack as pack

    if cache_dir is not None:
        pack.configure(pack.PackConfig(cache_dir=str(cache_dir)))
    names = grammar_languages()
    for attempt in range(1, attempts + 1):
        try:
            pack.prefetch(names)
            break
        except Exception as exc:
            if attempt >= attempts:
                raise GrammarFetchError(
                    f"gave up after {attempts} attempts: {type(exc).__name__}: {exc}") from exc
            delay = backoff * 2 ** (attempt - 1)
            log.warning("grammar download failed (attempt %d of %d, retrying in %gs): %s",
                        attempt, attempts, delay, exc)
            sleep(delay)
    have = set(pack.downloaded_languages())
    return pack.cache_dir(), [n for n in names if n not in have]


def _node_name(node: Any, source: bytes) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace")
    # arrow functions / closures assigned to a variable: look at the parent declarator
    parent = node.parent
    if parent is not None and parent.type in {"variable_declarator", "assignment", "pair",
                                              "assignment_expression", "let_declaration"}:
        for child in parent.children:
            if child.type in {"identifier", "property_identifier",
                              "shorthand_property_identifier"}:
                return source[child.start_byte:child.end_byte].decode("utf-8", "replace")
    return "<anonymous>"


@dataclass(frozen=True)
class TreeMetrics:
    """What inventory measures in one parse tree."""

    spans: list[tuple[str, int, int]]  # each function's name, first and last line, in order
    max_nesting: int
    comment_lines: int


@cache
def _kind_ids(grammar: Any, language: str) -> tuple[frozenset[int], ...]:
    """The kind ids of `grammar` named as function, nesting and comment node types.

    Comparing a node's integer `kind_id` saves building its `type` string on every node. Every
    id whose name matches is included, so aliased kinds count exactly as matching on `type` did."""
    names = [grammar.node_kind_for_id(i) for i in range(grammar.node_kind_count)]

    def ids(wanted: set[str]) -> frozenset[int]:
        return frozenset(i for i, name in enumerate(names) if name in wanted)

    return (ids(FUNCTION_NODE_TYPES.get(language, set())), ids(NESTING_NODE_TYPES),
            ids(COMMENT_NODE_TYPES))


def _walk(root: Any, source: bytes, function_kinds: frozenset[int],
          nesting_kinds: frozenset[int], comment_kinds: frozenset[int]) -> TreeMetrics:
    """The one pre-order walk of a tree that inventory makes (UNVAR-54).

    A tree cursor visits each node once without building a list of children per node. Inventory
    used to walk every tree three times (functions, nesting, comments); on a 600,000-line tool
    the tree-sitter metrics were 201 s of a 205 s inventory."""
    spans: list[tuple[str, int, int]] = []
    best = comments = 0
    cursor = root.walk()
    nesting = [0]  # nesting depth of each ancestor of the cursor's node, its parent last
    while True:
        node = cursor.node
        kind = node.kind_id
        here = nesting[-1] + (kind in nesting_kinds)
        if here > best:
            best = here
        if kind in comment_kinds:
            comments += node.end_point.row - node.start_point.row + 1
        if kind in function_kinds and not _is_test_runner_callback(node, source):
            spans.append(
                (_node_name(node, source), node.start_point.row + 1, node.end_point.row + 1)
            )
        if cursor.goto_first_child():
            nesting.append(here)
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return TreeMetrics(spans=spans, max_nesting=best, comment_lines=comments)
            nesting.pop()


def tree_metrics(tree: Any, language: str, source: bytes) -> TreeMetrics:
    """Functions (minus test-runner callbacks), deepest nesting and comment lines of `tree`."""
    return _walk(tree.root_node, source, *_kind_ids(tree.language, language))
