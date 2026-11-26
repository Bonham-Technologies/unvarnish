"""Field names that suggest sensitive data, and where they are declared (UNVAR-100).

Reads the names of columns, model fields and typed-structure properties: SQL `CREATE TABLE`
and `ALTER TABLE ... ADD` (in `.sql` files and in SQL strings in any source file), Python
classes (Django, SQLAlchemy, SQLModel, Pydantic, dataclasses, TypedDict, NamedTuple,
MongoEngine) and migrations (Django, Alembic), Prisma models, TypeScript interfaces and
object types, TypeORM entities, and Mongoose, Zod and Drizzle schemas. Each name is matched
word by word against the pattern set in `sensitive_data.yaml`, which
`scanners.sensitive_data.patterns` overrides. The result is an inventory
(`inventory/sensitive-data.json`), not findings. Name-based only: no data value is read or
recorded. Offline and deterministic."""

from __future__ import annotations

import ast
import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unvarnish.analysis.languages import CONFIG_LANGS, DATA_EXTS, DOC_LANGS, Classification
from unvarnish.config import DEFAULT_SCANNER_OPTIONS, bundled_sensitive_patterns
from unvarnish.scanners.base import ScanContext
from unvarnish.schemas.finding import Category, Finding
from unvarnish.schemas.sensitive_data import SensitiveData, SensitiveField

NAME = "sensitive_data"
OPTION = f"scanners.{NAME}.patterns"
MAX_FILE_BYTES = 5_000_000
MAX_BODY_CHARS = 200_000  # how far one table or type body is followed
# Characters one file's table and type bodies may take in all, as a multiple of its length:
# bodies that never close (or nest without end) would otherwise be followed once per opener,
# which is quadratic in the file's size.
SCAN_BUDGET_FACTOR = 4
# How far a pattern looks between a declaration's name and its opening brace (generics,
# `extends`, a type annotation), so that a declaration that never opens costs a bounded scan.
_GAP = 300
PYTHON_SUFFIXES = {".py", ".pyi"}
TS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}
# Source languages that declare data structures this pass does not read: reported as
# "not analysed" with their file counts.
UNREAD_LANGUAGES = {"go", "rust", "java", "kotlin", "ruby", "php", "c_sharp", "swift",
                    "scala", "dart", "elixir", "graphql", "proto", "vue", "svelte"}


# Languages whose files are never opened: configuration, documents and notebooks (whose
# saved outputs can hold data).
NEVER_OPENED = CONFIG_LANGS | DOC_LANGS | {"jupyter"}


def opens(path: str, language: str | None) -> bool:
    """Whether the pass opens a file: source code (SQL included) and Prisma schemas only,
    never data files, configuration or documents."""
    suffix = Path(path).suffix.lower()
    if suffix == ".prisma":
        return True
    return language is not None and language not in NEVER_OPENED and suffix not in DATA_EXTS


def bundled_patterns() -> dict[str, Any]:
    """The bundled pattern set, `src/unvarnish/scanners/sensitive_data.yaml`."""
    return bundled_sensitive_patterns()


# --- the pattern set -------------------------------------------------------------------------

WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
PATTERN_KEYS = {"classes", "ignore", "ignore_suffixes"}
CLASS_KEYS = {"label", "terms", "exclude"}


def name_words(name: str) -> list[str]:
    """A field name split into lower-case words at separators, digits and camelCase humps."""
    return [w.lower() for w in WORD_RE.findall(name)]


def _is_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) and name_words(x) for x in value)


def pattern_problems(patterns: Any) -> list[str]:
    """What is wrong with a pattern set, one entry per problem, each naming its key."""
    if not isinstance(patterns, dict):
        return ["must be a mapping with classes, ignore and ignore_suffixes"]
    out = [f"{k}: unknown key (expected classes, ignore or ignore_suffixes)"
           for k in patterns if k not in PATTERN_KEYS]
    for key in ("ignore", "ignore_suffixes"):
        if key in patterns and not _is_strings(patterns[key]):
            out.append(f"{key}: expected a list of words")
    classes = patterns.get("classes", {})
    if not isinstance(classes, dict):
        return [*out, "classes: expected a mapping of data classes to label, terms and exclude"]
    for name, spec in classes.items():
        where = f"classes.{name}"
        if not isinstance(spec, dict):
            out.append(f"{where}: expected a mapping with label, terms and exclude")
            continue
        out += [f"{where}.{k}: unknown key (expected label, terms or exclude)"
                for k in spec if k not in CLASS_KEYS]
        if "label" in spec and not isinstance(spec["label"], str):
            out.append(f"{where}.label: expected a string")
        if "terms" not in spec:
            out.append(f"{where}.terms: missing")
        for key in ("terms", "exclude"):
            if key in spec and not _is_strings(spec[key]):
                out.append(f"{where}.{key}: expected a list of words")
    return out


def _find(words: list[str], term: tuple[str, ...]) -> int | None:
    """Where `term` starts in `words`: its words next to each other, the last one optionally
    plural, or all of them joined as one word ("firstname"). None when absent."""
    last = term[-1]
    plurals = (last, last + "s", last + "es")
    n = len(term)
    for i in range(len(words) - n + 1):
        if list(term[:-1]) == words[i:i + n - 1] and words[i + n - 1] in plurals:
            return i
    if n > 1:
        joined = "".join(term)
        for i, w in enumerate(words):
            if w in (joined, joined + "s", joined + "es"):
                return i
    return None


def _words(phrases: list[str]) -> list[tuple[str, ...]]:
    return [tuple(name_words(p)) for p in phrases if name_words(p)]


@dataclass
class Patterns:
    classes: list[tuple[str, str, list[tuple[str, ...]], list[tuple[str, ...]]]]
    ignore: list[tuple[str, ...]]
    suffixes: set[str]

    def labels(self) -> dict[str, str]:
        return {key: label for key, label, _, _ in self.classes}

    def classify(self, name: str) -> list[tuple[str, str]]:
        """(data class, matched pattern) for each class whose pattern the name matches."""
        words = name_words(name)
        if not words:
            return []
        last = words[-1]
        if last in self.suffixes or (last.endswith("s") and last[:-1] in self.suffixes):
            return []
        if any(_find(words, ig) is not None for ig in self.ignore):
            return []
        out: list[tuple[str, str]] = []
        for key, _, terms, excludes in self.classes:
            if any(_find(words, ex) is not None for ex in excludes):
                continue
            best: tuple[int, int, tuple[str, ...]] | None = None
            for term in terms:
                pos = _find(words, term)
                if pos is not None and (best is None or (pos, -len(term)) < best[:2]):
                    best = (pos, -len(term), term)
            if best is not None:
                out.append((key, " ".join(best[2])))
        return out


def compile_patterns(patterns: Any) -> Patterns:
    problems = pattern_problems(patterns)
    if problems:
        raise ValueError(f"{OPTION}: " + "; ".join(problems))
    classes = [(key, spec.get("label") or key, _words(spec["terms"]),
                _words(spec.get("exclude", [])))
               for key, spec in patterns.get("classes", {}).items()]
    return Patterns(classes=classes, ignore=_words(patterns.get("ignore", [])),
                    suffixes={w for p in patterns.get("ignore_suffixes", [])
                              for w in name_words(p)})


# --- structures ------------------------------------------------------------------------------

@dataclass
class _Struct:
    store: str
    kind: str
    persistent: bool
    fields: list[tuple[str, int]] = field(default_factory=list)  # (name, line)


class _Lines:
    def __init__(self, text: str) -> None:
        self._starts = [m.start() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_left(self._starts, offset) + 1


class _Budget:
    """The characters left for following one file's bodies (SCAN_BUDGET_FACTOR)."""

    def __init__(self, text: str) -> None:
        self.left = SCAN_BUDGET_FACTOR * len(text) + MAX_BODY_CHARS
        self.spent = False

    def end(self, text: str, start: int) -> int:
        """Where a body that opens at `start` stops being followed."""
        return min(len(text), start + MAX_BODY_CHARS, start + max(self.left, 0))

    def take(self, start: int, stop: int) -> None:
        self.left -= stop - start
        if self.left <= 0:
            self.spent = True


# SQL ---------------------------------------------------------------------------------------

_IDENT = r'(?:"[^"\n]+"|`[^`\n]+`|\[[^\]\n]+\]|[A-Za-z_][\w$]*)'
_QUALIFIED = rf"((?:{_IDENT}\s*\.\s*)*{_IDENT})"
CREATE_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?"
    r"(?:(?:TEMP|TEMPORARY|UNLOGGED|VIRTUAL)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    rf"{_QUALIFIED}\s*\(", re.IGNORECASE)
ALTER_SQL_RE = re.compile(
    rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_QUALIFIED}([^;]{{0,5000}})",
    re.IGNORECASE)
# In SQL inside another language's string, an ALTER statement is read to the end of its line.
ALTER_EMBEDDED_RE = re.compile(
    rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_QUALIFIED}([^;\n]{{0,500}})",
    re.IGNORECASE)
ADD_RE = re.compile(rf"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({_IDENT})",
                    re.IGNORECASE)
NOT_COLUMNS = {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX", "KEY",
               "EXCLUDE", "LIKE", "FULLTEXT", "SPATIAL", "PERIOD"}
COLUMN_NAME_RE = re.compile(r"[\s\"'`\[+]*([A-Za-z_][\w$]*)")
# Comments, string literals and dollar-quoted bodies are blanked in .sql files; a double-quoted
# identifier is kept. A quote inside a string is doubled in standard SQL ('it''s') and
# escaped with a backslash in MySQL and Postgres E'' strings ('O\'Brien'); a standard string
# may also end in a backslash ('C:\'). The file is read both ways; a reading that leaves a
# string open at the end of the file is the wrong one. When neither or both readings close
# every string, the text is blanked wherever either puts a string: a misread then hides a
# declaration, never exposes a value.
_SQL_SKIP = (r"--[^\n]*|/\*.*?(?:\*/|\Z)|{string}"
             r"|\$(?P<tag>\w*)\$.*?(?:\$(?P=tag)\$|\Z)"
             r'|"[^"]*"')
SQL_SKIP_RES = (
    re.compile(_SQL_SKIP.format(string=r"'(?:[^']|'')*(?P<close>')?"), re.DOTALL),
    re.compile(_SQL_SKIP.format(string=r"'(?:[^'\\]|''|\\.)*(?P<close>')?"), re.DOTALL),
)


# The rows of a dump: `COPY ... FROM stdin;` up to its `\.` line (or the end of the file), and
# INSERT statements once strings are blanked. Blanked before anything else, so an apostrophe in
# a row (O'Brien) cannot shift which parts of the file count as strings.
# psql's `\copy ... from stdin` reads its rows the same way.
COPY_ROWS_RE = re.compile(r"^[ \t]*\\?COPY\b[^;\n]*\bFROM\s+stdin\b.*?(?:^\\\.[ \t]*$|\Z)",
                          re.IGNORECASE | re.MULTILINE | re.DOTALL)
# A double-quoted value (MySQL) is opaque, so a `;` in it does not end the statement early.
INSERT_RE = re.compile(r"\b(?:INSERT|REPLACE)\s+INTO\b(?:[^;\"]|\"[^\"]*(?:\"|\Z))*",
                       re.IGNORECASE)


def _blank_all(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _blank_strings(text: str) -> str:
    """Comments, strings and dollar-quoted bodies blanked as either reading of quotes finds
    them (SQL_SKIP_RES); line breaks and double-quoted identifiers are kept."""
    readings: list[tuple[list[tuple[int, int]], bool]] = []
    for rx in SQL_SKIP_RES:
        found, closed = [], True
        for m in rx.finditer(text):
            if m.group(0).startswith('"'):
                continue
            found.append(m.span())
            if m.group(0).startswith("'") and m.group("close") is None:
                closed = False
        readings.append((found, closed))
    good = [found for found, closed in readings if closed]
    chosen = good if len(good) == 1 else [found for found, _ in readings]
    spans = sorted(span for found in chosen for span in found)
    out: list[str] = []
    pos = 0
    for start, end in spans:
        if end <= pos:
            continue
        if start > pos:
            out.append(text[pos:start])
        out.append(re.sub(r"[^\n]", " ", text[max(start, pos):end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _unquote(name: str) -> str:
    part = re.split(r"\s*\.\s*(?=[\"`\[A-Za-z_])", name.strip())[-1]
    return part.strip('"`[]')


def _sql_columns(text: str, start: int, budget: _Budget) -> list[tuple[str, int]]:
    """Column names and offsets in the parenthesised list that opens at `start`."""
    out: list[tuple[str, int]] = []
    depth, i, seg = 1, start + 1, start + 1
    end = budget.end(text, start)
    while i < end and depth:
        c = text[i]
        if c in "\"'`":
            close = text.find(c, i + 1, end)
            i = end if close < 0 else close + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if (c == "," and depth == 1) or depth == 0:
            m = COLUMN_NAME_RE.match(text, seg, i)
            if m and m.group(1).upper() not in NOT_COLUMNS:
                out.append((m.group(1), m.start(1)))
            seg = i + 1
        i += 1
    budget.take(start, i)
    return out


def _sql_structures(text: str, embedded: bool) -> list[_Struct]:
    if embedded:
        code = text
    else:
        code = COPY_ROWS_RE.sub(_blank_all, text)
        code = INSERT_RE.sub(_blank_all, _blank_strings(code))
    lines = _Lines(code)
    budget = _Budget(code)
    tables: dict[str, _Struct] = {}

    def table(name: str) -> _Struct:
        store = _unquote(name)
        return tables.setdefault(store.lower(), _Struct(store, "SQL table", True))

    for m in CREATE_RE.finditer(code):
        if budget.spent:
            break
        t = table(m.group(1))
        t.fields += [(n, lines.line(o)) for n, o in _sql_columns(code, m.end() - 1, budget)]
    for m in (ALTER_EMBEDDED_RE if embedded else ALTER_SQL_RE).finditer(code):
        for add in ADD_RE.finditer(m.group(2)):
            name = add.group(1).strip('"`[]')
            if name.upper() in NOT_COLUMNS:
                continue
            table(m.group(1)).fields.append((name, lines.line(m.start(2) + add.start(1))))
    return list(tables.values())


# Python ------------------------------------------------------------------------------------

def _dotted(node: ast.expr) -> str:
    """`a.b.c` for a name, attribute chain, call or subscript of one; a part that is not a
    name (a call in a chain, say) is `?`. Iterative, so a long method chain is linear."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Subscript):
        node = node.value
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    parts.append(node.id if isinstance(node, ast.Name) else "?")
    return ".".join(reversed(parts))


def _str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _class_kind(cls: ast.ClassDef, django: bool, local: dict[str, tuple[str, bool]],
                sqla_bases: set[str]) -> tuple[str, bool] | None:
    for d in cls.decorator_list:
        last = _dotted(d).rsplit(".", 1)[-1]
        if last == "dataclass":
            return "dataclass", False
        if _dotted(d) in {"attr.s", "attrs.define", "attr.define", "define", "frozen",
                          "attrs.frozen"}:
            return "attrs class", False
    table = _kwarg_true(cls, "table")
    for base in cls.bases:
        text = _dotted(base)
        last = text.rsplit(".", 1)[-1]
        if text in local:
            return local[text]
        if text in sqla_bases or last in {"DeclarativeBase", "DeclarativeBaseNoMeta"} \
                or text == "db.Model":
            return "SQLAlchemy model", True
        if last == "Model" and (text == "models.Model" or django):
            return "Django model", True
        if last == "SQLModel":
            return "SQLModel model", table
        if last in {"BaseModel", "RootModel"}:
            return "Pydantic model", False
        if last in {"TypedDict", "NamedTuple"}:
            return last, False
        if last in {"Schema", "ModelSchema"}:
            return "schema", False
        if last in {"Document", "EmbeddedDocument", "DynamicDocument"}:
            return "MongoEngine document", True
    if any(isinstance(s, ast.Assign) and any(isinstance(t, ast.Name) and t.id in
                                             {"__tablename__", "__table__"} for t in s.targets)
           for s in cls.body):
        return "SQLAlchemy model", True
    return None


def _kwarg_true(cls: ast.ClassDef, name: str) -> bool:
    value = next((k.value for k in cls.keywords if k.arg == name), None)
    return isinstance(value, ast.Constant) and value.value is True


def _class_fields(cls: ast.ClassDef) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for stmt in cls.body:
        targets: list[ast.expr] = []
        if isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
        elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            targets = list(stmt.targets)
        out += [(t.id, stmt.lineno) for t in targets
                if isinstance(t, ast.Name) and not t.id.startswith("_")]
    return out


def _columns(nodes: list[ast.expr]) -> list[tuple[str, int]]:
    """`Column("name", ...)` calls among `nodes`, as (name, line)."""
    out: list[tuple[str, int]] = []
    for n in nodes:
        if isinstance(n, ast.Call) and _dotted(n).rsplit(".", 1)[-1] == "Column" and n.args:
            name = _str(n.args[0])
            if name:
                out.append((name, n.args[0].lineno))
    return out


def _python_structures(text: str) -> list[_Struct] | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):  # too deep: CPython's limits
        return None
    django = "django" in text
    sqla_bases = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
                  and isinstance(n.value, ast.Call)
                  and _dotted(n.value).rsplit(".", 1)[-1] in {"declarative_base",
                                                               "generate_base"}
                  for t in n.targets if isinstance(t, ast.Name)}
    local: dict[str, tuple[str, bool]] = {}
    out: list[_Struct] = []
    classes = sorted((n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)),
                     key=lambda n: n.lineno)
    for cls in classes:
        kind = _class_kind(cls, django, local, sqla_bases)
        if kind is None:
            continue
        local[cls.name] = kind
        out.append(_Struct(cls.name, kind[0], kind[1], _class_fields(cls)))
    tables: dict[tuple[str, str], _Struct] = {}

    def store(name: str, kind: str) -> _Struct:
        return tables.setdefault((name.lower(), kind), _Struct(name, kind, True))

    calls = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)),
                   key=lambda n: (n.lineno, n.col_offset))
    for call in calls:
        name = _dotted(call).rsplit(".", 1)[-1]
        first = _str(call.args[0]) if call.args else None
        if name in {"create_table", "Table"} and first:
            store(first, "SQL table").fields += _columns(call.args[1:])
        elif name == "add_column" and first:
            store(first, "SQL table").fields += _columns(call.args[1:])
        elif name == "CreateModel" and _str(_kwarg(call, "name")):
            model = store(_str(_kwarg(call, "name")) or "", "Django model")
            fields = _kwarg(call, "fields")
            for elt in fields.elts if isinstance(fields, (ast.List, ast.Tuple)) else []:
                if isinstance(elt, ast.Tuple) and elt.elts and _str(elt.elts[0]):
                    model.fields.append((_str(elt.elts[0]) or "", elt.elts[0].lineno))
        elif name == "AddField" and _str(_kwarg(call, "model_name")):
            target = _kwarg(call, "name")
            if _str(target):
                store(_str(_kwarg(call, "model_name")) or "", "Django model").fields.append(
                    (_str(target) or "", target.lineno))
    return out + list(tables.values())


# Prisma ------------------------------------------------------------------------------------

PRISMA_BLOCK_RE = re.compile(r"^\s*(model|type)\s+([A-Za-z_]\w*)\s*\{")
PRISMA_FIELD_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s+[A-Za-z_]")


def _prisma_structures(text: str) -> list[_Struct]:
    out: list[_Struct] = []
    current: _Struct | None = None
    for n, raw in enumerate(text.split("\n"), start=1):
        line = raw.split("//", 1)[0]
        if current is None:
            m = PRISMA_BLOCK_RE.match(line)
            if m:
                model = m.group(1) == "model"
                current = _Struct(m.group(2), "Prisma model" if model else "Prisma type", model)
                out.append(current)
            continue
        if line.strip().startswith("}"):
            current = None
            continue
        m = PRISMA_FIELD_RE.match(line)
        if m:
            current.fields.append((m.group(1), n))
    return out


# JavaScript and TypeScript -----------------------------------------------------------------

JS_SKIP_RE = re.compile(r"//[^\n]*|/\*.*?(?:\*/|\Z)|\"(?:\\.|[^\"\\\n])*\"?"
                        r"|'(?:\\.|[^'\\\n])*'?|`(?:\\.|[^`\\])*`?", re.DOTALL)
_JS_NAME = r"[A-Za-z_$][\w$]*"
_BINDING = rf"(?:(?:const|let|var)\s+({_JS_NAME})\s*(?::[^=\n]{{1,150}})?=\s*)?"
# (pattern, kind, persistent, nested fields count, TypeScript only)
JS_OPENERS: list[tuple[re.Pattern[str], str, bool, bool, bool]] = [
    (re.compile(rf"\binterface\s+({_JS_NAME})(?![\w$])[^{{;]{{0,{_GAP}}}\{{"),
     "TypeScript interface", False, True, True),
    (re.compile(rf"\btype\s+({_JS_NAME})(?:\s*<[^=;{{]{{0,{_GAP}}}>)?\s*=\s*\{{"),
     "TypeScript type", False, True, True),
    (re.compile(rf"@Entity\s*\([^)]{{0,{_GAP}}}\)\s*(?:export\s+)?(?:default\s+)?"
                rf"(?:abstract\s+)?class\s+({_JS_NAME})(?![\w$])[^{{]{{0,{_GAP}}}\{{"),
     "TypeORM entity", True, False, True),
    (re.compile(rf"{_BINDING}\bnew\s+(?:mongoose\.)?Schema\s*(?:<[^>]{{0,{_GAP}}}>)?"
                rf"\s*\(\s*\{{"),
     "Mongoose schema", True, False, False),
    (re.compile(rf"{_BINDING}\bz\.(?:strict)?[oO]bject\s*\(\s*\{{"),
     "Zod schema", False, False, False),
    (re.compile(r"\b(?:pg|mysql|sqlite)Table\s*\(\s*[\"'`]([^\"'`\n]+)[\"'`]\s*,\s*\{"),
     "Drizzle table", True, False, False),
]
# A property: up to 8 decorators (each `@name` with an optional argument list), up to 4
# modifiers, then the name and a colon. Each part can match in one way only: a decorator or a
# name is never cut short (the lookaheads) and is length-capped, and no two whitespace runs
# meet, so a failed match costs a bounded scan, never one that doubles per decorator or
# retries the name at every character it could give back.
JS_FIELD_RE = re.compile(
    rf"""\s*(?:@[\w.]{{1,100}}(?![\w.])(?:\s*\([^()]{{0,{_GAP}}}\))?\s*){{0,8}}"""
    r"""(?:(?:readonly|public|private|protected|declare|static|override)\s+){0,4}"""
    r"""(?:(["'])([^"'\n]{1,100})\1|([A-Za-z_$][\w$]{0,200})(?![\w$]))\s*(?:[?!]\s*)?:""")
DEFAULT_STORE = {"Mongoose schema": "schema", "Zod schema": "schema"}


def _js_skip(match: re.Match[str]) -> str:
    text = match.group(0)
    if text.startswith("/"):
        return re.sub(r"[^\n]", " ", text)
    return text


def _js_fields(code: str, start: int, nested: bool, budget: _Budget) -> list[tuple[str, int]]:
    """Property names and offsets in the object body that opens at `start`."""
    out: list[tuple[str, int]] = []
    depth = paren = bracket = 0
    seg = False
    i, end = start, budget.end(code, start)
    while i < end:
        c = code[i]
        if seg and not c.isspace():
            seg = False
            if paren == 0 and bracket == 0 and (depth == 1 or (nested and depth >= 1)):
                m = JS_FIELD_RE.match(code, i, end)
                if m:
                    group = 2 if m.group(2) else 3
                    out.append((m.group(group), m.start(group)))
        if c in "\"'`":
            close = i + 1
            while close < end and code[close] != c:
                close += 2 if code[close] == "\\" else 1
            i = close + 1
            continue
        if c == "{":
            depth += 1
            seg = True
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        elif c == "(":
            paren += 1
        elif c == ")":
            paren -= 1
        elif c == "[":
            bracket += 1
        elif c == "]":
            bracket -= 1
        elif c in ";,\n":
            seg = True
        i += 1
    budget.take(start, min(i, end))
    return out


def _js_structures(text: str, typescript: bool) -> list[_Struct]:
    code = JS_SKIP_RE.sub(_js_skip, text)
    lines = _Lines(code)
    budget = _Budget(code)
    found: list[tuple[int, _Struct]] = []
    for pattern, kind, persistent, nested, ts_only in JS_OPENERS:
        if ts_only and not typescript:
            continue
        for m in pattern.finditer(code):
            if budget.spent:
                break
            store = m.group(1) or DEFAULT_STORE.get(kind, kind)
            fields = [(n, lines.line(o))
                      for n, o in _js_fields(code, m.end() - 1, nested, budget)]
            found.append((m.start(), _Struct(store, kind, persistent, fields)))
    return [s for _, s in sorted(found, key=lambda x: x[0])]


# --- the scanner -----------------------------------------------------------------------------

class SensitiveDataScanner:
    name = NAME
    category = Category.data_handling

    def run(self, ctx: ScanContext) -> list[Finding]:
        raw = ctx.options.get("patterns", DEFAULT_SCANNER_OPTIONS[NAME]["patterns"])
        patterns = compile_patterns(raw)
        include_tests = bool(ctx.options.get("include_tests", False))
        # Source code (SQL included) and Prisma schemas only: data files (records, exports)
        # and configuration (JSON, YAML, XML, TOML, ...) are never opened.
        classes = {Classification.source, Classification.data}
        if include_tests:
            classes.add(Classification.test)
        out = SensitiveData(tool=ctx.tool, classes=patterns.labels(),
                            patterns_overridden=raw != bundled_patterns())
        not_read: dict[str, int] = {}
        hits: set[tuple[str, str, str, str, int]] = set()
        for rec in ctx.census.files:
            if rec.excluded or rec.classification not in classes or rec.bytes > MAX_FILE_BYTES:
                continue
            if not opens(rec.path, rec.language):
                continue
            if rec.classification == Classification.source and rec.language in UNREAD_LANGUAGES:
                not_read[rec.language] = not_read.get(rec.language, 0) + 1
            try:
                structs = self._structures(ctx.source_root, rec.path, out)
            except Exception:  # a parser broken by one file costs that file, not the pass
                out.unparsed.append(rec.path)
                continue
            if structs is None:
                continue
            out.files_read += 1
            out.structures_read += len({s.store.lower() for s in structs})
            for s in structs:
                for name, line in s.fields:
                    for key, matched in patterns.classify(name):
                        if (key, s.store, name, rec.path, line) in hits:
                            continue
                        hits.add((key, s.store, name, rec.path, line))
                        out.fields.append(SensitiveField(
                            data_class=key, field=name, store=s.store, store_kind=s.kind,
                            persistent=s.persistent, path=rec.path, line=line,
                            matched=matched))
        out.fields.sort(key=lambda f: (f.path, f.line, f.field, f.data_class))
        out.not_read = dict(sorted(not_read.items()))
        out.unparsed.sort()
        ctx.inventory = out
        return []

    def _structures(self, root: Path, path: str, out: SensitiveData) -> list[_Struct] | None:
        """The structures one file declares; None when it holds nothing this pass reads."""
        suffix = Path(path).suffix.lower()
        try:
            text = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        if suffix == ".prisma":
            return _prisma_structures(text)
        if suffix == ".sql":
            return _sql_structures(text, embedded=False)
        structs = _sql_structures(text, embedded=True) if CREATE_RE.search(text) \
            or "ALTER" in text.upper() else []
        if suffix in PYTHON_SUFFIXES:
            python = _python_structures(text)
            if python is None:
                out.unparsed.append(path)
            structs = (python or []) + structs
        elif suffix in TS_SUFFIXES or suffix in JS_SUFFIXES:
            structs = _js_structures(text, typescript=suffix in TS_SUFFIXES) + structs
        return structs or None
