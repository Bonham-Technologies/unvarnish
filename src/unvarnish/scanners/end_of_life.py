"""Runtimes, base images and frameworks past or near their end of life (UNVAR-43).

Versions come from the files that pin them (`.python-version`, `requires-python`, Poetry's
`python`, `Pipfile`, `setup.cfg` and `setup.py` `python_requires`, `runtime.txt`,
`package.json` engines, `.nvmrc` (an `lts/<codename>` too), `.tool-versions`, `go.mod`,
project files' TargetFramework, Dockerfile `FROM` tags, `.ruby-version`, the Gemfile's
`ruby`, `composer.json`) and from the framework dependencies the inventory parsed. Dates
come from the offline endoflife.date bundle (`unvarnish.analysis.eol`); without one the
scanner leaves a note and reports nothing. A bundle older than `max_data_age_days` leaves a
note too, and the findings are made from it as usual (UNVAR-59)."""

from __future__ import annotations

import calendar
import configparser
import json
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath

from unvarnish.analysis import eol
from unvarnish.analysis.languages import Classification
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.effort import rule_effort
from unvarnish.scanners.hardcoded_infra import scrub_text
from unvarnish.schemas.eol import EolBundle, EolCycle, EolProduct
from unvarnish.schemas.finding import Category, Evidence, Finding, Severity, Source

NAME = "end_of_life"
MAX_EVIDENCE = 25
MAX_BYTES = 1_000_000
MAX_SHOWN = 80  # characters of a version as written that an evidence note repeats
DEFAULT_WARN_MONTHS = 6
MAX_WARN_MONTHS = 120
DEFAULT_MAX_DATA_AGE_DAYS = 90
MAX_DATA_AGE_DAYS = 3650
# The old-data note starts "<NAME>: end-of-life data dated <date> is <_age_phrase>"; the
# findings document's summary row reads the phrase back (data_age_warning), so the two agree.
AGE_NOTE_RE = re.compile(rf"^{NAME}: end-of-life data dated \d{{4}}-\d{{2}}-\d{{2}} is "
                         r"(\d+ days? old, older than the \d+-day limit)")
Version = tuple[int, ...]

_OP = r"===|==|>=|<=|~=|!=|>|<|=|\^|~"
CLAUSE_RE = re.compile(rf"^(?P<op>{_OP})?v?(?P<ver>\d+(?:\.\d+)*)(?P<wild>(?:\.[xX*])*)"
                       r"(?:[-+_].*)?$")
OP_SPACE_RE = re.compile(rf"({_OP})\s+")
LOWER_BOUND_OPS = {">=", ">", "~=", "^", "~"}
NO_LOWER_BOUND_OPS = {"<", "<=", "!="}
LEADING_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")
CODENAME_RE = re.compile(r"^([a-z]+)(?:$|[-_.])")

FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.I)
# Docker image (last path component) to product. mcr.microsoft.com/dotnet/* is matched apart.
IMAGES = {"python": "python", "node": "nodejs", "golang": "go", "ruby": "ruby", "php": "php",
          "postgres": "postgresql", "mysql": "mysql", "ubuntu": "ubuntu", "debian": "debian",
          "alpine": "alpine-linux", "openjdk": "eclipse-temurin",
          "eclipse-temurin": "eclipse-temurin"}
TFM_RE = re.compile(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>")
NET_TFM_RE = re.compile(r"^net(coreapp)?(\d+)\.(\d+)")
PROJECT_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}
GO_RE = re.compile(r"^\s*go\s+(\d+\.\d+(?:\.\d+)?)\s*(?://.*)?$")
TOOLCHAIN_RE = re.compile(r"^\s*toolchain\s+go(\d+\.\d+(?:\.\d+)?)")
# Framework dependencies the inventory parses, by (ecosystem, name), to product.
DEPENDENCY_PRODUCTS = {("pypi", "django"): "django", ("npm", "react"): "react",
                       ("npm", "next"): "nextjs", ("npm", "vue"): "vue",
                       ("npm", "@angular/core"): "angular"}
SPRING_BOOT_GROUP = "org.springframework.boot:"
VERSION_FILES = {".python-version": ("python", ""), ".nvmrc": ("nodejs", ""),
                 ".ruby-version": ("ruby", "ruby-"), "runtime.txt": ("python", "python-")}
MANIFESTS = {"pyproject.toml", "package.json", "composer.json", "go.mod", "Pipfile",
             "setup.cfg", "setup.py", ".tool-versions", "Gemfile"}
NVM_LTS_RE = re.compile(r"lts/([a-z]+)")  # lts/fermium; lts/* and lts/-1 float
ASDF_LTS_RE = re.compile(r"lts-([a-z]+)")  # the asdf nodejs plugin's lts-fermium
# Node.js LTS codenames to their major version. endoflife.date carries no Node.js codenames
# (its releases have codename null), so the table lives here; a codename never changes once
# Node.js assigns it. A newer codename (after Lithium, 26) is skipped until it is added.
NODE_LTS_CODENAMES = {"argon": 4, "boron": 6, "carbon": 8, "dubnium": 10, "erbium": 12,
                      "fermium": 14, "gallium": 16, "hydrogen": 18, "iron": 20, "jod": 22,
                      "krypton": 24, "lithium": 26}
# asdf and mise plugin names in .tool-versions to product; the first version is the default.
TOOL_VERSIONS = {"python": "python", "nodejs": "nodejs", "node": "nodejs", "ruby": "ruby"}
# setup.py is never run: only a literal python_requires="..." keyword is read.
SETUP_PY_RE = re.compile(r"""\bpython_requires\s*=\s*(['"])([^'"\n]*)\1""")
# Gemfile `ruby '2.6.3'` or `ruby('>= 2.6', '< 3')`: the leading string arguments only.
# Possessive whitespace, so a long run of spaces is not split two ways (no backtracking).
GEMFILE_RUBY_RE = re.compile(
    r"""^\s*+ruby\b\s*+\(?\s*+((['"])[^'"\n]*\2(?:\s*,\s*(['"])[^'"\n]*\3)*)""")
QUOTED_RE = re.compile(r"""['"]([^'"]*)['"]""")
# `ruby '2.6.3', engine: 'jruby'` (or `:engine => 'jruby'`) is another implementation.
GEMFILE_ENGINE_RE = re.compile(r"\bengine\b")


def lowest_version(spec: str) -> tuple[Version | None, bool]:
    """(lowest version the spec allows, whether the spec is a range). `>=3.9,<4`, `^7.4|^8.0`
    and `18.x` are ranges; `3.9`, `==3.9.7` and `v18.17.0` are not. None when the spec has no
    lower bound (`<4`, `*`) or names no version (`latest`, `lts/hydrogen`)."""
    spec = OP_SPACE_RE.sub(r"\1", spec.strip())
    lows: list[Version] = []
    ranged = False
    for alternative in re.split(r"\|\|?", spec):
        for clause in re.split(r"[,\s]+", alternative.strip()):
            if clause in ("*", "x", "X"):
                ranged = True
                continue
            m = CLAUSE_RE.match(clause)
            if not m:
                continue
            op = m.group("op") or ""
            if op in NO_LOWER_BOUND_OPS:
                ranged = True
                continue
            ranged = ranged or op in LOWER_BOUND_OPS or bool(m.group("wild"))
            lows.append(tuple(int(p) for p in m.group("ver").split(".")))
    if len(lows) > 1:
        ranged = True
    return (min(lows) if lows else None), ranged


def _shown(text: str) -> str:
    """Repository text as an evidence note may repeat it: secrets and URL credentials
    redacted, on one line, at most MAX_SHOWN characters."""
    one_line = scrub_text(" ".join(text.split()))
    return one_line if len(one_line) <= MAX_SHOWN else one_line[:MAX_SHOWN - 1] + "…"


def _whole_number(value: object, default: int, maximum: int) -> int:
    """The value as a whole number from 0 to maximum, or the default when it is not one."""
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if 0 <= number <= maximum else default


def warn_months(value: object) -> int:
    """The `warn_months` option, or the default when it is not a whole number of months
    from 0 to MAX_WARN_MONTHS."""
    return _whole_number(value, DEFAULT_WARN_MONTHS, MAX_WARN_MONTHS)


def max_data_age_days(value: object) -> int:
    """The `max_data_age_days` option, or the default when it is not a whole number of days
    from 0 to MAX_DATA_AGE_DAYS."""
    return _whole_number(value, DEFAULT_MAX_DATA_AGE_DAYS, MAX_DATA_AGE_DAYS)


def _age_phrase(age: int, limit: int) -> str:
    return f"{age} day{'' if age == 1 else 's'} old, older than the {limit}-day limit"


def data_age_note(fetched: date, today: date, limit: int) -> str | None:
    """A note when the bundle was fetched more than `limit` days before today, else None.
    It only informs: the findings are made from the bundle all the same."""
    age = (today - fetched).days
    if age <= limit:
        return None
    return (f"{NAME}: end-of-life data dated {fetched.isoformat()} is "
            f"{_age_phrase(age, limit)} (max_data_age_days); releases and end-of-life dates "
            f"published since then are missing, so a newer release is skipped and a release "
            f"whose end-of-life date was set or moved since then can be reported wrongly. The "
            f"findings still use this data (run `unvarnish eol refresh` while online, or "
            f"rebuild the site kit, then rerun)")


def _numbers(text: str) -> Version | None:
    m = re.fullmatch(r"\d+(?:\.\d+)*", text)
    return tuple(int(p) for p in text.split(".")) if m else None


def match_cycle(product: EolProduct, version: Version | None,
                codename: str | None = None) -> EolCycle | None:
    """The cycle whose name is the longest leading part of the version (3.9.7 is cycle 3.9;
    6.0 is .NET 6), or whose codename's first word is the codename (buster, focal)."""
    if codename:
        for c in product.cycles:
            if c.codename and c.codename.split()[0].lower() == codename:
                return c
        return None
    best: tuple[int, EolCycle] | None = None
    for c in product.cycles:
        parts = _numbers(c.cycle)
        if version and parts and version[:len(parts)] == parts:
            if best is None or len(parts) > best[0]:
                best = (len(parts), c)
    return best[1] if best else None


def add_months(day: date, months: int) -> date:
    month = day.month - 1 + months
    year, month = day.year + month // 12, month % 12 + 1
    return date(year, month, min(day.day, calendar.monthrange(year, month)[1]))


def cycle_status(cycle: EolCycle, today: date, warn_until: date) -> str | None:
    """'past' (end of life on or before today), 'near' (by warn_until), or None."""
    if cycle.eol_from is not None:
        if cycle.eol_from <= today:
            return "past"
        return "near" if cycle.eol_from <= warn_until else None
    return "past" if cycle.is_eol else None


@dataclass
class Declared:
    """One place a version is pinned."""
    product: str
    spec: str  # the version as written, for the evidence note
    what: str  # where it is written: "FROM python:3.9-slim", "requires-python >=3.9"
    path: str
    line: int | None
    version: Version | None = None
    codename: str | None = None
    ranged: bool = False

    @classmethod
    def from_spec(cls, product: str, spec: str, what: str, path: str,
                  line: int | None) -> Declared:
        version, ranged = lowest_version(spec)
        return cls(product, spec, what, path, line, version, None, ranged)


def _line_of(lines: list[str], *needles: str) -> int | None:
    """The first line holding the last needle, after lines holding each earlier one."""
    start = 0
    found = None
    for needle in needles:
        found = next((i for i in range(start, len(lines)) if needle in lines[i]), None)
        if found is None:
            return None
        start = found + 1
    return None if found is None else found + 1


def _key_line(lines: list[str], header: str, key: str) -> int | None:
    """The first line that sets `key` (`key = …` or `key: …`) after the line `header`."""
    start = next((i + 1 for i, line in enumerate(lines) if line.strip() == header), None)
    if start is None:
        return None
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*[=:]")
    return next((i + 1 for i in range(start, len(lines)) if key_re.match(lines[i])), None)


def _first_line(text: str) -> tuple[str, int] | None:
    for n, line in enumerate(text.splitlines(), start=1):
        value = line.split("#", 1)[0].strip()
        if value:
            return value, n
    return None


def _docker(path: str, text: str) -> list[Declared]:
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = FROM_RE.match(line)
        if not m or "$" in m.group(1):
            continue
        ref = m.group(1).split("@", 1)[0]
        repo, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
        parts = repo.lower().split("/")
        if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            parts = parts[1:]  # a registry host: never repeated in the report
        name = parts[-1]
        product = "dotnet" if "dotnet" in parts[:-1] else IMAGES.get(name)
        if not product or not tag:
            continue
        what = f"FROM {name}:{tag}"
        v = LEADING_VERSION_RE.match(tag)
        if v:
            out.append(Declared(product, tag, what, path, n,
                                tuple(int(p) for p in v.group(1).split("."))))
        elif c := CODENAME_RE.match(tag.lower()):
            out.append(Declared(product, tag, what, path, n, codename=c.group(1)))
    return out


def _project_file(path: str, text: str) -> list[Declared]:
    out = []
    for m in TFM_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        for tfm in m.group(1).split(";"):
            t = NET_TFM_RE.match(tfm.strip().lower())
            if t and (t.group(1) or int(t.group(2)) >= 5):  # net4x is .NET Framework
                out.append(Declared("dotnet", tfm.strip(),
                                    f"TargetFramework {_shown(tfm)}",
                                    path, line, (int(t.group(2)), int(t.group(3)))))
    return out


def _go_mod(path: str, text: str) -> list[Declared]:
    go = toolchain = None
    for n, line in enumerate(text.splitlines(), start=1):
        if m := TOOLCHAIN_RE.match(line):
            toolchain = Declared.from_spec("go", m.group(1), f"toolchain go{m.group(1)}",
                                           path, n)
        elif m := GO_RE.match(line):
            # the go directive is the minimum version the module accepts
            go = Declared.from_spec("go", f">={m.group(1)}", f"go {m.group(1)}", path, n)
    chosen = toolchain or go
    return [chosen] if chosen else []


def _toml_value(data: object, *keys: str) -> str | None:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data if isinstance(data, str) else None


def _pyproject(path: str, text: str) -> list[Declared]:
    """`[project] requires-python` and Poetry's `[tool.poetry.dependencies] python`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    lines = text.splitlines()
    out = []
    if spec := _toml_value(data, "project", "requires-python"):
        out.append(Declared.from_spec("python", spec, f"requires-python {_shown(spec)}", path,
                                      _line_of(lines, "requires-python")))
    if spec := _toml_value(data, "tool", "poetry", "dependencies", "python"):
        out.append(Declared.from_spec(
            "python", spec, f"tool.poetry.dependencies.python {_shown(spec)}", path,
            _key_line(lines, "[tool.poetry.dependencies]", "python")))
    return out


def _pipfile(path: str, text: str) -> list[Declared]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    for key in ("python_full_version", "python_version"):
        if spec := _toml_value(data, "requires", key):
            return [Declared.from_spec("python", spec, f"requires.{key} {_shown(spec)}", path,
                                       _key_line(text.splitlines(), "[requires]", key))]
    return []


def _setup_cfg(path: str, text: str) -> list[Declared]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    spec = parser.get("options", "python_requires", fallback=None)
    if not spec:
        return []
    return [Declared.from_spec("python", spec, f"options.python_requires {_shown(spec)}", path,
                               _key_line(text.splitlines(), "[options]", "python_requires"))]


def _setup_py(path: str, text: str) -> list[Declared]:
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.lstrip().startswith("#") and (m := SETUP_PY_RE.search(line)):
            spec = m.group(2)
            return [Declared.from_spec("python", spec, f"python_requires {_shown(spec)}", path,
                                       n)]
    return []


def _tool_versions(path: str, text: str) -> list[Declared]:
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[0] in TOOL_VERSIONS:
            product, spec = TOOL_VERSIONS[fields[0]], fields[1]
            what = f".tool-versions {_shown(' '.join(fields[:2]))}"
            if product == "nodejs" and (lts := ASDF_LTS_RE.fullmatch(spec.lower())):
                out += _node_lts(spec, what, path, n, lts.group(1))
            else:
                out.append(Declared.from_spec(product, spec, what, path, n))
    return out


def _node_lts(spec: str, what: str, path: str, line: int, codename: str) -> list[Declared]:
    """An LTS line named by its codename (lts/fermium, lts-fermium): Node.js 14."""
    major = NODE_LTS_CODENAMES.get(codename)
    return [Declared("nodejs", spec, what, path, line, version=(major,))] if major else []


def _gemfile(path: str, text: str) -> list[Declared]:
    for n, line in enumerate(text.splitlines(), start=1):
        if m := GEMFILE_RUBY_RE.match(line):
            if GEMFILE_ENGINE_RE.search(line, m.end()):
                return []  # JRuby or TruffleRuby, not MRI's end-of-life dates
            written = ", ".join(QUOTED_RE.findall(m.group(1)))
            # Bundler's pessimistic `~> 2.6.0` has the lower bound of PEP 440's `~=`
            return [Declared.from_spec("ruby", written.replace("~>", "~="),
                                       f"ruby {_shown(written)}", path, n)]
    return []


def _json_value(text: str, *keys: str) -> str | None:
    try:
        node = json.loads(text)
    except (ValueError, RecursionError):
        return None
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, str) else None


def _is_dockerfile(name: str) -> bool:
    return (name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile.")
            or name.lower().endswith(".dockerfile"))


def _may_declare(path: str) -> bool:
    """Whether the file's name is one `_declared_in` reads, so other files are never read."""
    p = PurePosixPath(path)
    return (p.name in VERSION_FILES or p.name in MANIFESTS
            or p.suffix.lower() in PROJECT_SUFFIXES or _is_dockerfile(p.name))


def _declared_in(path: str, text: str) -> list[Declared]:
    name = PurePosixPath(path).name
    if name in VERSION_FILES:
        first = _first_line(text)
        if not first:
            return []
        value, n = first
        product, prefix = VERSION_FILES[name]
        # runtime.txt must say "python-3.x"; .ruby-version is "3.2.2" (rbenv, chruby, asdf) or
        # "ruby-3.2.2" (rvm), and "jruby-…" is not a version, so the parser skips it.
        if name == "runtime.txt" and not value.startswith(prefix):
            return []
        spec = value.removeprefix(prefix)
        what = f"{name} {_shown(value)}"
        if name == ".nvmrc" and (lts := NVM_LTS_RE.fullmatch(spec.lower())):
            return _node_lts(spec, what, path, n, lts.group(1))
        return [Declared.from_spec(product, spec, what, path, n)]
    if name == "pyproject.toml":
        return _pyproject(path, text)
    if name == "Pipfile":
        return _pipfile(path, text)
    if name == "setup.cfg":
        return _setup_cfg(path, text)
    if name == "setup.py":
        return _setup_py(path, text)
    if name == ".tool-versions":
        return _tool_versions(path, text)
    if name == "Gemfile":
        return _gemfile(path, text)
    if name == "package.json":
        spec = _json_value(text, "engines", "node")
        return [Declared.from_spec("nodejs", spec, f"engines.node {_shown(spec)}", path,
                                   _line_of(text.splitlines(), '"engines"', '"node"'))
                ] if spec else []
    if name == "composer.json":
        spec = _json_value(text, "require", "php")
        return [Declared.from_spec("php", spec, f"require.php {_shown(spec)}", path,
                                   _line_of(text.splitlines(), '"require"', '"php"'))
                ] if spec else []
    if name == "go.mod":
        return _go_mod(path, text)
    if PurePosixPath(path).suffix.lower() in PROJECT_SUFFIXES:
        return _project_file(path, text)
    if _is_dockerfile(name):
        return _docker(path, text)
    return []


class EndOfLifeScanner:
    name = NAME
    category = Category.dependency

    def __init__(self, today: date | None = None, bundle: Path | None = None) -> None:
        self._today = today
        self._bundle = bundle
        self.notes: list[str] = []

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.notes = []
        bundle, why = eol.load_bundle(self._bundle)
        if bundle is None:
            self.notes.append(
                f"{NAME}: {why}; runtime and framework versions were not checked against "
                f"end-of-life dates (run `unvarnish eol refresh` while online, or set "
                f"{eol.DIR_ENV} to a folder holding {eol.BUNDLE_NAME}, then rerun)")
            return []
        today = self._today or datetime.now(UTC).date()
        limit = max_data_age_days(ctx.options.get("max_data_age_days",
                                                  DEFAULT_MAX_DATA_AGE_DAYS))
        if note := data_age_note(bundle.fetched, today, limit):
            self.notes.append(note)
        months = warn_months(ctx.options.get("warn_months", DEFAULT_WARN_MONTHS))
        warn_until = add_months(today, months)

        groups: dict[tuple[str, str, str], list[Declared]] = defaultdict(list)
        for d in self._declarations(ctx):
            product = bundle.products.get(d.product)
            cycle = match_cycle(product, d.version, d.codename) if product else None
            status = cycle_status(cycle, today, warn_until) if cycle else None
            if cycle and status:
                groups[(d.product, cycle.cycle, status)].append(d)
        return [self._finding(ctx, bundle, product, cycle_name, status, decls, today,
                              warn_until, months)
                for (product, cycle_name, status), decls in sorted(groups.items())]

    def _declarations(self, ctx: ScanContext) -> list[Declared]:
        out: list[Declared] = []
        tests = set()
        for rec in ctx.census.files:
            if rec.classification == Classification.test:
                tests.add(rec.path)
            if (rec.excluded or rec.classification in (Classification.test,
                                                       Classification.binary)
                    or rec.bytes > MAX_BYTES or not _may_declare(rec.path)):
                continue
            try:
                text = (ctx.source_root / rec.path).read_text(encoding="utf-8",
                                                              errors="replace")
            except OSError:
                continue
            try:
                out += _declared_in(rec.path, text)
            except Exception:  # one odd file must not silence the scan
                continue
        for dep in ctx.dependencies.dependencies:
            product = DEPENDENCY_PRODUCTS.get((dep.ecosystem, dep.name))
            if dep.ecosystem == "maven" and dep.name.startswith(SPRING_BOOT_GROUP):
                product = "spring-boot"
            if not product or dep.dev or not dep.constraint or dep.manifest in tests:
                continue
            spec = scrub_text(dep.constraint)
            out.append(Declared.from_spec(product, spec, f"{dep.name} {spec}", dep.manifest,
                                          None))
        return out

    def _finding(self, ctx: ScanContext, bundle: EolBundle, slug: str, cycle_name: str,
                 status: str, decls: list[Declared], today: date, warn_until: date,
                 months: int) -> Finding:
        product = bundle.products[slug]
        cycle = next(c for c in product.cycles if c.cycle == cycle_name)
        release = f"{product.label} {cycle_name}"
        dated = f"endoflife.date data dated {bundle.fetched.isoformat()}"
        when = cycle.eol_from.isoformat() if cycle.eol_from else None
        decls = sorted(decls, key=lambda d: (d.path, d.line or 0, d.what))
        evidence = []
        for d in decls[:MAX_EVIDENCE]:
            parts = [d.what]
            if d.ranged and d.version:
                lowest = ".".join(str(p) for p in d.version)
                parts.append(f"a range, judged by its lowest allowed version, {lowest}")
            parts += [f"end of life {when or 'date not published'}", dated]
            evidence.append(Evidence(path=d.path, line_start=d.line, line_end=d.line,
                                     note="; ".join(parts)))
        places = sorted({d.path for d in decls})
        where = (f"It is declared in {places[0]}." if len(places) == 1 else
                 f"It is declared in {len(places)} places: {', '.join(places)}.")
        if any(d.ranged for d in decls):
            where += (" A version range is judged by its lowest version, because the tool "
                      "can still be installed and run on it.")
        if status == "past":
            title = f"{release} is past end of life"
            severity = Severity.high
            lead = (f"{release} reached end of life on {when}" if when else
                    f"{release} is past end of life (no end-of-life date is published)")
            summary = (f"{lead}: its maintainers no longer fix bugs or security issues in "
                       f"it. {where} Dates are from {dated}.")
            impact = ("Security flaws found from now on in this release are not fixed "
                      "upstream, so the tool accumulates known vulnerabilities, and libraries "
                      "drop support for it, which blocks routine upgrades.")
        else:
            title = f"{release} is near end of life"
            severity = Severity.medium
            summary = (f"{release} reaches end of life on {when}, within {months} months of "
                       f"{today.isoformat()}: after that its maintainers no longer fix bugs "
                       f"or security issues in it. {where} Dates are from {dated}.")
            impact = ("Within months this release stops receiving security fixes; an "
                      "upgrade planned now avoids running unpatched.")
        supported = next((c.cycle for c in product.cycles
                          if cycle_status(c, today, warn_until) is None), None)
        remediation = ("Move to a release its maintainers still support, test the tool on it, "
                       "and update every place listed below.")
        if supported:
            remediation += f" Supported releases include {product.label} {supported}."
        return Finding(
            tool=ctx.tool, category=self.category, severity=severity, title=title,
            summary=summary, impact=impact, remediation=remediation, evidence=evidence,
            source=Source.scanner, scanner=self.name,
            tags=["end-of-life", f"{status}-eol", f"eol:{slug}", f"cycle:{cycle_name}"],
            **rule_effort(ctx, self.name, status),
        )


def eol_counts(findings: list[Finding]) -> dict[str, int]:
    """Past and near end-of-life findings, for the findings document's row."""
    mine = [f for f in findings if f.scanner == NAME]
    return {"past": sum("past-eol" in f.tags for f in mine),
            "near": sum("near-eol" in f.tags for f in mine)}


def data_age_warning(notes: list[str]) -> str | None:
    """"200 days old, older than the 90-day limit" from the scan's old-data note, for the
    findings document's row; None when the data was within the limit."""
    for note in notes:
        if m := AGE_NOTE_RE.match(note):
            return m.group(1)
    return None
