"""Dependency licences (UNVAR-93): joining osv-scanner's packages to the declared
dependencies, and evaluating SPDX licence expressions against an allowlist.

Licences come from deps.dev through osv-scanner in online mode only; nothing here invents
one. The allowlist is Unvarnish's own (`scanners.dependencies.licences`)."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath

from unvarnish.schemas.inventory import DependencyRecord

# osv-scanner's ecosystem names, mapped to the manifest parser's (analysis/dependencies.py)
OSV_ECOSYSTEMS = {"pypi": "pypi", "npm": "npm", "crates.io": "cargo", "go": "go",
                  "maven": "maven"}
# What deps.dev reports for a licence it cannot name: not a licence, so "not known".
UNKNOWN_LICENCES = {"", "unknown", "non-standard", "noassertion", "none"}
# Licences whose terms can reach the code that uses the package when it is distributed. An
# expression that cannot be satisfied without one of them is a medium finding, any other
# licence outside the allowlist a low one.
COPYLEFT_RE = re.compile(r"^(?:A?GPL|LGPL|MPL|EPL|EUPL|CDDL|OSL|SSPL|CPAL|RPL|CC-BY-SA|"
                         r"CC-BY-NC|Sleepycat|QPL|CECILL(?!-B|-C))", re.I)
TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def ecosystem(name: str) -> str:
    """The manifest parser's name for an osv-scanner ecosystem (`PyPI` -> `pypi`)."""
    return OSV_ECOSYSTEMS.get(name.lower(), name.lower())


def normal_name(eco: str, name: str) -> str:
    """A package name as registries compare it: PEP 503 for PyPI, case-blind elsewhere."""
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def package_key(eco: str, name: str, manifest: str) -> tuple[str, str, str]:
    """(ecosystem, name, folder): a lockfile beside a manifest resolves that manifest's
    dependencies, so a package and a record join on their folder, not their file."""
    eco = ecosystem(eco)
    return eco, normal_name(eco, name), PurePosixPath(manifest or ".").parent.as_posix()


def attach_licences(records: Iterable[DependencyRecord],
                    packages: Iterable[dict]) -> list[DependencyRecord]:
    """The records with the licences of the packages osv-scanner resolved for them; a record
    no package matches keeps None (not known), never a guess."""
    by_key: dict[tuple[str, str, str], list[str]] = {}
    for p in packages:
        found = by_key.setdefault(package_key(p["ecosystem"], p["name"], p["manifest"]), [])
        found += [lic for lic in p.get("licences") or [] if lic not in found]
    out = []
    for r in records:
        key = package_key(r.ecosystem, r.name, r.manifest)
        out.append(r.model_copy(update={"licences": list(by_key[key])})
                   if key in by_key else r)
    return out


def expression(licences: list[str]) -> str | None:
    """One SPDX expression for a package's licences (all of them apply), or None when deps.dev
    knows none."""
    known = [lic.strip() for lic in licences if lic.strip().lower() not in UNKNOWN_LICENCES]
    if not known or len(known) < len([x for x in licences if x.strip()]):
        return None
    if len(known) == 1:
        return known[0]
    return " AND ".join(f"({lic})" if " " in lic else lic for lic in known)


def satisfied(expr: str, ok: Callable[[str], bool]) -> bool:
    """Whether an SPDX licence expression can be met using only licences `ok` accepts: any
    branch of an OR, every part of an AND; `X WITH exception` is accepted when the whole of
    it or X is. A malformed expression is never satisfied."""
    tokens = TOKEN_RE.findall(expr)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end")
        pos += 1
        return tokens[pos - 1]

    def atom() -> bool:
        tok = take()
        if tok == "(":
            value = either()
            if take() != ")":
                raise ValueError("unbalanced")
            return value
        if tok == ")" or tok.upper() in ("AND", "OR", "WITH"):
            raise ValueError(f"unexpected {tok}")
        if (peek() or "").upper() == "WITH":
            take()
            exception = take()
            if exception in ("(", ")") or exception.upper() in ("AND", "OR", "WITH"):
                raise ValueError(f"no exception after WITH: {exception}")
            return ok(f"{tok} WITH {exception}") or ok(tok)
        return ok(tok)

    def both() -> bool:
        value = atom()
        while (peek() or "").upper() == "AND":
            take()
            value = atom() and value
        return value

    def either() -> bool:
        value = both()
        while (peek() or "").upper() == "OR":
            take()
            value = both() or value
        return value

    try:
        value = either()
    except ValueError:
        return False
    return value if pos == len(tokens) else False


def copyleft(expr: str) -> bool:
    """Whether the expression cannot be met without a copyleft licence."""
    return not satisfied(expr, lambda lic: not COPYLEFT_RE.match(lic))


def cyclonedx_licences(licences: list[str]) -> list[dict]:
    """A CycloneDX `licenses` value, as deps.dev declared it: one SPDX expression when every
    licence is a known one, otherwise each licence by name."""
    expr = expression(licences)
    if expr is not None and satisfied(expr, lambda lic: True):
        return [{"expression": expr, "acknowledgement": "declared"}]
    return [{"license": {"name": lic, "acknowledgement": "declared"}}
            for lic in licences if lic.strip()]
