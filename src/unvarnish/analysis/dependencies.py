from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from unvarnish.schemas.inventory import DependencyRecord, FileRecord

FRAMEWORK_HINTS: dict[str, str] = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "streamlit": "Streamlit",
    "gradio": "Gradio", "celery": "Celery", "sqlalchemy": "SQLAlchemy", "langchain": "LangChain",
    "react": "React", "next": "Next.js", "express": "Express", "vue": "Vue",
    "@angular/core": "Angular", "svelte": "Svelte", "nestjs": "NestJS", "@nestjs/core": "NestJS",
    "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber",
    "actix-web": "Actix Web", "axum": "Axum", "rocket": "Rocket", "tokio": "Tokio",
    "spring-boot-starter": "Spring Boot", "rails": "Rails", "laravel/framework": "Laravel",
}

PY_SPLIT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(.*)$")
GO_REQ_RE = re.compile(r"^\s*([\w./\-~]+)\s+(v[\w.+\-]+)")
POM_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
POM_EXCLUSIONS_RE = re.compile(r"<exclusions>.*?</exclusions>", re.DOTALL)


def _framework_for(name: str) -> str | None:
    key = name.lower()
    if key in FRAMEWORK_HINTS:
        return FRAMEWORK_HINTS[key]
    for hint, label in FRAMEWORK_HINTS.items():
        if ("/" in hint or "-" in hint) and hint in key:
            return label
    return None


def _py_requirement(line: str, manifest: str) -> DependencyRecord | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http")):
        return None
    m = PY_SPLIT_RE.match(line)
    if not m:
        return None
    name = re.split(r"\[", m.group(1), maxsplit=1)[0].lower()
    constraint = m.group(2).strip() or None
    return DependencyRecord(ecosystem="pypi", name=name, constraint=constraint, manifest=manifest)


def _parse_package_json(text: str, manifest: str) -> list[DependencyRecord]:
    data = json.loads(text)
    out = []
    for key, dev in (("dependencies", False), ("devDependencies", True)):
        for name, constraint in (data.get(key) or {}).items():
            out.append(DependencyRecord(ecosystem="npm", name=name, constraint=str(constraint),
                                        manifest=manifest, dev=dev))
    return out


def _table_constraint(spec: object) -> str | None:
    """A Poetry or Cargo dependency value as one constraint string: the version, or a marker
    for a local path, a workspace member, or a git source (with its pinned revision)."""
    if isinstance(spec, str):
        return spec
    if not isinstance(spec, dict):
        return None
    if spec.get("version"):
        return str(spec["version"])
    if spec.get("path"):
        return f"path:{spec['path']}"
    if spec.get("workspace"):
        return "workspace"
    if spec.get("git"):
        rev = spec.get("rev") or spec.get("tag")
        return f"git:{spec['git']}" + (f"#rev={rev}" if rev else "")
    return None


def _parse_pyproject(text: str, manifest: str) -> list[DependencyRecord]:
    data = tomllib.loads(text)
    out = []
    for req in data.get("project", {}).get("dependencies", []) or []:
        rec = _py_requirement(req, manifest)
        if rec:
            out.append(rec)
    for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
        for req in group:
            rec = _py_requirement(req, manifest)
            if rec:
                rec.dev = True
                out.append(rec)
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        out.append(DependencyRecord(ecosystem="pypi", name=name.lower(),
                                    constraint=_table_constraint(spec), manifest=manifest))
    return out


def _parse_go_mod(text: str, manifest: str) -> list[DependencyRecord]:
    out = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            candidate: str | None = stripped[len("require "):]
        else:
            candidate = stripped if in_block else None
        if candidate is None:
            continue
        m = GO_REQ_RE.match(candidate)
        if m:
            out.append(DependencyRecord(ecosystem="go", name=m.group(1), constraint=m.group(2),
                                        manifest=manifest))
    return out


def _parse_cargo(text: str, manifest: str) -> list[DependencyRecord]:
    data = tomllib.loads(text)
    out = []
    for table, dev in (("dependencies", False), ("dev-dependencies", True),
                       ("build-dependencies", True)):
        for name, spec in (data.get(table) or {}).items():
            out.append(DependencyRecord(ecosystem="cargo", name=name,
                                        constraint=_table_constraint(spec),
                                        manifest=manifest, dev=dev))
    return out


def _pom_tag(block: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.DOTALL)
    return m.group(1).strip() if m and m.group(1).strip() else None


def _parse_pom(text: str, manifest: str) -> list[DependencyRecord]:
    """One record per <dependency> block; a block without <version> is managed by a BOM or
    parent, so its constraint is None. Exclusions inside a block are not dependencies."""
    out = []
    for block in POM_BLOCK_RE.findall(text):
        block = POM_EXCLUSIONS_RE.sub("", block)
        group, artifact = _pom_tag(block, "groupId"), _pom_tag(block, "artifactId")
        if group and artifact:
            out.append(DependencyRecord(ecosystem="maven", name=f"{group}:{artifact}",
                                        constraint=_pom_tag(block, "version"),
                                        manifest=manifest))
    return out


def parse_manifests(
    source_root: Path, files: list[FileRecord]
) -> tuple[list[DependencyRecord], list[str], list[str]]:
    """Returns (dependencies, frameworks, failures).

    A malformed manifest is recorded as a failure, never raised.
    """
    deps: list[DependencyRecord] = []
    failures: list[str] = []
    for rec in files:
        if rec.excluded:
            continue
        name = Path(rec.path).name
        path = source_root / rec.path
        try:
            text = path.read_text(errors="replace", encoding="utf-8")
            if name == "package.json":
                deps += _parse_package_json(text, rec.path)
            elif name == "pyproject.toml":
                deps += _parse_pyproject(text, rec.path)
            elif name.startswith("requirements") and name.endswith(".txt"):
                deps += [
                    r for r in (_py_requirement(ln, rec.path) for ln in text.splitlines()) if r
                ]
            elif name == "go.mod":
                deps += _parse_go_mod(text, rec.path)
            elif name == "Cargo.toml":
                deps += _parse_cargo(text, rec.path)
            elif name == "pom.xml":
                deps += _parse_pom(text, rec.path)
        except Exception as exc:  # one bad manifest never kills a run
            failures.append(f"{rec.path}: could not parse manifest ({exc!r})")
    frameworks = sorted({fw for d in deps if (fw := _framework_for(d.name))})
    return deps, frameworks, failures
