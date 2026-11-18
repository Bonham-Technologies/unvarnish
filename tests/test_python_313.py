"""UNVAR-27: CI, the image and the package metadata name one Python line, 3.13, together."""

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout"
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_ci_image_and_metadata_agree_on_python_313():
    assert re.search(r"uv python install 3\.13\b", _read(".github/workflows/ci.yml"))
    base = [line for line in _read("Dockerfile").splitlines()
            if line.startswith("FROM python:")]
    assert len(base) == 1 and base[0].startswith("FROM python:3.13-slim-trixie@sha256:")
    meta = tomllib.loads(_read("pyproject.toml"))
    assert meta["project"]["requires-python"] == ">=3.13"
    assert meta["tool"]["ruff"]["target-version"] == "py313"
    classifiers = meta["project"]["classifiers"]
    assert "Programming Language :: Python :: 3.13" in classifiers
    assert "Programming Language :: Python :: 3.12" not in classifiers
    assert re.search(r'^requires-python = ">=3.13"$', _read("uv.lock"), re.M)


def test_tree_sitter_excludes_the_026_0_release_that_segfaults():
    # 0.26.0 segfaults freeing large parse trees; 0.26.1 passes the suite (docs/decisions.md).
    deps = tomllib.loads(_read("pyproject.toml"))["project"]["dependencies"]
    assert "tree-sitter>=0.23,!=0.26.0,<0.27" in deps
    assert re.search(r'name = "tree-sitter"\nversion = "(?!0\.26\.0")', _read("uv.lock"))


def test_no_supported_version_still_names_312():
    for rel in ("README.md", "CONTRIBUTING.md", "CLAUDE.md", "docs/operations.md",
                ".github/workflows/ci.yml", "Dockerfile", "pyproject.toml", "site/index.html"):
        assert "3.12" not in _read(rel), rel


def test_dependabot_does_not_propose_a_lone_python_line_bump():
    text = _read(".github/dependabot.yml")
    docker = text.split('package-ecosystem: "docker"', 1)[1].split("package-ecosystem:", 1)[0]
    assert re.search(
        r'dependency-name: "python"\s*\n\s*update-types: \["version-update:semver-minor"\]',
        docker,
    )
