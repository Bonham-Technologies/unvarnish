import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.analysis import eol
from unvarnish.analysis.dependencies import parse_manifests
from unvarnish.artifacts import read_artifact
from unvarnish.config import DEFAULT_SCANNER_OPTIONS
from unvarnish.phases.base import PhaseRunner, PhaseStatus, build_context
from unvarnish.phases.inventory import InventoryPhase, census_files
from unvarnish.scanners import builtin_scanners
from unvarnish.scanners.base import ScanContext
from unvarnish.scanners.end_of_life import EndOfLifeScanner, lowest_version
from unvarnish.schemas.finding import Effort, Severity
from unvarnish.schemas.git import GitStats
from unvarnish.schemas.inventory import Census, CensusTotals, Dependencies, Metrics
from unvarnish.schemas.scan import ScannerFindings

BUNDLE_DIR = Path(__file__).parent / "data" / "eol"
BUNDLE = BUNDLE_DIR / "endoflife.json"
TODAY = date(2026, 11, 10)
DATA_DATE = "2026-11-01"  # the fixture bundle's fetch date

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
</Project>
"""


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


def _ctx(root: Path, **options) -> ScanContext:
    files = census_files(root)
    deps, _, _ = parse_manifests(root, files)
    return ScanContext(tool="t", source_root=root,
                       census=Census(tool="t", files=files, totals=CensusTotals()),
                       metrics=Metrics(tool="t", files=[]),
                       git=GitStats(tool="t", available=False),
                       dependencies=Dependencies(tool="t", dependencies=deps),
                       options={**DEFAULT_SCANNER_OPTIONS["end_of_life"], **options})


def _scan(root: Path, files: dict[str, str], *, bundle: Path = BUNDLE, today: date = TODAY,
          **options):
    scanner = EndOfLifeScanner(today=today, bundle=bundle)
    return scanner.run(_ctx(_write(root, files), **options)), scanner


def _by_title(findings) -> dict:
    return {f.title: f for f in findings}


# --- acceptance 1: past end of life is high, with its date; a supported runtime is clean ----

def test_eol_runtimes_are_high_with_their_dates(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "Dockerfile": "FROM python:3.9-slim\nRUN pip install -r requirements.txt\n",
        "web/package.json": json.dumps({"name": "web", "engines": {"node": "18"}}, indent=2),
        "api/Api.csproj": CSPROJ,
    })
    titles = _by_title(found)
    assert set(titles) == {"Python 3.9 is past end of life",
                           "Node.js 18 is past end of life",
                           "Microsoft .NET 6 is past end of life"}
    assert all(f.severity == Severity.high for f in found)
    assert scanner.notes == []

    py = titles["Python 3.9 is past end of life"]
    assert "2025-10-31" in py.summary
    assert py.evidence[0].path == "Dockerfile" and py.evidence[0].line_start == 1
    assert "FROM python:3.9-slim" in py.evidence[0].note
    assert f"endoflife.date data dated {DATA_DATE}" in py.evidence[0].note
    assert py.scanner == "end_of_life" and "end-of-life" in py.tags
    assert py.effort == Effort.L and py.effort_note  # UNVAR-42 band

    node = titles["Node.js 18 is past end of life"]
    assert "2025-04-30" in node.summary
    assert node.evidence[0].path == "web/package.json" and node.evidence[0].line_start == 4
    assert "engines.node 18" in node.evidence[0].note

    net = titles["Microsoft .NET 6 is past end of life"]
    assert "2024-11-12" in net.summary
    assert net.evidence[0].path == "api/Api.csproj" and net.evidence[0].line_start == 3
    assert "Supported releases include Microsoft .NET 10" in net.remediation


def test_supported_python_gives_no_finding(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "Dockerfile": "FROM python:3.13-slim\n",
        ".python-version": "3.13.1\n",
        "pyproject.toml": '[project]\nname = "x"\nrequires-python = ">=3.13"\n',
    })
    assert found == [] and scanner.notes == []


def test_eol_within_six_months_is_medium(tmp_path: Path):
    # Node.js 22 ends 2027-04-30, inside six months of TODAY; 24 ends in 2028.
    found, _ = _scan(tmp_path, {".nvmrc": "v22.11.0\n", "app/.nvmrc": "24\n"})
    assert [(f.title, f.severity) for f in found] == [
        ("Node.js 22 is near end of life", Severity.medium)]
    assert "2027-04-30" in found[0].summary
    # a shorter window puts it outside
    assert _scan(tmp_path / "b", {".nvmrc": "22\n"}, warn_months=3)[0] == []


def test_today_decides_not_the_fetch_date(tmp_path: Path):
    files = {".nvmrc": "22\n"}
    assert _scan(tmp_path / "a", files, today=date(2026, 1, 1))[0] == []
    later, _ = _scan(tmp_path / "b", files, today=date(2027, 5, 1))
    assert [f.severity for f in later] == [Severity.high]


# --- acceptance 2: no bundle is one note, never a failure ----------------------------------

def test_missing_bundle_is_one_note(tmp_path: Path):
    found, scanner = _scan(tmp_path, {"Dockerfile": "FROM python:3.9\n"},
                           bundle=tmp_path / "nowhere" / "endoflife.json")
    assert found == []
    assert len(scanner.notes) == 1
    assert scanner.notes[0].startswith("end_of_life: no end-of-life data bundle")
    assert "unvarnish eol refresh" in scanner.notes[0]
    assert str(tmp_path) not in scanner.notes[0]  # no consultant paths in a client report


@pytest.mark.parametrize("body", ["not json", '{"format": 99, "fetched": "2026-01-01"}',
                                  '{"format": 1}'])
def test_unreadable_bundle_is_one_note(tmp_path: Path, body: str):
    bad = tmp_path / "eol" / "endoflife.json"
    _write(tmp_path, {"eol/endoflife.json": body})
    found, scanner = _scan(tmp_path / "src", {"Dockerfile": "FROM python:3.9\n"}, bundle=bad)
    assert found == []
    assert len(scanner.notes) == 1 and "unreadable" in scanner.notes[0]
    assert eol.bundle_date(bad) is None


def test_notes_reset_between_runs(tmp_path: Path):
    scanner = EndOfLifeScanner(today=TODAY, bundle=tmp_path / "none.json")
    ctx = _ctx(_write(tmp_path / "src", {"a.py": "x = 1\n"}))
    scanner.run(ctx)
    scanner.run(ctx)
    assert len(scanner.notes) == 1


# --- acceptance 4: a range is judged by its lowest allowed version -------------------------

def test_range_is_judged_by_lowest_version_and_says_so(tmp_path: Path):
    found, _ = _scan(tmp_path, {
        "pyproject.toml": '[project]\nname = "x"\nrequires-python = ">=3.9"\n'})
    assert len(found) == 1
    f = found[0]
    assert f.title == "Python 3.9 is past end of life" and f.severity == Severity.high
    assert f.evidence[0].path == "pyproject.toml" and f.evidence[0].line_start == 3
    assert "requires-python >=3.9" in f.evidence[0].note
    assert "lowest allowed version, 3.9" in f.evidence[0].note
    assert "lowest version" in f.summary


@pytest.mark.parametrize("spec,expected", [
    ("3.9", ((3, 9), False)),
    ("v18.17.0", ((18, 17, 0), False)),
    ("==3.9.7", ((3, 9, 7), False)),
    (">=3.9", ((3, 9), True)),
    (">=3.9,<4", ((3, 9), True)),
    (">=16 <20", ((16,), True)),
    ("^7.4|^8.0", ((7, 4), True)),
    ("^18.2.0 || ^19.0.0", ((18, 2, 0), True)),
    ("~=3.10", ((3, 10), True)),
    ("18.x", ((18,), True)),
    ("8.1.*", ((8, 1), True)),
    ("<4", (None, True)),
    ("*", (None, True)),
    ("latest", (None, False)),
    ("lts/hydrogen", (None, False)),
    ("", (None, False)),
])
def test_lowest_version(spec: str, expected):
    assert lowest_version(spec) == expected


# --- every source the ticket lists ---------------------------------------------------------

def test_every_declared_source(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "runtime.txt": "python-3.10.12\n",
        "go.mod": "module example.com/x\n\ngo 1.20\n",
        ".ruby-version": "ruby-2.7.2\n",
        "composer.json": json.dumps({"require": {"php": "^7.4|^8.0"}}, indent=2),
        "deploy/Dockerfile.prod": ("FROM --platform=linux/amd64 golang:1.25 AS build\n"
                                   "FROM debian:buster-slim\n"
                                   "FROM eclipse-temurin:16-jre AS jre\n"
                                   "FROM build\n"
                                   "FROM ubuntu:focal\n"
                                   "ARG NODE=18\n"
                                   "FROM node:${NODE}\n"
                                   "FROM registry.internal.example/library/ruby:2.7\n"),
        "requirements.txt": "django>=3.2,<4\n",
        "package.json": json.dumps({"dependencies": {"react": "^17.0.2"},
                                    "devDependencies": {"vue": "2.6.0"}}),
    })
    titles = _by_title(found)
    assert set(titles) == {
        "Python 3.10 is past end of life", "Go 1.20 is past end of life",
        "Ruby 2.7 is past end of life", "PHP 7.4 is past end of life",
        "Debian 10 is past end of life", "Eclipse Temurin 16 is past end of life",
        "Ubuntu 20.04 is past end of life", "Django 3.2 is past end of life",
        "React 17 is past end of life",
    }
    assert scanner.notes == []
    assert titles["Go 1.20 is past end of life"].evidence[0].line_start == 3
    ruby = titles["Ruby 2.7 is past end of life"]
    assert [(e.path, e.line_start) for e in ruby.evidence] == [
        (".ruby-version", 1), ("deploy/Dockerfile.prod", 8)]
    assert "registry.internal.example" not in ruby.model_dump_json()  # no internal hosts
    assert "FROM debian:buster-slim" in titles["Debian 10 is past end of life"].evidence[0].note
    php = titles["PHP 7.4 is past end of life"]
    assert php.evidence[0].line_start == 3 and "lowest allowed version, 7.4" in \
        php.evidence[0].note
    react = titles["React 17 is past end of life"]
    assert "no end-of-life date is published" in react.summary
    assert react.evidence[0].path == "package.json" and react.evidence[0].line_start is None
    assert "Django" in titles["Django 3.2 is past end of life"].summary


@pytest.mark.parametrize("body", ["2.7.8\n", "ruby-2.7.8\n"])
def test_ruby_version_with_or_without_the_rvm_prefix(tmp_path: Path, body: str):
    # rbenv, chruby and asdf write a bare version; rvm writes "ruby-2.7.8"
    found, _ = _scan(tmp_path, {".ruby-version": body})
    assert [f.title for f in found] == ["Ruby 2.7 is past end of life"]


def test_other_ruby_implementations_are_not_ruby(tmp_path: Path):
    found, _ = _scan(tmp_path, {".ruby-version": "jruby-9.4.5.0\n",
                                "b/.ruby-version": "truffleruby-23.1.1\n"})
    assert found == []


# --- UNVAR-52: the other common ways Python, Node and Ruby versions are declared ----------

POETRY = ('[tool.poetry]\nname = "x"\n\n[tool.poetry.dependencies]\n'
          'python-dotenv = "^1.0"\npython = "^3.7"\n')
PIPFILE = ('[[source]]\nurl = "https://pypi.org/simple"\n\n[packages]\nrequests = "*"\n\n'
           '[requires]\npython_version = "3.6"\n')
SETUP_CFG = "[metadata]\nname = x\n\n[options]\npython_requires = >=3.6\n"
SETUP_PY = ('from setuptools import setup\n\n# python_requires=">=2.7" was dropped\nsetup(\n'
            '    name="x",\n    python_requires=\'>=3.6\',\n)\n')
TOOL_VERSIONS = "# asdf\npython 3.6.15\nnodejs 14.21.3\nruby 2.6.3\nterraform 1.5.0\n"
GEMFILE = "source 'https://rubygems.org'\n\nruby '2.6.3'\n\ngem 'sinatra'\n"


@pytest.mark.parametrize("files,expected", [
    ({"pyproject.toml": POETRY},
     [("Python 3.7 is past end of life", 6, "tool.poetry.dependencies.python ^3.7")]),
    ({"Pipfile": PIPFILE},
     [("Python 3.6 is past end of life", 8, "requires.python_version 3.6")]),
    ({"Pipfile": '[requires]\npython_full_version = "3.6.15"\n'},
     [("Python 3.6 is past end of life", 2, "requires.python_full_version 3.6.15")]),
    ({"setup.cfg": SETUP_CFG},
     [("Python 3.6 is past end of life", 5, "options.python_requires >=3.6")]),
    ({"setup.py": SETUP_PY},
     [("Python 3.6 is past end of life", 6, "python_requires >=3.6")]),
    ({".tool-versions": TOOL_VERSIONS},
     [("Node.js 14 is past end of life", 3, ".tool-versions nodejs 14.21.3"),
      ("Python 3.6 is past end of life", 2, ".tool-versions python 3.6.15"),
      ("Ruby 2.6 is past end of life", 4, ".tool-versions ruby 2.6.3")]),
    ({"Gemfile": GEMFILE}, [("Ruby 2.6 is past end of life", 3, "ruby 2.6.3")]),
    ({"Gemfile": 'ruby "~> 2.6.0"\n'}, [("Ruby 2.6 is past end of life", 1, "ruby ~> 2.6.0")]),
    ({".nvmrc": "lts/fermium\n"}, [("Node.js 14 is past end of life", 1, ".nvmrc lts/fermium")]),
    ({".nvmrc": "lts/Hydrogen\n"},
     [("Node.js 18 is past end of life", 1, ".nvmrc lts/Hydrogen")]),
    ({".tool-versions": "nodejs lts-fermium\n"},
     [("Node.js 14 is past end of life", 1, ".tool-versions nodejs lts-fermium")]),
    ({"setup.py": 'setup(url="http://x/#a", python_requires=">=3.6")\n'},
     [("Python 3.6 is past end of life", 1, "python_requires >=3.6")]),
])
def test_common_declarations_give_end_of_life_findings(tmp_path: Path, files, expected):
    found, scanner = _scan(tmp_path, files)
    path = next(iter(files))
    assert [(f.title, f.severity) for f in found] == [(t, Severity.high) for t, _, _ in expected]
    for f, (_, line, what) in zip(found, expected, strict=True):
        assert [(e.path, e.line_start) for e in f.evidence] == [(path, line)]
        assert f.evidence[0].note.startswith(f"{what}; ")
    assert scanner.notes == []


def test_poetry_range_is_judged_by_its_lowest_version(tmp_path: Path):
    found, _ = _scan(tmp_path, {"pyproject.toml": POETRY})
    assert "lowest allowed version, 3.7" in found[0].evidence[0].note


def test_poetry_and_requires_python_in_one_file_are_both_read(tmp_path: Path):
    found, _ = _scan(tmp_path, {"pyproject.toml": (
        '[project]\nname = "x"\nrequires-python = ">=3.13"\n\n'
        '[tool.poetry.dependencies]\npython = ">=3.9,<4.0"\n')})
    assert [(f.title, f.evidence[0].line_start) for f in found] == [
        ("Python 3.9 is past end of life", 6)]


def test_supported_common_declarations_give_no_finding(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "a/pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.13"\n',
        "b/Pipfile": '[requires]\npython_version = "3.13"\n',
        "c/setup.cfg": "[options]\npython_requires = >=3.12\n",
        "d/setup.py": 'setup(name="x", python_requires=">=3.13")\n',
        "e/.tool-versions": "python 3.13.1\nnodejs 24.1.0\nruby 3.4.1\n",
        "f/Gemfile": 'ruby "3.4.1"\n',
        "g/.nvmrc": "lts/krypton\n",
    })
    assert found == [] and scanner.notes == []


def test_node_lts_codenames_name_their_major_version():
    from unvarnish.scanners.end_of_life import _declared_in

    assert [d.version for d in _declared_in(".nvmrc", "lts/Lithium\n")] == [(26,)]
    assert [d.version for d in _declared_in(".tool-versions", "node lts-lithium\n")] == [(26,)]


def test_gemfile_ruby_with_another_engine_is_not_ruby(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "a/Gemfile": "ruby '2.6.3', engine: 'jruby', engine_version: '9.2.0'\n",
        "b/Gemfile": "ruby '2.6.3', :engine => 'jruby', :engine_version => '9.2.0'\n",
    })
    assert found == [] and scanner.notes == []


def test_floating_or_unknown_common_declarations_are_skipped(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "a/.nvmrc": "lts/*\n",
        "b/.nvmrc": "lts/argon\n",  # Node.js 4, a line the test bundle does not hold
        "i/.nvmrc": "lts/zinc\n",  # a codename not (yet) in the table
        "c/.nvmrc": "lts/-1\n",
        "d/.tool-versions": "python system\nnodejs lts\nruby latest\n",
        "e/Gemfile": 'ruby file: ".ruby-version"\n',
        "f/Gemfile": "ruby RUBY_VERSION\n",
        "g/setup.py": "PY = '>=3.6'\nsetup(python_requires=PY)\n",
        "h/setup.py": 'setup(python_requires=f">={MIN}")\n',
    })
    assert found == [] and scanner.notes == []


@pytest.mark.parametrize("path,text", [
    ("pyproject.toml", "[tool.poetry.dependencies\npython = '^3.7'\n"),
    ("pyproject.toml", '[tool]\npoetry = "not a table"\n'),
    ("pyproject.toml", '[tool.poetry]\ndependencies = ["python"]\n'),
    ("pyproject.toml", "[tool.poetry.dependencies]\npython = 3.7\n"),
    ("Pipfile", "[requires\npython_version = '3.6'\n"),
    ("Pipfile", 'requires = "3.6"\n'),
    ("Pipfile", "[requires]\npython_version = 3.6\n"),
    ("setup.cfg", "python_requires = >=3.6\n"),
    ("setup.cfg", "[options]\npython_requires = >=3.6\n[options]\n  bad\n"),
    ("setup.cfg", "[metadata]\nname = x\n"),
    ("setup.py", "\x00\xff" * 10),
    (".tool-versions", "python\n\n   \n"),
    ("Gemfile", "ruby '\n"),
])
def test_malformed_common_declarations_do_not_raise(path: str, text: str):
    from unvarnish.scanners.end_of_life import _declared_in

    assert _declared_in(path, text) == []


def test_gemfile_ruby_line_is_read_in_linear_time():
    import time

    from unvarnish.scanners.end_of_life import _declared_in

    start = time.perf_counter()
    for text in ("ruby" + " " * 20_000 + "x", "ruby" + " " * 10_000 + "(" + " " * 10_000 + "x"):
        assert _declared_in("Gemfile", text) == []
    assert time.perf_counter() - start < 1.0  # backtracking took seconds
    assert [d.spec for d in _declared_in("Gemfile", "ruby  (  '2.6.3' )\n")] == ["2.6.3"]


def test_go_toolchain_wins_over_the_go_directive(tmp_path: Path):
    found, _ = _scan(tmp_path, {"go.mod": "module x\n\ngo 1.20\n\ntoolchain go1.25.1\n"})
    assert found == []


def test_unknown_or_floating_versions_are_skipped(tmp_path: Path):
    found, scanner = _scan(tmp_path, {
        "Dockerfile": "FROM python:3\nFROM node:lts-alpine\nFROM node\nFROM scratch\n",
        ".python-version": "pypy3.10-7.3.12\n",
        ".nvmrc": "lts/*\n",
        "x/Old.csproj": "<TargetFramework>net48</TargetFramework>\n",
        "y/Lib.csproj": "<TargetFrameworks>netstandard2.0;net10.0</TargetFrameworks>\n",
        "package.json": "{not json",
        "pyproject.toml": "[project\n",
    })
    assert found == [] and scanner.notes == []


def test_several_target_frameworks_and_legacy_netcoreapp(tmp_path: Path):
    found, _ = _scan(tmp_path, {
        "a/A.csproj": "<TargetFrameworks>net6.0;net8.0-windows</TargetFrameworks>\n",
        "b/B.fsproj": "<TargetFramework>netcoreapp3.1</TargetFramework>\n",
    })
    titles = _by_title(found)
    # .NET 8 ends on TODAY itself: past end of life from that day
    assert set(titles) == {"Microsoft .NET 6 is past end of life",
                           "Microsoft .NET 8 is past end of life",
                           "Microsoft .NET 3.1 is past end of life"}


def test_same_cycle_in_two_places_is_one_finding(tmp_path: Path):
    found, _ = _scan(tmp_path, {"Dockerfile": "FROM python:3.9\n",
                                "worker/Dockerfile": "FROM python:3.9.18-alpine\n"})
    assert len(found) == 1
    assert [e.path for e in found[0].evidence] == ["Dockerfile", "worker/Dockerfile"]
    assert "2 places" in found[0].summary


def test_test_fixtures_are_not_read(tmp_path: Path):
    found, _ = _scan(tmp_path, {"tests/fixtures/Dockerfile": "FROM python:3.9\n"})
    assert found == []


# --- hostile repository text --------------------------------------------------------------

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
CRAFTED = (">=3.9\n# Injected heading\nsee https://user:hunter2@git.acme.internal/x "
           f"key {AWS_KEY} " + "padding " * 20)


@pytest.mark.parametrize("files", [
    {"pyproject.toml": f'[project]\nname = "x"\nrequires-python = """{CRAFTED}"""\n'},
    {"package.json": json.dumps({"engines": {"node": CRAFTED.replace(">=3.9", ">=18")}})},
    {"composer.json": json.dumps({"require": {"php": CRAFTED.replace(">=3.9", ">=7.4")}})},
    {".python-version": "3.9 " + CRAFTED.replace("\n", " ").replace("#", "")},
])
def test_repository_text_in_notes_is_scrubbed_one_line_and_capped(tmp_path: Path, files):
    found, _ = _scan(tmp_path, files)
    assert len(found) == 1
    note = found[0].evidence[0].note
    shown = note.split("; ")[0]
    assert "\n" not in note and "\r" not in note
    assert len(shown) <= 100 and shown.endswith("…")
    assert "hunter2" not in note and "user:" not in note and AWS_KEY not in note


def test_short_values_are_shown_unchanged(tmp_path: Path):
    found, _ = _scan(tmp_path, {"runtime.txt": "python-3.10.12\n"})
    assert found[0].evidence[0].note.startswith("runtime.txt python-3.10.12; ")


@pytest.mark.parametrize("hostile", [
    {"deep/package.json": "[" * 100_000 + "]" * 100_000},
    {"deep/composer.json": '{"a":' * 100_000 + "1" + "}" * 100_000},
    {"odd/pyproject.toml": 'project = "not a table"\n'},
])
def test_one_odd_file_does_not_silence_the_scanner(tmp_path: Path, hostile):
    found, _ = _scan(tmp_path, {**hostile, "Dockerfile": "FROM python:3.9-slim\n"})
    assert [f.title for f in found] == ["Python 3.9 is past end of life"]


def test_a_file_that_breaks_its_parser_is_skipped(tmp_path: Path, monkeypatch):
    from unvarnish.scanners import end_of_life

    real = end_of_life._go_mod

    def boom(path, text):
        if path == "bad/go.mod":
            raise RuntimeError("parser bug")
        return real(path, text)

    monkeypatch.setattr(end_of_life, "_go_mod", boom)
    found, _ = _scan(tmp_path, {"bad/go.mod": "go 1.20\n", "go.mod": "go 1.20\n",
                                "Dockerfile": "FROM python:3.9-slim\n"})
    assert {f.title for f in found} == {"Python 3.9 is past end of life",
                                        "Go 1.20 is past end of life"}


@pytest.mark.parametrize("value", ["x", None, -1, 10**9, 1.0e300, True, [6]])
def test_bad_warn_months_falls_back_to_six(tmp_path: Path, value):
    # Node.js 22 ends 2027-04-30, inside the default six months of TODAY
    found, _ = _scan(tmp_path, {".nvmrc": "22\n"}, warn_months=value)
    assert [(f.title, f.severity) for f in found] == [
        ("Node.js 22 is near end of life", Severity.medium)]
    assert "within 6 months" in found[0].summary


def test_warn_months_as_a_number_string_is_accepted(tmp_path: Path):
    assert _scan(tmp_path, {".nvmrc": "22\n"}, warn_months="3")[0] == []


def test_only_files_that_can_pin_a_version_are_read(tmp_path: Path, monkeypatch):
    read: list[str] = []
    real = Path.read_text

    def spy(self, *a, **kw):
        read.append(self.name)
        return real(self, *a, **kw)

    root = _write(tmp_path, {"Dockerfile": "FROM python:3.9\n", "app.py": "x = 1\n",
                             "README.md": "# hi\n", "web/package.json": "{}",
                             "api/Api.csproj": CSPROJ, "build.dockerfile": "FROM node:18\n"})
    ctx = _ctx(root)
    monkeypatch.setattr(Path, "read_text", spy)
    EndOfLifeScanner(today=TODAY, bundle=BUNDLE).run(ctx)
    assert sorted(n for n in read if n != "endoflife.json") == [
        "Api.csproj", "Dockerfile", "build.dockerfile", "package.json"]


def test_registered_with_default_options():
    assert "end_of_life" in [s.name for s in builtin_scanners()]
    assert DEFAULT_SCANNER_OPTIONS["end_of_life"] == {"warn_months": 6,
                                                      "max_data_age_days": 90}


# --- UNVAR-59: an old bundle is named in Not analysed and the summary row -----------------

FETCHED = date(2026, 11, 1)  # DATA_DATE as a date


def _age_notes(scanner) -> list[str]:
    return [n for n in scanner.notes if "days old" in n]


def test_old_bundle_adds_a_note_and_still_finds(tmp_path: Path):
    found, scanner = _scan(tmp_path, {"Dockerfile": "FROM python:3.9-slim\n"},
                           today=FETCHED + timedelta(days=200))
    assert [f.title for f in found] == ["Python 3.9 is past end of life"]
    assert found[0].severity == Severity.high
    notes = _age_notes(scanner)
    assert len(notes) == 1 and scanner.notes == notes
    assert notes[0].startswith("end_of_life: ")
    assert DATA_DATE in notes[0] and "200 days old" in notes[0]
    assert "90-day" in notes[0] and "unvarnish eol refresh" in notes[0]


def test_old_bundle_note_does_not_change_findings(tmp_path: Path):
    files = {"Dockerfile": "FROM python:3.9-slim\n", ".nvmrc": "18\n"}
    today = FETCHED + timedelta(days=200)
    stale, _ = _scan(tmp_path / "a", files, today=today)
    fresh, scanner = _scan(tmp_path / "b", files, today=today, max_data_age_days=365)
    assert scanner.notes == []
    assert [f.model_dump() for f in stale] == [f.model_dump() for f in fresh]


def test_recent_bundle_adds_no_note(tmp_path: Path):
    found, scanner = _scan(tmp_path, {"Dockerfile": "FROM python:3.9-slim\n"},
                           today=FETCHED + timedelta(days=10))
    assert len(found) == 1 and scanner.notes == []
    # exactly the limit is not older than it
    assert _scan(tmp_path / "b", {"a.py": "x = 1\n"},
                 today=FETCHED + timedelta(days=90))[1].notes == []


def test_configured_data_age_is_honoured(tmp_path: Path):
    files = {"Dockerfile": "FROM python:3.9-slim\n"}
    _, scanner = _scan(tmp_path / "a", files, today=FETCHED + timedelta(days=40),
                       max_data_age_days=30)
    assert len(_age_notes(scanner)) == 1
    assert "40 days old" in scanner.notes[0] and "30-day" in scanner.notes[0]
    assert _scan(tmp_path / "b", files, today=FETCHED + timedelta(days=200),
                 max_data_age_days=365)[1].notes == []
    assert _scan(tmp_path / "c", files, today=FETCHED + timedelta(days=200),
                 max_data_age_days="365")[1].notes == []


def test_one_day_old_reads_as_one_day_and_round_trips(tmp_path: Path):
    from unvarnish.scanners.end_of_life import data_age_warning

    _, scanner = _scan(tmp_path, {"a.py": "x = 1\n"}, today=FETCHED + timedelta(days=1),
                       max_data_age_days=0)
    assert len(scanner.notes) == 1 and "is 1 day old" in scanner.notes[0]
    assert data_age_warning(scanner.notes) == "1 day old, older than the 0-day limit"


@pytest.mark.parametrize("value", ["x", None, -1, 10**9, 1.0e300, True, [90]])
def test_bad_max_data_age_falls_back_to_ninety(tmp_path: Path, value):
    files = {"a.py": "x = 1\n"}
    assert _scan(tmp_path / "a", files, today=FETCHED + timedelta(days=60),
                 max_data_age_days=value)[1].notes == []
    _, scanner = _scan(tmp_path / "b", files, today=FETCHED + timedelta(days=91),
                       max_data_age_days=value)
    assert len(scanner.notes) == 1 and "90-day" in scanner.notes[0]


# --- bundle lookup -------------------------------------------------------------------------

def test_default_bundle_lookup(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(eol.DIR_ENV, str(tmp_path / "kit"))
    assert eol.bundle_path() == tmp_path / "kit" / "endoflife.json"
    monkeypatch.delenv(eol.DIR_ENV)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert eol.bundle_path() == tmp_path / "xdg" / "unvarnish" / "eol" / "endoflife.json"
    monkeypatch.delenv("XDG_DATA_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert eol.bundle_path() == (tmp_path / "home" / ".local" / "share" / "unvarnish" / "eol"
                                 / "endoflife.json")


def test_bundle_date_and_load(monkeypatch):
    monkeypatch.setenv(eol.DIR_ENV, str(BUNDLE_DIR))
    assert eol.bundle_date() == DATA_DATE
    bundle, note = eol.load_bundle()
    assert note is None and bundle is not None
    assert bundle.fetched == date(2026, 11, 1) and "python" in bundle.products


# --- acceptance 3 and 5: the date reaches the report, and a refresh reruns the inventory ---

def _engagement_run(engagement, files, phases):
    from unvarnish.phases.ingest import ingest_tool

    src = _write(engagement.root.parent / "client-src", files)
    ingest_tool(engagement, "svc", str(src), "files")
    ctx = build_context(engagement, "svc")
    return ctx, PhaseRunner(phases).run(ctx)


def _phases(today: date = TODAY):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.scanners import builtin_scanners as scanners

    others = [s for s in scanners() if s.name != "end_of_life"]
    return [InventoryPhase(), GitPhase(),
            ScanPhase(scanners=[*others, EndOfLifeScanner(today=today)]), RenderPhase()]


def test_bundle_date_appears_in_the_report(engagement, monkeypatch):
    monkeypatch.setenv(eol.DIR_ENV, str(BUNDLE_DIR))
    ctx, results = _engagement_run(engagement, {"Dockerfile": "FROM python:3.9-slim\n"},
                                   _phases())
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    assert deps.eol_data_date == DATA_DATE
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert ("| End-of-life runtimes and frameworks | 1 past end of life, 0 near it; "
            f"endoflife.date data dated {DATA_DATE} |") in doc
    assert "Python 3.9 is past end of life" in doc


def test_missing_bundle_in_the_report(engagement, monkeypatch, tmp_path: Path):
    monkeypatch.setenv(eol.DIR_ENV, str(tmp_path / "empty"))
    ctx, results = _engagement_run(engagement, {"Dockerfile": "FROM python:3.9-slim\n"},
                                   _phases())
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    assert not scan.skipped
    eol_notes = [n for n in scan.notes if n.startswith("end_of_life:")]
    assert len(eol_notes) == 1
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    not_analysed = doc.split("## Not analysed", 1)[1]
    assert eol_notes[0] in not_analysed
    assert ("| End-of-life runtimes and frameworks | not checked (no end-of-life data "
            "bundle) |") in doc


def test_old_bundle_in_the_report(engagement, monkeypatch):
    monkeypatch.setenv(eol.DIR_ENV, str(BUNDLE_DIR))
    ctx, results = _engagement_run(engagement, {"Dockerfile": "FROM python:3.9-slim\n"},
                                   _phases(today=FETCHED + timedelta(days=200)))
    assert all(r.status == PhaseStatus.ok for r in results), [r.model_dump() for r in results]
    scan = read_artifact(ctx.paths.scanner_findings, ScannerFindings).data
    eol_notes = [n for n in scan.notes if n.startswith("end_of_life:")]
    assert len(eol_notes) == 1 and DATA_DATE in eol_notes[0]
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert eol_notes[0] in doc.split("## Not analysed", 1)[1]
    assert ("| End-of-life runtimes and frameworks | 1 past end of life, 0 near it; "
            f"endoflife.date data dated {DATA_DATE} (200 days old, older than the 90-day "
            "limit: refresh it) |") in doc
    assert "Python 3.9 is past end of life" in doc


def test_report_says_not_checked_without_the_scanner(engagement, monkeypatch):
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.scan import ScanPhase

    monkeypatch.setenv(eol.DIR_ENV, str(BUNDLE_DIR))
    ctx, _ = _engagement_run(engagement, {"a.py": "x = 1\n"},
                             [InventoryPhase(), GitPhase(), ScanPhase(scanners=[]),
                              RenderPhase()])
    doc = ctx.paths.findings_doc.read_text(encoding="utf-8")
    assert "| End-of-life runtimes and frameworks | not checked |" in doc


def test_inventory_hash_includes_the_bundle_date(engagement, monkeypatch, tmp_path: Path):
    from unvarnish.phases.ingest import ingest_tool

    src = _write(tmp_path / "src", {"a.py": "x = 1\n"})
    ingest_tool(engagement, "svc", str(src), "files")
    ctx = build_context(engagement, "svc")
    kit = tmp_path / "kit"
    monkeypatch.setenv(eol.DIR_ENV, str(kit))
    without = InventoryPhase().inputs_hash(ctx)
    kit.mkdir()
    shutil.copy(BUNDLE, kit / "endoflife.json")
    dated = InventoryPhase().inputs_hash(ctx)
    raw = json.loads(BUNDLE.read_text(encoding="utf-8"))
    raw["fetched"] = "2026-12-01"
    (kit / "endoflife.json").write_text(json.dumps(raw), encoding="utf-8")
    refreshed = InventoryPhase().inputs_hash(ctx)
    assert len({without, dated, refreshed}) == 3


# --- unvarnish eol refresh -----------------------------------------------------------------

def _api(slug: str) -> dict:
    """An endoflife.date API v1 product response, shaped like the real one."""
    return {"schema_version": "1.2.0", "result": {
        "name": slug, "label": slug.title(), "releases": [
            {"name": "2", "codename": "Two", "releaseDate": "2025-01-01", "isEol": False,
             "eolFrom": "2028-01-31", "isMaintained": True,
             "latest": {"name": "2.1", "date": "2025-06-01"}},
            {"name": "1", "codename": None, "releaseDate": "2020-01-01", "isEol": True,
             "eolFrom": None, "isMaintained": False, "latest": None},
        ]}}


def test_build_bundle_from_the_api():
    urls: list[str] = []

    def fetch(url: str):
        urls.append(url)
        return _api(url.rsplit("/", 1)[1])

    bundle = eol.build_bundle(fetch=fetch, today=date(2026, 11, 9))
    assert urls == [f"https://endoflife.date/api/v1/products/{p}" for p in eol.PRODUCTS]
    assert set(bundle.products) == set(eol.PRODUCTS) and len(eol.PRODUCTS) == 19
    assert bundle.fetched == date(2026, 11, 9) and bundle.format == 1
    py = bundle.products["python"]
    assert py.label == "Python"
    assert py.cycles[0].cycle == "2" and py.cycles[0].codename == "Two"
    assert py.cycles[0].eol_from == date(2028, 1, 31) and py.cycles[0].latest == "2.1"
    assert py.cycles[1].is_eol and py.cycles[1].eol_from is None
    assert "MIT" in bundle.attribution


def test_product_slugs_are_endoflife_slugs():
    for slug in ("python", "nodejs", "go", "dotnet", "eclipse-temurin", "ruby", "php",
                 "django", "rails", "spring-boot", "react", "angular", "vue", "nextjs",
                 "postgresql", "mysql", "ubuntu", "debian", "alpine-linux"):
        assert slug in eol.PRODUCTS, slug


def test_build_bundle_retries_then_fails_naming_the_product():
    calls: list[str] = []
    sleeps: list[float] = []

    def flaky(url: str):
        calls.append(url)
        if url.endswith("/nodejs") and calls.count(url) == 1:
            raise TimeoutError("timed out")
        if url.endswith("/go"):
            return {"result": {"releases": "nope"}}
        return _api(url.rsplit("/", 1)[1])

    with pytest.raises(eol.EolFetchError, match="go"):
        eol.build_bundle(fetch=flaky, today=TODAY, attempts=2, sleep=sleeps.append)
    assert sum(u.endswith("/nodejs") for u in calls) == 2
    assert sleeps == [2.0, 2.0]  # one retry for nodejs, one for go


def test_fetch_json_uses_https_and_a_generic_agent(monkeypatch):
    import io

    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout):
        seen["url"], seen["agent"], seen["timeout"] = (req.full_url,
                                                       req.get_header("User-agent"), timeout)
        return Resp(b'{"result": {}}')

    monkeypatch.setattr(eol.urllib.request, "urlopen", urlopen)
    assert eol.fetch_json("https://endoflife.date/api/v1/products/python") == {"result": {}}
    assert seen["url"].startswith("https://endoflife.date/")
    assert seen["agent"].startswith("unvarnish/") and seen["timeout"] > 0


def test_cli_eol_refresh_writes_the_bundle(monkeypatch, tmp_path: Path):
    from unvarnish.cli import app

    monkeypatch.setattr(eol, "fetch_json", lambda url: _api(url.rsplit("/", 1)[1]))
    out = tmp_path / "eol"
    result = CliRunner().invoke(app, ["eol", "refresh", "--dir", str(out)],
                                env={"COLUMNS": "400"})
    assert result.exit_code == 0, result.output
    bundle, note = eol.load_bundle(out / "endoflife.json")
    assert note is None and len(bundle.products) == 19
    assert f"data dated {bundle.fetched.isoformat()}" in result.output
    assert not list(out.glob("*.tmp"))


def test_cli_eol_refresh_default_dir(monkeypatch, tmp_path: Path):
    from unvarnish.cli import app

    monkeypatch.setattr(eol, "fetch_json", lambda url: _api(url.rsplit("/", 1)[1]))
    result = CliRunner().invoke(app, ["eol", "refresh"],
                                env={"COLUMNS": "400", eol.DIR_ENV: str(tmp_path / "d")})
    assert result.exit_code == 0, result.output
    assert (tmp_path / "d" / "endoflife.json").is_file()


def test_cli_eol_refresh_failure_keeps_the_old_bundle(monkeypatch, tmp_path: Path):
    from unvarnish.cli import app

    def down(url: str):
        raise OSError("network unreachable")

    monkeypatch.setattr(eol, "fetch_json", down)
    out = tmp_path / "eol"
    out.mkdir()
    shutil.copy(BUNDLE, out / "endoflife.json")
    result = CliRunner().invoke(app, ["eol", "refresh", "--dir", str(out), "--attempts", "1"],
                                env={"COLUMNS": "400"})
    assert result.exit_code == 1
    assert "python" in result.output and "network unreachable" in result.output
    assert eol.bundle_date(out / "endoflife.json") == DATA_DATE
