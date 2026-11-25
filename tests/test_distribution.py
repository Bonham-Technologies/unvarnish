import re
import subprocess
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.config import SUPPORTED_SCHEMA_VERSION, UnsupportedSchemaVersion, load_config
from unvarnish.engagement import Engagement

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


def test_newer_schema_version_is_refused(tmp_path: Path):
    eng = Engagement.create(tmp_path / "e")
    text = eng.config_file.read_text().replace("schema_version: 1",
                                               f"schema_version: {SUPPORTED_SCHEMA_VERSION + 1}")
    eng.config_file.write_text(text)
    with pytest.raises(UnsupportedSchemaVersion, match="newer"):
        load_config(eng.config_file)
    out = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert out.exit_code == 2 and "newer Unvarnish" in out.output


def test_dockerfile_bundles_the_export_toolchain():
    text = (ROOT / "Dockerfile").read_text()
    for pkg in ("pandoc", "graphviz", "weasyprint", "git"):
        assert pkg in text, pkg
    assert "python:3.13" in text and 'ENTRYPOINT ["unvarnish"]' in text
    assert "/engagement" in text
    ignore = (ROOT / ".dockerignore").read_text()
    assert ".venv" in ignore and ".git" in ignore


@pytest.mark.skipif(not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout")
def test_dockerfile_installs_a_weasyprint_that_tags_pdfs():
    from unvarnish.export.tools import MIN_WEASYPRINT_TAGGED

    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    apt = re.search(r"apt-get install[^&]*", text).group(0)
    # Debian's weasyprint (62.3) hides every link in a PDF/UA file, so it comes from PyPI.
    assert not re.search(r"(?<![\w-])weasyprint(?![\w-])", apt), apt
    for lib in ("libpango-1.0-0", "libpangoft2-1.0-0", "libharfbuzz-subset0"):
        assert lib in apt, lib
    assert "COPY docker/weasyprint.txt /tmp/weasyprint.txt" in text
    assert "--require-hashes -r /tmp/weasyprint.txt" in text
    assert "/usr/local/bin/weasyprint" in text
    pins = (ROOT / "docker" / "weasyprint.txt").read_text(encoding="utf-8")
    m = re.search(r"^weasyprint==(\d+(?:\.\d+)*) \\$", pins, re.M)
    assert m, "weasyprint is not pinned in docker/weasyprint.txt"
    assert tuple(int(x) for x in m.group(1).split(".")) >= MIN_WEASYPRINT_TAGGED
    assert f"weasyprint=={m.group(1)}" in (ROOT / "docker" / "weasyprint.in").read_text(
        encoding="utf-8")
    for block in re.split(r"\n(?=\S)", pins):
        if not block.startswith("#"):
            assert "--hash=sha256:" in block, block.splitlines()[0]


def test_pyproject_metadata():
    text = (ROOT / "pyproject.toml").read_text()
    assert "[project.urls]" in text and "Bonham-Technologies/unvarnish" in text
    assert "Programming Language :: Python :: 3.13" in text
    assert re.search(r'^unv = "unvarnish.cli:app"$', text, re.M)


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs the repository")
def test_wheel_contains_export_assets(tmp_path: Path):
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(tmp_path)], cwd=ROOT, check=True,
                   capture_output=True, timeout=300)
    wheel = next(tmp_path.glob("unvarnish-*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert any(n.endswith("export/assets/report.css") for n in names)
    assert any(n.endswith("export/assets/reference.docx") for n in names)
    assert any(n.endswith("render/templates/findings.md.j2") for n in names)
    assert any(n.endswith("model/prompts/extract_system.md") for n in names)


@pytest.mark.skipif(not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout")
def test_dockerfile_bundles_the_scanners():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "zricethezav/gitleaks:v" in text and "ghcr.io/google/osv-scanner:v" in text
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv" in text
    assert "ARG OSV_ECOSYSTEMS" in text


def _dockerfile_images() -> tuple[list[str], list[str], set[str]]:
    """The Dockerfile's FROM images, its COPY --from sources, and its stage names."""
    froms: list[str] = []
    copies: list[str] = []
    stages: set[str] = set()
    for raw in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        m = re.match(r"FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if m:
            if m.group(1) not in stages and m.group(1).lower() != "scratch":
                froms.append(m.group(1))
            if m.group(2):
                stages.add(m.group(2))
            continue
        m = re.match(r"COPY\s+(?:--\S+\s+)*?--from=(\S+)", line, re.IGNORECASE)
        if m:
            copies.append(m.group(1))
    return froms, copies, stages


@pytest.mark.skipif(not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout")
def test_dockerfile_images_are_digest_pinned():
    """Every FROM and COPY --from names an upstream image as tag@sha256:<digest> (UNVAR-19)."""
    froms, copies, stages = _dockerfile_images()
    refs = froms + [c for c in copies if c not in stages]
    assert len(refs) >= 4, refs
    unpinned = [r for r in refs if not re.search(r"@sha256:[0-9a-f]{64}$", r)]
    assert not unpinned, f"images not pinned by digest: {unpinned}"


@pytest.mark.skipif(not (ROOT / "Dockerfile").exists(), reason="needs the repository checkout")
def test_dockerfile_copies_only_from_named_stages():
    """Dependabot's docker updater reads only FROM lines, so a `COPY --from=<image>` pin would
    never be bumped. Each tool image is a named stage and COPY --from names the stage."""
    _, copies, stages = _dockerfile_images()
    assert copies, "expected COPY --from lines for the scanners and uv"
    assert not [c for c in copies if c not in stages], copies


def test_coverage_floor_is_enforced_by_plain_pytest():
    import tomllib

    cfg = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8"))
    assert "--cov" in cfg["tool"]["pytest"]["ini_options"]["addopts"].split()
    assert cfg["tool"]["coverage"]["run"] == {"source": ["unvarnish"], "branch": True}
    floor = cfg["tool"]["coverage"]["report"]["fail_under"]
    # The floor only rises: lowering fail_under below the UNVAR-87 level fails here too.
    assert isinstance(floor, int) and 95 <= floor <= 100
    assert any(d.startswith("pytest-cov") for d in cfg["dependency-groups"]["dev"])


@pytest.mark.skipif(not (ROOT / ".github").exists(), reason="needs the repository checkout")
def test_ci_and_verify_install_from_the_lockfile():
    # UNVAR-20: without --locked, a pyproject.toml edit that skips uv.lock re-resolves silently
    # in CI, which then tests dependencies no release (Dockerfile --frozen, site kit) installs.
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "run: uv sync --locked --all-groups" in ci
    assert not re.search(r"uv sync(?![^\n]*--locked)", ci)
    verify = "uv sync --locked --all-groups && uv run ruff check . && uv run pytest -q && uv build"
    assert verify in (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert verify in (ROOT / "docs/operations.md").read_text(encoding="utf-8")



@pytest.mark.skipif(not (ROOT / ".github").exists(), reason="needs the repository checkout")
def test_ci_builds_the_image_and_runs_it_on_a_fixture():
    # UNVAR-80: CI checked the Dockerfile as text only, so a Dependabot bump of one of its
    # digest-pinned images could merge with an image that no longer builds or runs.
    import yaml

    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = ci["jobs"]
    assert "docker" in jobs, "ci.yml has no docker job"
    script = "\n".join(step.get("run", "") for step in jobs["docker"]["steps"])
    assert re.search(r"docker build\b.*-t unvarnish:ci", script)
    for command in ("--version", "init /engagement", "add smoke --files", " run\n",
                    "export --format html"):
        assert command in script, command
    assert "--network none" in script
    assert "--entrypoint gitleaks" in script and "--entrypoint osv-scanner" in script
    assert (ROOT / "tests/data/docker-smoke/app.py").is_file()
    # It builds on every push to main, and on a pull request that touches the image's inputs.
    triggers = ci.get("on", ci.get(True))  # PyYAML reads a bare `on` key as true
    assert triggers["push"]["branches"] == ["main"] and "pull_request" in triggers
    for path in ("Dockerfile", "docker/", "pyproject\\.toml", "uv\\.lock"):
        assert path in script, path
    # Only the steps skip when nothing relevant changed: a skipped job would pass the gate.
    assert "if" not in jobs["docker"]
    gated = [step for step in jobs["docker"]["steps"] if "docker build" in step.get("run", "")
             or "docker run" in step.get("run", "")]
    assert gated and all(step["if"] == "steps.image.outputs.build == 'true'" for step in gated)
    # The single required check waits for every other job, the image build included.
    needs = jobs["ci-status"]["needs"]
    assert set(needs) == set(jobs) - {"ci-status"}, needs

# ---------------------------------------------------------------- end-of-life bundle (UNVAR-44)


def _eol_run_step() -> str:
    """The Dockerfile's RUN step that builds the end-of-life bundle, continuations joined."""
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8").replace("\\\n", " ")
    steps = [line for line in text.splitlines() if line.startswith("RUN ") and "EOL_DATA" in line]
    assert len(steps) == 1, steps
    return steps[0].removeprefix("RUN ")


def test_dockerfile_bundles_end_of_life_data():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG EOL_DATA=fetch" in text
    assert "ENV UNVARNISH_EOL_DIR=/opt/eol" in text
    step = _eol_run_step()
    assert 'unvarnish eol refresh --dir "$UNVARNISH_EOL_DIR"' in step
    # The refresh needs Unvarnish installed, so it runs after the project is synced.
    assert text.index("uv sync --frozen --no-dev --no-editable") < text.index("eol refresh")


def _run_eol_step(tmp_path: Path, eol_data: str, stub: str) -> tuple[subprocess.CompletedProcess,
                                                                      Path]:
    """Run the Dockerfile's step under sh with a stand-in `unvarnish` on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "unvarnish"
    fake.write_text(f"#!/bin/sh\n{stub}\n", encoding="utf-8")
    fake.chmod(0o755)
    data = tmp_path / "opt" / "eol"
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "EOL_DATA": eol_data,
           "UNVARNISH_EOL_DIR": str(data), "BUNDLE": str(ROOT / "tests/data/eol/endoflife.json")}
    result = subprocess.run(["sh", "-c", _eol_run_step()], env=env, capture_output=True,
                            text=True, timeout=30)
    return result, data


@pytest.mark.parametrize("eol_data", ["fetch", "skip", "Fetch", ""])
def test_dockerfile_eol_step_fetches_skips_or_fails(tmp_path: Path, eol_data: str):
    ok = 'mkdir -p "$4" && cp "$BUNDLE" "$4/endoflife.json"'  # eol refresh --dir <dir>
    result, data = _run_eol_step(tmp_path, eol_data, ok)
    if eol_data == "fetch":
        assert result.returncode == 0, result.stderr
        assert (data / "endoflife.json").read_bytes() == (
            ROOT / "tests/data/eol/endoflife.json").read_bytes()
    elif eol_data == "skip":
        assert result.returncode == 0, result.stderr
        assert data.is_dir() and not (data / "endoflife.json").exists()
    else:  # a typo never ships an image silently without the bundle
        assert result.returncode != 0
        assert "EOL_DATA must be fetch or skip" in result.stderr


def test_dockerfile_eol_step_fails_the_build_when_the_fetch_fails(tmp_path: Path):
    # `unvarnish eol refresh` exits 1 and writes nothing when any product fails (UNVAR-43).
    result, data = _run_eol_step(tmp_path, "fetch", "echo 'error: download failed' >&2; exit 1")
    assert result.returncode != 0
    assert not (data / "endoflife.json").exists()


def test_site_kit_bundles_and_checks_end_of_life_data():
    script = (ROOT / "scripts" / "site-kit.sh").read_text(encoding="utf-8")
    assert "--build-arg EOL_DATA=fetch" in script
    # The image check reads the bundle as the scanner does, offline, and prints its date.
    assert "bundle_date()" in script and "end-of-life data dated" in script
    runbook = (ROOT / "docs" / "site-kit.md").read_text(encoding="utf-8")
    assert "end-of-life" in runbook and "eol refresh" in runbook and "/opt/eol" in runbook


@pytest.mark.parametrize("doc", ["docs/site-kit.md", "docs/operations.md"])
def test_eol_refresh_instructions_create_the_mounted_folder_first(doc: str):
    # A missing bind-mount source is created by the Docker daemon as root, and the refresh,
    # run as the caller's --user, then cannot write its bundle there.
    text = (ROOT / doc).read_text(encoding="utf-8")
    assert '-v "$PWD/eol:/eol"' in text
    assert text.index("mkdir -p eol") < text.index('-v "$PWD/eol:/eol"')
