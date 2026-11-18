import os
from pathlib import Path

from tests.conftest import _git
from unvarnish.analysis.dependencies import parse_manifests
from unvarnish.analysis.languages import Classification
from unvarnish.artifacts import read_artifact
from unvarnish.engagement import Engagement
from unvarnish.phases.base import PhaseStatus, build_context
from unvarnish.phases.ingest import ingest_tool
from unvarnish.phases.inventory import InventoryPhase
from unvarnish.schemas.inventory import Census, Dependencies, FileRecord, Metrics


def _run(eng: Engagement, name: str):
    ctx = build_context(eng, name)
    result = InventoryPhase().run(ctx)
    assert result.status == PhaseStatus.ok, result.message
    census = read_artifact(ctx.paths.census, Census).data
    metrics = read_artifact(ctx.paths.metrics, Metrics).data
    deps = read_artifact(ctx.paths.dependencies, Dependencies).data
    return census, metrics, deps


def test_census_on_synthetic_repo(ingested: tuple[Engagement, str]):
    census, metrics, deps = _run(*ingested)
    by_path = {f.path: f for f in census.files}
    assert ".git/HEAD" not in by_path
    assert by_path["app.py"].classification == Classification.source
    assert by_path["app.py"].language == "python"
    assert by_path["node_modules/leftpad/index.js"].excluded
    assert by_path["node_modules/leftpad/index.js"].exclusion_reason == "vendored:node_modules"
    assert by_path["node_modules/leftpad/index.js"].classification == Classification.vendored
    assert by_path["static/app.min.js"].classification == Classification.generated
    assert by_path["CLAUDE.md"].classification == Classification.docs
    assert by_path["requirements.txt"].classification == Classification.config
    assert census.totals.excluded_files == 1
    assert census.totals.by_classification["source"] >= 1
    assert census.languages["python"] > 3000
    assert "Flask" in census.frameworks


def test_metrics_cover_source_not_excluded(ingested: tuple[Engagement, str]):
    census, metrics, _ = _run(*ingested)
    paths = {m.path for m in metrics.files}
    assert "app.py" in paths
    assert "static/index.html" in paths
    assert "node_modules/leftpad/index.js" not in paths
    assert "README.md" not in paths
    app = next(m for m in metrics.files if m.path == "app.py")
    assert app.max_function_name == "process_everything"
    assert app.max_function_lines > 2500


def test_dependencies_from_requirements(ingested: tuple[Engagement, str]):
    _, _, deps = _run(*ingested)
    names = {(d.ecosystem, d.name, d.constraint) for d in deps.dependencies}
    assert ("pypi", "flask", "==2.3.2") in names
    assert ("pypi", "requests", ">=2.31") in names
    assert deps.advisories_checked is False


def test_parse_manifests_multi_ecosystem(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "^18.2.0", "express": "4.19.2"}, '
        '"devDependencies": {"jest": "^29"}}'
    )
    (tmp_path / "go.mod").write_text(
        "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n"
        "\tgolang.org/x/text v0.14.0\n)\n"
    )
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\n\n[dependencies]\naxum = "0.7"\n'
        'serde = { version = "1.0", features = ["derive"] }\n'
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "y"\ndependencies = ["fastapi>=0.110", "pydantic"]\n'
    )
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.springframework.boot</groupId>"
        "<artifactId>spring-boot-starter-web</artifactId><version>3.2.0</version></dependency>"
        "</dependencies></project>"
    )
    files = [
        FileRecord(path=n, bytes=1, lines=1, language=None, classification=Classification.config,
                   excluded=False, exclusion_reason=None)
        for n in ("package.json", "go.mod", "Cargo.toml", "pyproject.toml", "pom.xml")
    ]
    deps, frameworks, failures = parse_manifests(tmp_path, files)
    assert failures == []
    tuples = {(d.ecosystem, d.name) for d in deps}
    assert ("npm", "react") in tuples and ("npm", "jest") in tuples
    assert next(d for d in deps if d.name == "jest").dev is True
    assert ("go", "github.com/gin-gonic/gin") in tuples
    assert ("cargo", "axum") in tuples and ("cargo", "serde") in tuples
    assert ("pypi", "fastapi") in tuples
    assert ("maven", "org.springframework.boot:spring-boot-starter-web") in tuples
    assert {"React", "Express", "Gin", "Axum", "FastAPI", "Spring Boot"} <= set(frameworks)


def test_inventory_empty_tool(engagement: Engagement, tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    ingest_tool(engagement, "empty", str(empty), "files")
    census, metrics, deps = _run(engagement, "empty")
    assert census.files == []
    assert census.totals.files == 0
    assert metrics.files == []
    assert deps.dependencies == []


def test_inventory_skips_symlinks(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "real.py").write_text("x = 1\n")
    os.symlink("real.py", pile / "alias.py")
    os.symlink("nowhere", pile / "broken.py")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, _, _ = _run(engagement, "pile")
    assert [f.path for f in census.files] == ["real.py"]
    assert census.totals.symlinks_skipped == 2


def test_inventory_unicode_filename(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    (pile / "données").mkdir(parents=True)
    (pile / "données" / "résumé final.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, metrics, _ = _run(engagement, "pile")
    assert census.files[0].path == "données/résumé final.py"
    assert metrics.files[0].path == "données/résumé final.py"


def test_inventory_binary_with_text_extension(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "blob.txt").write_bytes(b"\x89PNG\x00\x00binary")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, metrics, _ = _run(engagement, "pile")
    assert census.files[0].classification == Classification.binary
    assert census.files[0].lines == 0
    assert metrics.files == []


# --- fixes from the whole-branch review -------------------------------------
def test_malformed_manifest_is_recorded_not_fatal(engagement: Engagement, tmp_path: Path):
    pile = tmp_path / "pile"
    pile.mkdir()
    (pile / "package.json").write_text("[]")
    (pile / "pyproject.toml").write_text("this is = not toml [[[")
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")
    census, _, deps = _run(engagement, "pile")
    assert deps.dependencies == []
    assert any("package.json" in f for f in census.failures)
    assert any("pyproject.toml" in f for f in census.failures)


def test_inventory_does_not_read_large_binaries_fully(
    engagement: Engagement, tmp_path: Path, monkeypatch
):
    pile = tmp_path / "pile"
    pile.mkdir()
    big = pile / "dump.sqlite"
    with big.open("wb") as fh:
        fh.write(b"SQLite format 3\x00")
        fh.write(b"\x00" * (3 * 1024 * 1024))
    (pile / "a.py").write_text("x = 1\n")
    ingest_tool(engagement, "pile", str(pile), "files")

    real = Path.read_bytes

    def guarded(self: Path):
        if self.name == "dump.sqlite":
            raise AssertionError("binary file must not be read whole")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    census, _, _ = _run(engagement, "pile")
    rec = next(f for f in census.files if f.path == "dump.sqlite")
    assert rec.classification == Classification.binary
    assert rec.bytes > 3 * 1024 * 1024


def _repo_with_forced_files(root: Path) -> Path:
    """A repo whose .gitignore matches files that were then committed with `git add -f`."""
    root.mkdir()
    (root / ".gitignore").write_text("*.log\nbuild/\nconfig.json\n", encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "config.json").write_text('{"db": "prod"}\n', encoding="utf-8")
    (root / "shipped.log").write_text("tracked log\n", encoding="utf-8")
    (root / "build").mkdir()
    (root / "build" / "bundle.js").write_text("var x = 1;\n", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / ".gitignore").write_text("*.secret\n", encoding="utf-8")
    (root / "sub" / "naïve.secret").write_text("tracked under a nested rule\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", ".gitignore", "app.py", "sub/.gitignore")
    _git(root, "add", "-f", "config.json", "shipped.log", "build/bundle.js", "sub/naïve.secret")
    _git(root, "commit", "-q", "-m", "init")
    (root / "debug.log").write_text("untracked log\n", encoding="utf-8")
    return root


def test_tracked_file_is_not_excluded_by_gitignore(engagement: Engagement, tmp_path: Path):
    """UNVAR-28: git never ignores a tracked file, so neither does the census."""
    repo = _repo_with_forced_files(tmp_path / "forced")
    for kind, name in (("repo", "copied"), ("link", "linked")):
        ingest_tool(engagement, name, str(repo), kind)
        census, _, _ = _run(engagement, name)
        by_path = {f.path: f for f in census.files}
        assert by_path["config.json"].excluded is False, kind
        assert by_path["shipped.log"].excluded is False, kind
        assert by_path["debug.log"].exclusion_reason == "gitignore", kind
        assert by_path["sub/naïve.secret"].excluded is False, kind  # nested rule, non-ASCII
        # tracked, but still build output: excluded, so not listed as analysed
        assert by_path["build/bundle.js"].exclusion_reason == "build_output:build", kind
        assert census.tracked_despite_gitignore == [
            "config.json", "shipped.log", "sub/naïve.secret"], kind


def test_files_pile_keeps_gitignore_exclusion(engagement: Engagement, tmp_path: Path):
    """A --files pile has no index to consult: its .gitignore applies as before."""
    repo = _repo_with_forced_files(tmp_path / "forced")
    ingest_tool(engagement, "pile", str(repo), "files")
    census, _, _ = _run(engagement, "pile")
    by_path = {f.path: f for f in census.files}
    assert by_path["config.json"].exclusion_reason == "gitignore"
    assert by_path["shipped.log"].exclusion_reason == "gitignore"
    assert census.tracked_despite_gitignore == []


def test_untracking_a_gitignored_file_makes_the_inventory_stale(
        engagement: Engagement, tmp_path: Path):
    """The tree is unchanged, but what the census excludes is not."""
    repo = _repo_with_forced_files(tmp_path / "forced")
    ingest_tool(engagement, "linked", str(repo), "link")
    ctx = build_context(engagement, "linked")
    before = InventoryPhase().inputs_hash(ctx)
    _git(repo, "rm", "-q", "--cached", "config.json")
    assert InventoryPhase().inputs_hash(ctx) != before
