"""Known-issues burn-down, task 7: export and Docker."""
import shutil
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
HAVE_PANDOC = shutil.which("pandoc") is not None and shutil.which("dot") is not None


@pytest.mark.skipif(not HAVE_PANDOC, reason="pandoc or graphviz missing")
def test_a_second_export_in_the_same_second_does_not_overwrite(engagement, synthetic_repo):
    from tests.test_export_cli import _rendered
    from unvarnish.export.exporter import export_engagement

    _rendered(engagement, synthetic_repo)
    a = export_engagement(engagement, formats=["html"], docs=["findings"], tools=["alpha"],
                          template=None, timestamp="20261019-120000")
    b = export_engagement(engagement, formats=["html"], docs=["findings"], tools=["alpha"],
                          template=None, timestamp="20261019-120000")
    assert a.items[0].path != b.items[0].path
    assert b.items[0].path.endswith("-2.html")


def test_template_must_be_docx_or_css(tmp_path):
    from unvarnish.export.exporter import check_template

    with pytest.raises(ValueError, match="docx or .css"):
        check_template(tmp_path / "brand.txt", ["html"])


@pytest.mark.skipif(not HAVE_PANDOC, reason="pandoc or graphviz missing")
def test_naming_a_tool_does_not_export_the_comparison(engagement, synthetic_repo):
    from tests.test_export_cli import _rendered

    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "alpha", "--format", "html", "-e",
                              str(engagement.root)])
    assert out.exit_code == 0, out.output
    names = [p.name for p in engagement.exports_dir.iterdir()]
    assert names and not any(n.startswith("comparison-") for n in names)


@pytest.mark.skipif(not HAVE_PANDOC, reason="pandoc or graphviz missing")
def test_export_table_folds_long_paths(engagement, synthetic_repo):
    from tests.test_export_cli import _rendered

    _rendered(engagement, synthetic_repo)
    out = runner.invoke(app, ["export", "alpha", "--format", "html", "--doc", "findings", "-e",
                              str(engagement.root)], terminal_width=60)
    assert "…" not in out.output


def test_dockerfile_installs_dependencies_before_source_and_has_no_volume():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "VOLUME" not in text
    deps = text.index("--no-install-project")
    assert deps < text.index("COPY src ./src")
    assert "UNVARNISH_IN_DOCKER=1" in text


def test_container_warns_when_engagement_is_not_mounted(tmp_path, monkeypatch):
    import unvarnish.cli as cli

    monkeypatch.setenv("UNVARNISH_IN_DOCKER", "1")
    monkeypatch.setattr(cli, "ENGAGEMENT_MOUNT", str(tmp_path))
    monkeypatch.setattr(cli.os.path, "ismount", lambda p: False)
    out = runner.invoke(app, ["status", "-e", str(tmp_path)])
    assert "not mounted" in out.output


def test_windows_paths_from_osv_are_relativised():
    from unvarnish.analysis.advisories import _relative

    assert _relative(r"C:\work\repo\api\requirements.txt", Path(r"C:\work\repo")) == \
        "api/requirements.txt"
    assert _relative(r"D:\elsewhere\x.txt", Path(r"C:\work\repo")) == "x.txt"
    assert PurePosixPath(_relative("/src/a/b.txt", Path("/src"))).as_posix() == "a/b.txt"
