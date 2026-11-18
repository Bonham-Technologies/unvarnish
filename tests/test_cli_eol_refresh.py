"""`unvarnish eol refresh` checks the target folder before it downloads anything (UNVAR-56)."""

import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.analysis import eol
from unvarnish.cli import app

runner = CliRunner()


@pytest.fixture
def fetched(monkeypatch) -> list[int]:
    calls: list[int] = []

    def fake_build(**_kwargs):
        calls.append(1)
        raise AssertionError("must not download into an unwritable folder")

    monkeypatch.setattr(eol, "build_bundle", fake_build)
    return calls


def _assert_one_clean_error(result, target: Path) -> None:
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    errors = [line for line in result.output.splitlines() if "error:" in line]
    assert len(errors) == 1
    assert "--dir" in result.output
    assert str(target) in result.output.replace("\n", "")


def test_unwritable_dir_fails_before_downloading(tmp_path: Path, fetched):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder", encoding="utf-8")
    target = blocker / "eol"
    result = runner.invoke(app, ["eol", "refresh", "--dir", str(target)])
    assert fetched == []
    _assert_one_clean_error(result, target)


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0,
                    reason="root ignores folder permissions")
def test_permission_denied_dir_fails_before_downloading(tmp_path: Path, fetched):
    target = tmp_path / "readonly"
    target.mkdir()
    target.chmod(0o500)
    try:
        result = runner.invoke(app, ["eol", "refresh", "--dir", str(target)])
    finally:
        target.chmod(0o700)
    assert fetched == []
    _assert_one_clean_error(result, target)
    assert list(target.iterdir()) == []


def test_writable_check_leaves_nothing_behind(tmp_path: Path):
    target = tmp_path / "new" / "eol"
    assert eol.ensure_writable(target) == target
    assert list(target.iterdir()) == []


def test_write_failure_after_download_is_one_clean_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(eol, "build_bundle", lambda **_k: object())

    def boom(*_a, **_k):
        raise PermissionError("denied")

    monkeypatch.setattr(eol, "write_bundle", boom)
    target = tmp_path / "eol"
    result = runner.invoke(app, ["eol", "refresh", "--dir", str(target)])
    _assert_one_clean_error(result, target)
