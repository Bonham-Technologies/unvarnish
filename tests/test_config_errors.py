"""UNVAR-50: invalid content in engagement.yaml or tool.yaml is a one-line error, not a
traceback."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.engagement import Engagement
from unvarnish.phases.ingest import ingest_tool

runner = CliRunner()


@pytest.fixture
def eng(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Engagement:
    monkeypatch.setenv("UNVARNISH_CONFIG_DIR", str(tmp_path / "user-config"))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    e = Engagement.create(tmp_path / "acme", client="Acme")
    ingest_tool(e, "t1", str(src), "files")
    return e


def _set(path: Path, dotted: str, value) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    *parents, leaf = dotted.split(".")
    node = data
    for key in parents:
        node = node.setdefault(key, {})
    node[leaf] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _break_concurrency(e: Engagement) -> None:
    _set(e.config_file, "pipeline.concurrency", "zero")


def _break_line_drift(e: Engagement) -> None:
    _set(e.config_file, "baseline.line_drift", -3)


def _break_tools(e: Engagement) -> None:
    _set(e.config_file, "tools", "t1")


def _break_engagement_yaml(e: Engagement) -> None:
    with e.config_file.open("a", encoding="utf-8") as fh:
        fh.write("report: [unclosed\n")


def _break_tool_yaml(e: Engagement) -> None:
    with e.tool_paths("t1").meta_file.open("a", encoding="utf-8") as fh:
        fh.write("origin: : [\n")


CASES = [
    pytest.param(_break_concurrency, "pipeline.concurrency", id="concurrency-zero"),
    pytest.param(_break_line_drift, "baseline.line_drift", id="line-drift-negative"),
    pytest.param(_break_tools, "tools", id="tools-not-a-list"),
    pytest.param(_break_engagement_yaml, "engagement.yaml", id="engagement-yaml-syntax"),
    pytest.param(_break_tool_yaml, "tools/t1/tool.yaml", id="tool-yaml-syntax"),
]


@pytest.mark.parametrize(("breaker", "named"), CASES)
@pytest.mark.parametrize("command", [["status"], ["run", "--dry-run"]])
def test_invalid_config_is_one_error_line_exit_2(eng, breaker, named, command):
    breaker(eng)
    r = runner.invoke(app, [*command, "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception  # nothing escaped
    assert "Traceback" not in r.output
    errors = [line for line in r.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1, r.output
    assert named in errors[0]


def test_each_problem_gets_its_own_line_naming_file_and_key(eng):
    _break_concurrency(eng)
    _break_line_drift(eng)
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    errors = [line for line in r.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 2, r.output
    assert all("engagement.yaml" in line for line in errors)
    assert any("pipeline.concurrency" in line and "'zero'" in line for line in errors)
    assert any("baseline.line_drift" in line for line in errors)


def test_invalid_tool_yaml_value_names_the_key(eng):
    _set(eng.tool_paths("t1").meta_file, "origin_kind", "ftp")
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "tools/t1/tool.yaml" in r.output and "origin_kind" in r.output
    assert "Traceback" not in r.output


def test_user_config_problem_names_the_user_config(eng, tmp_path):
    user = tmp_path / "user-config" / "config.yaml"
    user.parent.mkdir(parents=True)
    user.write_text("pipeline:\n  parallel_tools: many\n", encoding="utf-8")
    data = yaml.safe_load(eng.config_file.read_text(encoding="utf-8"))
    del data["pipeline"]  # so the user config's value is the one in force
    eng.config_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert str(user) in r.output and "pipeline.parallel_tools" in r.output


def test_square_brackets_in_the_message_survive(eng):
    _set(eng.config_file, "tools", "[t1")  # a string that looks like Rich markup
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "'[t1'" in r.output


def test_config_check_reports_scanner_options_of_the_wrong_type(eng):
    _set(eng.config_file, "scanners.oversized_files.file_lines", "lots")
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "scanners.oversized_files.file_lines" in r.output and "'lots'" in r.output


def test_config_check_accepts_the_default_scanner_options(eng):
    _set(eng.config_file, "scanners.bus_factor.single_author_share", 1)  # an int is a number
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "scanners." not in r.output


@pytest.mark.parametrize("which", ["engagement", "tool"])
def test_a_file_that_is_not_a_mapping_is_an_error(eng, which):
    path = eng.config_file if which == "engagement" else eng.tool_paths("t1").meta_file
    path.write_text("- just\n- a list\n", encoding="utf-8")
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "must contain a mapping" in r.output and "Traceback" not in r.output


def test_scanners_that_is_not_a_mapping_names_the_key(eng):
    _set(eng.config_file, "scanners", "lots")
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception
    assert "engagement.yaml: scanners:" in r.output and "'lots'" in r.output


def _other_args(command: str, eng: Engagement) -> list[str]:
    src = eng.root.parent / "src"
    return {
        "add": ["add", "t2", "--files", str(src)],
        "compare": ["compare"],
        "export": ["export"],
        "ask": ["ask", "what does it do?"],
        "cost": ["cost"],
        "config check": ["config", "check", "--no-probe"],
        "cache clear": ["cache", "clear", "--yes"],
        "scanners list": ["scanners", "list"],
    }[command]


@pytest.mark.parametrize("command", ["add", "compare", "export", "ask", "cost", "config check",
                                     "cache clear", "scanners list"])
def test_every_command_that_loads_the_engagement_reports_invalid_config(eng, command):
    _break_concurrency(eng)
    r = runner.invoke(app, [*_other_args(command, eng), "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception
    assert "Traceback" not in r.output
    assert "engagement.yaml: pipeline.concurrency" in r.output


@pytest.mark.parametrize("command", ["export", "ask"])
def test_commands_that_read_tools_refuse_an_invalid_tool_yaml(eng, command):
    _break_tool_yaml(eng)
    r = runner.invoke(app, [*_other_args(command, eng), "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception
    assert "tools/t1/tool.yaml: invalid YAML" in r.output


def test_a_long_value_is_shortened(eng):
    _set(eng.config_file, "pipeline.concurrency", "x" * 500)
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "x" * 50 in r.output and "x" * 100 not in r.output


def test_scanners_list_reports_an_invalid_engagement(eng):
    _break_tools(eng)
    r = runner.invoke(app, ["scanners", "list", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "tools" in r.output and "Traceback" not in r.output


FAKE_KEY = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz0123456789"  # split: not a real key


def test_a_key_pasted_into_the_wrong_field_is_not_printed(eng):
    _set(eng.config_file, "backends", {"claude": FAKE_KEY})  # a key where a mapping belongs
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "backends.claude" in r.output and "redacted" in r.output
    assert "abcdefghij" not in r.output


def test_config_check_does_not_print_a_key_given_as_a_scanner_option(eng):
    _set(eng.config_file, "scanners.client_exposure.client_roots", FAKE_KEY)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "scanners.client_exposure.client_roots" in r.output
    assert "abcdefghij" not in r.output


def test_config_check_shortens_a_long_scanner_option(eng):
    _set(eng.config_file, "scanners.client_exposure.client_roots", "x" * 500)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "x" * 50 in r.output and "x" * 100 not in r.output


def test_config_check_names_the_user_config_for_its_scanner_option(eng, tmp_path):
    user = tmp_path / "user-config" / "config.yaml"
    user.parent.mkdir(parents=True)
    user.write_text("scanners:\n  oversized_files:\n    file_lines: lots\n", encoding="utf-8")
    data = yaml.safe_load(eng.config_file.read_text(encoding="utf-8"))
    del data["scanners"]  # so the user config's value is the one in force
    eng.config_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    errors = [line for line in r.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1, r.output
    assert str(user) in errors[0] and "scanners.oversized_files.file_lines" in errors[0]


SECRET_PART = "abcdefghij"  # inside FAKE_KEY; must never reach the output


@pytest.mark.parametrize("where", [
    pytest.param(lambda e: _set(e.config_file, "scanners.secrets.effort",
                                {"credential": FAKE_KEY}), id="in-a-validator-message"),
    pytest.param(lambda e: _set(e.config_file, "scanners.hygiene.effort", {FAKE_KEY: "S"}),
                 id="as-an-effort-rule-name"),
    pytest.param(lambda e: _set(e.config_file, "backends", {FAKE_KEY: "x"}),
                 id="in-the-dotted-key"),
])
def test_a_key_anywhere_in_an_error_line_is_redacted(eng, where):
    where(eng)
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert "error:" in r.output and "redacted" in r.output
    assert SECRET_PART not in r.output


def test_a_key_used_as_an_unknown_setting_is_redacted(eng, caplog):
    _set(eng.config_file, FAKE_KEY, 1)
    with caplog.at_level("WARNING", logger="unvarnish.config"):
        r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(eng.root)])
    assert "unknown setting" in r.output and "unknown setting" in caplog.text
    assert SECRET_PART not in r.output and SECRET_PART not in caplog.text


def test_a_config_error_never_holds_a_key():
    from unvarnish.config import ConfigError

    exc = ConfigError([f"engagement.yaml: x: {FAKE_KEY}"])
    assert SECRET_PART not in str(exc) and SECRET_PART not in "".join(exc.problems)


@pytest.mark.parametrize("which", ["engagement", "tool"])
def test_a_file_that_is_not_utf8_is_one_error_line(eng, which):
    path = eng.config_file if which == "engagement" else eng.tool_paths("t1").meta_file
    path.write_bytes(path.read_text(encoding="utf-8").encode("utf-16"))  # Notepad, PowerShell
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception
    errors = [line for line in r.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1 and "UTF-8" in errors[0], r.output
    assert ("engagement.yaml" if which == "engagement" else "tools/t1/tool.yaml") in errors[0]


def test_a_tool_yaml_that_cannot_be_read_is_one_error_line(eng):
    meta = eng.tool_paths("t1").meta_file
    meta.unlink()
    meta.mkdir()  # exists, but reading it fails (IsADirectoryError, an OSError)
    r = runner.invoke(app, ["status", "-e", str(eng.root)])
    assert r.exit_code == 2, r.output
    assert isinstance(r.exception, SystemExit), r.exception
    assert "error: tools/t1/tool.yaml: cannot be read" in r.output
