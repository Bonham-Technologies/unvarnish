"""Square brackets in exception and user text survive Rich markup (UNVAR-53)."""

from typer.testing import CliRunner

from unvarnish.cli import app

runner = CliRunner()


def test_bad_tool_name_error_shows_the_full_rule(engagement, synthetic_repo):
    r = runner.invoke(app, ["add", "Bad Name", "--repo", str(synthetic_repo),
                            "-e", str(engagement.root)])
    assert r.exit_code == 2
    assert "^[a-z0-9][a-z0-9_-]{0,63}$" in r.output.replace("\n", "")


def test_init_error_keeps_brackets(tmp_path, monkeypatch):
    from unvarnish import cli
    from unvarnish.engagement import EngagementError

    def boom(*_a, **_k):
        raise EngagementError("bad [red]thing[/red] [x]")

    monkeypatch.setattr(cli.Engagement, "create", boom)
    r = runner.invoke(app, ["init", str(tmp_path / "e")])
    assert r.exit_code == 2
    assert "bad [red]thing[/red] [x]" in r.output


def test_unknown_tool_name_with_brackets_is_echoed(engagement, synthetic_repo):
    runner.invoke(app, ["add", "ok-tool", "--repo", str(synthetic_repo),
                        "-e", str(engagement.root)])
    r = runner.invoke(app, ["ask", "q", "--tool", "[b]x[/b]", "-e", str(engagement.root)])
    assert r.exit_code == 2
    assert "[b]x[/b]" in r.output


def test_config_check_backend_error_keeps_brackets(engagement, monkeypatch):
    from unvarnish import cli
    from unvarnish.config import EngagementConfig
    from unvarnish.model.base import BackendConfigError

    data = engagement.config.model_dump()
    data["models"] = {"default": {"backend": "openai_compatible", "model": "m[a-z]"}}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()

    def boom(*_a, **_k):
        raise BackendConfigError("set [bold]KEY[/bold] for [a-z]")

    monkeypatch.setattr(cli, "resolve_backend", boom)
    r = runner.invoke(app, ["config", "check", "--no-probe", "-e", str(engagement.root)],
                      env={"COLUMNS": "400"})
    assert r.exit_code == 2
    assert "set [bold]KEY[/bold] for [a-z]" in r.output
    assert "m[a-z]" in r.output  # the model name in the table


def test_export_failure_detail_keeps_brackets(engagement, synthetic_repo, monkeypatch):
    from unvarnish import cli
    from unvarnish.export.exporter import ExportItem, ExportReport

    report = ExportReport(items=[ExportItem(doc="findings", tool="t", fmt="pdf",
                                            status="failed", detail="pandoc: [b]x[/b]")])
    runner.invoke(app, ["add", "t", "--repo", str(synthetic_repo), "-e", str(engagement.root)])
    monkeypatch.setattr(cli, "export_engagement", lambda *_a, **_k: report)
    r = runner.invoke(app, ["export", "-e", str(engagement.root)], env={"COLUMNS": "400"})
    assert "pandoc: [b]x[/b]" in r.output


def test_scanners_list_keeps_brackets_in_options(engagement):
    from unvarnish.config import EngagementConfig

    data = engagement.config.model_dump()
    data["scanners"] = {"hygiene": {"ignore": "[a-z]+\\.tmp"}}
    engagement.config = EngagementConfig.model_validate(data)
    engagement.save_config()
    r = runner.invoke(app, ["scanners", "list", "-e", str(engagement.root)],
                      env={"COLUMNS": "400"})
    assert r.exit_code == 0, r.output
    assert "ignore=[a-z]+\\.tmp" in r.output
