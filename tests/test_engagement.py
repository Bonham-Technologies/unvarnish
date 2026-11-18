from pathlib import Path

import pytest
from typer.testing import CliRunner

from unvarnish.cli import app
from unvarnish.engagement import (
    Engagement,
    EngagementExists,
    NotAnEngagement,
)

runner = CliRunner()


def test_create_makes_layout_and_config(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme", client="Acme")
    assert (eng.root / "engagement.yaml").exists()
    for d in ("tools", "comparison", "exports", "cache", "logs"):
        assert (eng.root / d).is_dir()
    assert eng.config.client == "Acme"


def test_create_refuses_existing_engagement(tmp_path: Path):
    Engagement.create(tmp_path / "acme")
    with pytest.raises(EngagementExists):
        Engagement.create(tmp_path / "acme")


def test_load_round_trip(tmp_path: Path):
    Engagement.create(tmp_path / "acme", client="Acme", consultant="BT")
    eng = Engagement.load(tmp_path / "acme")
    assert eng.config.client == "Acme"
    assert eng.config.consultant == "BT"


def test_load_non_engagement_raises(tmp_path: Path):
    with pytest.raises(NotAnEngagement):
        Engagement.load(tmp_path)


def test_find_walks_up(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    nested = eng.root / "tools" / "x" / "deep"
    nested.mkdir(parents=True)
    assert Engagement.find(nested).root == eng.root


def test_register_tool_validates_and_persists(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    eng.register_tool("expense-bot")
    eng.register_tool("expense-bot")  # idempotent
    assert Engagement.load(eng.root).tool_names() == ["expense-bot"]
    with pytest.raises(ValueError):
        eng.register_tool("Bad Name!")


def test_tool_paths_layout(tmp_path: Path):
    eng = Engagement.create(tmp_path / "acme")
    p = eng.tool_paths("expense-bot")
    assert p.root == eng.root / "tools" / "expense-bot"
    assert p.census == p.root / "inventory" / "census.json"
    assert p.scanner_findings == p.root / "inventory" / "scanner-findings.json"
    assert p.findings_doc == p.root / "docs" / "findings.md"
    assert p.meta_file == p.root / "tool.yaml"


def test_cli_init(tmp_path: Path):
    result = runner.invoke(app, ["init", str(tmp_path / "acme"), "--client", "Acme"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme" / "engagement.yaml").exists()
    again = runner.invoke(app, ["init", str(tmp_path / "acme")])
    assert again.exit_code == 2
