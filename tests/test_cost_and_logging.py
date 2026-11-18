import logging
from datetime import UTC, datetime

from typer.testing import CliRunner

from tests.conftest import model_config
from unvarnish.cli import app
from unvarnish.config import EngagementConfig
from unvarnish.engagement import Engagement
from unvarnish.model.budget import record_cost
from unvarnish.model.estimate import (
    OUTPUT_TOKENS_PER_UNIT,
    SYSTEM_PROMPT_TOKENS,
    estimate_extract,
)
from unvarnish.phases import default_phases
from unvarnish.schemas.analysis import Unit, UnitKind, UnitsIndex
from unvarnish.schemas.cost import CostEntry, Usage
from unvarnish.util.logging import setup_run_logging

runner = CliRunner()


def test_default_phase_order():
    assert [p.name for p in default_phases()] == [
        "inventory", "git", "scan", "split", "extract", "rollup_modules", "rollup_tool",
        "verify", "render",
    ]


def test_estimate_extract_counts_remaining_units():
    units = [Unit(id=f"u{i}", tool="t", module_id="a", path="a", language="python",
                  kind=UnitKind.group, line_start=1, line_end=2, byte_start=0, byte_end=1,
                  token_estimate=1000, split_method="structural") for i in range(3)]
    idx = UnitsIndex(tool="t", unit_tokens=8000, units=units, modules={"a": ["u0", "u1", "u2"]})
    est = estimate_extract(idx)
    assert est.input_tokens == 3 * (SYSTEM_PROMPT_TOKENS + 1000 + 300)
    assert est.output_tokens == 3 * OUTPUT_TOKENS_PER_UNIT
    assert estimate_extract(idx, done_ids={"u0"}).output_tokens == 2 * OUTPUT_TOKENS_PER_UNIT


def test_setup_run_logging_writes_file(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    path = setup_run_logging(eng)
    logging.getLogger("unvarnish.test").info("hello from the test")
    logging.getLogger("unvarnish.test").debug("debug detail")
    for h in logging.getLogger("unvarnish").handlers:
        h.flush()
    text = path.read_text()
    assert path.parent == eng.logs_dir
    assert "hello from the test" in text and "debug detail" in text
    setup_run_logging(eng)  # idempotent: no duplicate handlers
    ours = [h for h in logging.getLogger("unvarnish").handlers if getattr(h, "_unvarnish", False)]
    assert len(ours) == 2


def test_cost_command(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    record_cost(eng, CostEntry(tool="x", phase="extract", backend="b", model="m",
                               usage=Usage(input_tokens=1_000_000, output_tokens=50_000),
                               at=datetime.now(UTC)))
    r = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert r.exit_code == 0 and "extract" in r.output and "1,000,000" in r.output
    assert "USD" not in r.output
    eng.config = EngagementConfig.model_validate({
        **eng.config.model_dump(),
        "budget": {"prices": {"input_per_mtok": 4.0, "output_per_mtok": 20.0}},
    })
    eng.save_config()
    r = runner.invoke(app, ["cost", "-e", str(eng.root)])
    assert "USD" in r.output and "5.00" in r.output


def test_dry_run_shows_estimate(tmp_path, synthetic_repo, fake_llm):
    eng = Engagement.create(tmp_path / "e", client="Acme")
    eng.config = EngagementConfig.model_validate({**eng.config.model_dump(),
                                                  **model_config(fake_llm)})
    eng.save_config()
    r = runner.invoke(app, ["add", "bot", "--repo", str(synthetic_repo), "-e", str(eng.root)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["run", "--dry-run", "-e", str(eng.root)])
    assert r.exit_code == 0, r.output
    assert "extract" in r.output and "estimate" in r.output.lower()
    assert not (eng.root / "tools" / "bot" / "analysis" / "units.json").exists()


LEDGER_WRITER = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from unvarnish.engagement import Engagement
from unvarnish.model.budget import record_cost
from unvarnish.schemas.cost import CostEntry, Usage
eng = Engagement.load(Path(sys.argv[1]))
for _ in range(int(sys.argv[2])):
    record_cost(eng, CostEntry(tool="x", phase=sys.argv[3], backend="b", model="m",
                               usage=Usage(input_tokens=1), at=datetime.now(UTC)))
"""


def test_ledger_writes_from_separate_processes_are_not_lost(tmp_path):
    """UNVAR-33: `config check` records cost while a `run` in another process may be writing
    the ledger; a read-modify-write that only a thread lock guards drops entries or crashes."""
    import subprocess
    import sys

    from unvarnish.model.budget import load_ledger

    eng = Engagement.create(tmp_path / "e")
    procs = [subprocess.Popen([sys.executable, "-c", LEDGER_WRITER, str(eng.root), "40",
                               f"p{i}"], stderr=subprocess.PIPE, text=True) for i in range(4)]
    errors = [p.communicate(timeout=120)[1] for p in procs]
    assert all(p.returncode == 0 for p in procs), errors
    assert len(load_ledger(eng).entries) == 160


def test_a_filesystem_without_flock_still_records_cost(tmp_path, monkeypatch):
    import errno

    from unvarnish.model import budget

    def refuse(fd, op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(budget.fcntl, "flock", refuse)
    eng = Engagement.create(tmp_path / "e")
    record_cost(eng, CostEntry(tool="x", phase="config-check", backend="b", model="m",
                               usage=Usage(input_tokens=5), at=datetime.now(UTC)))
    assert len(budget.load_ledger(eng).entries) == 1
