from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from unvarnish.config import BackendConfig, EngagementConfig, ModelRef, Prices
from unvarnish.engagement import Engagement
from unvarnish.schemas.analysis import (
    CandidateFinding,
    Unit,
    UnitExtraction,
    UnitKind,
    UnitsIndex,
)
from unvarnish.schemas.cost import CostEntry, CostLedger, Usage
from unvarnish.schemas.finding import Category, Severity


def test_usage_adds_and_totals():
    a = Usage(input_tokens=10, output_tokens=5, cache_read_tokens=3)
    b = Usage(input_tokens=1, cache_write_tokens=2)
    s = a + b
    assert (s.input_tokens, s.output_tokens, s.cache_read_tokens, s.cache_write_tokens) == (
        11, 5, 3, 2,
    )
    assert s.total() == 21


def test_cost_ledger_totals_and_estimate():
    led = CostLedger(entries=[
        CostEntry(tool="t", phase="extract", backend="a", model="m",
                  usage=Usage(input_tokens=1_000_000, output_tokens=100_000), at=datetime.now(UTC)),
        CostEntry(tool="t", phase="verify", backend="a", model="m",
                  usage=Usage(input_tokens=500_000), at=datetime.now(UTC)),
    ])
    assert led.total().input_tokens == 1_500_000
    assert led.by_phase()["extract"].output_tokens == 100_000
    assert led.estimate_usd(Prices(input_per_mtok=4.0, output_per_mtok=20.0)) == pytest.approx(8.0)
    assert led.estimate_usd(None) is None


def test_unit_and_index_shapes():
    u = Unit(id="abc", tool="t", module_id="a.py", path="a.py", language="python",
             kind=UnitKind.function, name="f", line_start=1, line_end=10, byte_start=0,
             byte_end=120, token_estimate=40, split_method="structural")
    idx = UnitsIndex(tool="t", unit_tokens=8000, units=[u], modules={"a.py": ["abc"]}, skipped=[])
    assert idx.modules["a.py"] == ["abc"]
    assert u.generated is False


def test_candidate_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        CandidateFinding(category=Category.security, severity=Severity.high, title="t", summary="s",
                         impact="i", remediation="r", line_start=1, line_end=2, excerpt=None,
                         confidence=1.5)


def test_unit_extraction_minimal():
    ex = UnitExtraction(purpose="p", interface=[], external_calls=[], data_read=[], data_written=[],
                        auth_behaviour=None, error_handling=None, risks=[], candidate_findings=[],
                        confidence=0.5)
    assert ex.purpose == "p"


def test_config_additions():
    cfg = EngagementConfig(backends={"b": {"type": "anthropic", "unit_tokens": 4000}},
                           models={"default": {"backend": "b", "model": "m", "effort": "high"}})
    assert cfg.backends["b"].unit_tokens == 4000
    assert cfg.models.default is not None and cfg.models.default.effort == "high"
    assert BackendConfig(type="anthropic").unit_tokens is None
    assert ModelRef(backend="b", model="m").effort is None


def test_new_paths(tmp_path):
    eng = Engagement.create(tmp_path / "e")
    p = eng.tool_paths("x")
    assert p.units_index == p.analysis / "units.json"
    assert p.unit_dir == p.analysis / "units"
    assert p.extract_state == p.analysis / "extract-state.json"
    assert p.run_record == p.analysis / "run-record.json"
    assert p.failures == p.analysis / "failures.json"
    assert eng.cost_file == eng.root / "cost.json"
