import pytest
from pydantic import ValidationError

from unvarnish.schemas.finding import (
    SEVERITY_ORDER,
    Category,
    Evidence,
    Finding,
    Severity,
    Source,
    Verification,
)


def _finding(**overrides) -> Finding:
    base = dict(
        tool="expense-bot",
        category=Category.security,
        severity=Severity.critical,
        title="AWS access key committed",
        summary="A key is in app.py.",
        impact="Anyone with repo access can use the key.",
        remediation="Rotate and move to a secret store.",
        evidence=[Evidence(path="app.py", line_start=2, line_end=2)],
        source=Source.scanner,
        scanner="secrets",
    )
    base.update(overrides)
    return Finding(**base)


def test_id_is_derived_and_stable():
    a = _finding()
    b = _finding(summary="different prose")
    assert a.id == b.id
    assert len(a.id) == 16


def test_id_changes_with_evidence_location():
    a = _finding()
    b = _finding(evidence=[Evidence(path="app.py", line_start=9)])
    assert a.id != b.id


def test_evidence_required():
    with pytest.raises(ValidationError):
        _finding(evidence=[])


def test_scanner_findings_default_to_not_required_verification():
    assert _finding().verification == Verification.not_required


def test_model_findings_keep_verification_none():
    f = _finding(source=Source.model, scanner=None, model="claude", confidence=0.8)
    assert f.verification is None


def test_evidence_path_must_be_relative_posix():
    with pytest.raises(ValidationError):
        Evidence(path="/abs/app.py")
    with pytest.raises(ValidationError):
        Evidence(path="dir\\app.py")


def test_severity_order():
    assert SEVERITY_ORDER[Severity.critical] < SEVERITY_ORDER[Severity.info]
    assert sorted(Severity, key=SEVERITY_ORDER.__getitem__)[0] == Severity.critical


def test_id_includes_fingerprint_when_present():
    a = _finding(evidence=[Evidence(path="app.py", fingerprint="aaaaaaaaaaaa")])
    b = _finding(evidence=[Evidence(path="app.py", fingerprint="bbbbbbbbbbbb")])
    assert a.id != b.id
