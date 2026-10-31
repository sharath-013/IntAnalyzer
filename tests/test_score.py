import pytest

from intanalyze.models import Finding, Relationship, Severity, Status, Verdict
from intanalyze.score import exit_code, risk_score, status_for


def _f(sev, verdict=Verdict.SUSPICIOUS):
    return Finding(
        path="x", verdict=verdict, severity=sev, relationship=Relationship.MODIFIED, reason="r"
    )


def test_weights_and_cap():
    assert risk_score([]) == 0
    assert risk_score([_f(Severity.HIGH)]) == 40
    assert risk_score([_f(Severity.MEDIUM), _f(Severity.LOW), _f(Severity.INFO)]) == 12
    assert risk_score([_f(Severity.HIGH)] * 5) == 100


def test_expected_findings_never_score():
    assert risk_score([_f(Severity.HIGH, Verdict.EXPECTED)]) == 0


@pytest.mark.parametrize(
    ("score", "status"),
    [(0, Status.CLEAN), (1, Status.REVIEW), (39, Status.REVIEW), (40, Status.DANGEROUS)],
)
def test_status(score, status):
    assert status_for(score) is status


@pytest.mark.parametrize(
    ("severity", "fail_on", "code"),
    [
        (Severity.HIGH, "high", 1),
        (Severity.MEDIUM, "high", 0),
        (Severity.MEDIUM, "medium", 1),
        (Severity.LOW, "medium", 0),
        (Severity.LOW, "low", 1),
        (Severity.HIGH, "never", 0),
    ],
)
def test_exit_code(severity, fail_on, code):
    assert exit_code([_f(severity)], fail_on) == code


def test_expected_findings_never_fail():
    assert exit_code([_f(Severity.HIGH, Verdict.EXPECTED)], "low") == 0
