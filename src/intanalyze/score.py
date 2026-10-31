"""Overall risk score, status and exit code."""

from __future__ import annotations

from collections.abc import Iterable

from intanalyze.models import Finding, Severity, Status, Verdict

WEIGHTS = {Severity.HIGH: 40, Severity.MEDIUM: 10, Severity.LOW: 2, Severity.INFO: 0}
FAIL_ON = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


def risk_score(findings: Iterable[Finding]) -> int:
    total = sum(WEIGHTS[f.severity] for f in findings if f.verdict is not Verdict.EXPECTED)
    return min(total, 100)


def status_for(score: int) -> Status:
    if score == 0:
        return Status.CLEAN
    return Status.DANGEROUS if score >= 40 else Status.REVIEW


def exit_code(findings: Iterable[Finding], fail_on: str = "high") -> int:
    """1 if any non-EXPECTED finding is at or above the ``fail_on`` severity, else 0."""
    if fail_on == "never":
        return 0
    threshold = FAIL_ON[fail_on].rank
    hit = any(
        f.verdict is not Verdict.EXPECTED and f.severity.rank >= threshold for f in findings
    )
    return 1 if hit else 0
