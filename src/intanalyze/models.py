"""Pydantic data models shared by every stage of the pipeline."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    EXPECTED = "EXPECTED"
    CHANGED = "CHANGED"
    SUSPICIOUS = "SUSPICIOUS"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


class Relationship(StrEnum):
    IDENTICAL = "IDENTICAL"
    MODIFIED = "MODIFIED"
    ONLY_IN_PACKAGE = "ONLY_IN_PACKAGE"
    ONLY_IN_SOURCE = "ONLY_IN_SOURCE"


class Status(StrEnum):
    CLEAN = "CLEAN"
    REVIEW = "REVIEW"
    DANGEROUS = "DANGEROUS"


# npm names: optional "@scope/" then a lowercase-ish name; versions are anything after the last "@".
_NAME_RE = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)


class PackageSpec(BaseModel):
    name: str
    version: str

    @classmethod
    def parse(cls, spec: str) -> PackageSpec:
        """Parse "name@version" or "@scope/name@version"."""
        spec = spec.strip()
        at = spec.rfind("@")
        if at <= 0:
            raise ValueError(f"expected <name>@<version>, got {spec!r}")
        name, version = spec[:at], spec[at + 1 :]
        if not version or not _NAME_RE.match(name):
            raise ValueError(f"expected <name>@<version>, got {spec!r}")
        return cls(name=name, version=version)

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"


class FileDiff(BaseModel):
    """How one path in the package relates to the same path in the source."""

    path: str
    relationship: Relationship
    package_sha256: str | None = None
    source_sha256: str | None = None
    size: int = 0
    is_binary: bool = False
    # Over the per-file analysis limit: hashed, but not scanned or diffed.
    too_large: bool = False
    diff: str | None = None
    diff_truncated: bool = False
    lines_added: int = 0
    lines_removed: int = 0


class Explanation(BaseModel):
    summary: str
    why_it_matters: str
    recommended_action: str


class Finding(BaseModel):
    path: str
    verdict: Verdict
    severity: Severity
    relationship: Relationship
    rule_ids: list[str] = Field(default_factory=list)
    reason: str
    evidence: list[str] = Field(default_factory=list)
    mapped_source: str | None = None
    diff: str | None = None
    explanation: Explanation | None = None
    explanation_source: Literal["llm", "rules"] = "rules"


class IntegrityResult(BaseModel):
    checked: bool = False
    algorithm: str | None = None
    expected: str | None = None
    actual: str | None = None
    ok: bool | None = None


class SourceInfo(BaseModel):
    repo_url: str | None = None
    ref: str | None = None
    ref_kind: Literal["cli", "gitHead", "tag", "local"] | None = None
    directory: str | None = None


class LLMInfo(BaseModel):
    used: bool = False
    server: str | None = None
    model: str | None = None
    reason: str | None = None


class Report(BaseModel):
    tool_version: str
    package: PackageSpec
    tarball_url: str | None = None
    source: SourceInfo = Field(default_factory=SourceInfo)
    integrity: IntegrityResult = Field(default_factory=IntegrityResult)
    findings: list[Finding] = Field(default_factory=list)
    expected_counts: dict[str, int] = Field(default_factory=dict)
    files_in_package: int = 0
    files_in_source: int = 0
    score: int = 0
    status: Status = Status.CLEAN
    llm: LLMInfo = Field(default_factory=LLMInfo)
    summary: str | None = None
