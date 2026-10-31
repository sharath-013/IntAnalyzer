"""Rule engine: turn file-level differences into findings with verdicts and severities."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from intanalyze.diff import read_text
from intanalyze.models import Explanation, FileDiff, Finding, Relationship, Severity, Verdict
from intanalyze.rules import RULES
from intanalyze.rules.build_mapping import is_code, map_to_source
from intanalyze.rules.manifest import (
    ManifestIssue,
    compare_manifests,
    compare_registry_manifest,
)
from intanalyze.rules.obfuscation import new_dangerous_signals, obfuscation_signals, scan

MAX_EVIDENCE = 12
_DOC_RE = re.compile(
    r"^(readme|license|licence|copying|changelog|changes|history|authors|notice|contributing)"
    r"(\.[\w.-]+)?$",
    re.IGNORECASE,
)


@dataclass
class ClassifyResult:
    findings: list[Finding]
    expected_counts: Counter[str] = field(default_factory=Counter)


def _is_doc(path: str) -> bool:
    return bool(_DOC_RE.match(path.rsplit("/", 1)[-1]))


def _loose(text: str | None) -> str | None:
    return " ".join(text.lower().split()) if text is not None else None


def _load_json(path: Path) -> dict | None:
    text = read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _cap(evidence: list[str]) -> list[str]:
    if len(evidence) <= MAX_EVIDENCE:
        return evidence
    return evidence[:MAX_EVIDENCE] + [f"... and {len(evidence) - MAX_EVIDENCE} more"]


def rule_explanation(finding: Finding) -> Explanation:
    """Fallback explanation built only from rule text (used when no LLM is available)."""
    rules = "; ".join(f"{r}: {RULES[r]}" for r in finding.rule_ids if r in RULES)
    action = {
        Verdict.SUSPICIOUS: "Do not install this version until the difference is understood; "
        "compare it with the source and the maintainers' release notes.",
        Verdict.CHANGED: "Review the difference and confirm it is an intended part of the "
        "release build.",
        Verdict.EXPECTED: "No action needed.",
    }[finding.verdict]
    return Explanation(
        summary=finding.reason,
        why_it_matters=rules or finding.reason,
        recommended_action=action,
    )


def _finding(fd: FileDiff, verdict, severity, rule_ids, reason, evidence, **extra) -> Finding:
    f = Finding(
        path=fd.path,
        verdict=verdict,
        severity=severity,
        relationship=fd.relationship,
        rule_ids=list(dict.fromkeys(rule_ids)),
        reason=reason,
        evidence=_cap(evidence),
        **extra,
    )
    f.explanation = rule_explanation(f)
    return f


def _doc_matches_source(fd: FileDiff, pkg: Path, src: Path, src_files: set[str]) -> str | None:
    """Source doc file (same dir, any letter case) whose text matches ignoring case/whitespace."""
    if not _is_doc(fd.path):
        return None
    pkg_text = _loose(read_text(pkg / fd.path))
    if pkg_text is None:
        return None
    folder, _, name = fd.path.rpartition("/")
    for cand in sorted(src_files):
        c_folder, _, c_name = cand.rpartition("/")
        if c_folder == folder and c_name.lower() == name.lower():
            if _loose(read_text(src / cand)) == pkg_text:
                return cand
    return None


def _classify_package_only(
    fd: FileDiff, pkg: Path, src: Path, src_files: set[str], counts: Counter[str]
) -> tuple[Finding | None, bool]:
    """Returns (finding, is_unexplained)."""
    if fd.too_large:
        return (
            _finding(
                fd, Verdict.SUSPICIOUS, Severity.MEDIUM, ["IA-FILE-001"],
                "file found nowhere in the repo (too large to analyse)",
                [f"{fd.size} bytes, over the 20 MB analysis limit"],
            ),
            True,
        )

    doc_src = _doc_matches_source(fd, pkg, src, src_files)
    if doc_src:
        counts["docs"] += 1
        return (
            _finding(
                fd, Verdict.EXPECTED, Severity.INFO, [],
                f"same document as {doc_src} (case/whitespace only)",
                [f"matches source {doc_src}"], mapped_source=doc_src,
            ),
            False,
        )

    mapped = map_to_source(fd.path, src_files)
    text = None if fd.is_binary else read_text(pkg / fd.path)

    if mapped:
        signals = []
        if text is not None and is_code(fd.path):
            src_text = read_text(src / mapped)
            signals = obfuscation_signals(text, path=fd.path, minified_ok=True)
            signals += new_dangerous_signals(text, src_text)
        if signals:
            return (
                _finding(
                    fd, Verdict.SUSPICIOUS, Severity.HIGH, ["IA-CODE-001"],
                    f"build output of {mapped} contains code its source does not",
                    [f"maps to source {mapped}"] + [s.evidence() for s in signals],
                    mapped_source=mapped,
                ),
                False,
            )
        counts["build_output"] += 1
        return (
            _finding(
                fd, Verdict.EXPECTED, Severity.INFO, [],
                f"compiled output of {mapped}",
                [f"maps to source {mapped}"], mapped_source=mapped,
            ),
            False,
        )

    if fd.is_binary:
        return (
            _finding(
                fd, Verdict.SUSPICIOUS, Severity.MEDIUM, ["IA-FILE-001"],
                "binary file found nowhere in the repo",
                [f"binary, {fd.size} bytes, sha256 {fd.package_sha256}"],
            ),
            True,
        )

    signals = scan(text or "", path=fd.path)
    if signals:
        return (
            _finding(
                fd, Verdict.SUSPICIOUS, Severity.HIGH, ["IA-CODE-001"],
                "file found nowhere in the repo, with obfuscation or dangerous APIs",
                [s.evidence() for s in signals],
            ),
            True,
        )
    return (
        _finding(
            fd, Verdict.SUSPICIOUS, Severity.MEDIUM, ["IA-FILE-001"],
            "file found nowhere in the repo",
            [f"{fd.size} bytes, sha256 {fd.package_sha256}"],
        ),
        True,
    )


def _classify_modified(
    fd: FileDiff, pkg: Path, src: Path, src_files: set[str], counts: Counter[str]
) -> Finding:
    if fd.is_binary or fd.too_large:
        why = "binary" if fd.is_binary else "over the 20 MB analysis limit"
        return _finding(
            fd, Verdict.CHANGED, Severity.MEDIUM, ["IA-FILE-002"],
            "file differs from the source",
            [f"content differs ({why}); package sha256 {fd.package_sha256}"],
        )

    pkg_text = read_text(pkg / fd.path) or ""
    src_text = read_text(src / fd.path)

    if _is_doc(fd.path) and _loose(pkg_text) == _loose(src_text):
        counts["docs"] += 1
        return _finding(
            fd, Verdict.EXPECTED, Severity.INFO, [],
            "only case/whitespace differences", ["case/whitespace-only change"],
        )

    added = new_dangerous_signals(pkg_text, src_text)
    mapped = map_to_source(fd.path, src_files)
    if mapped and is_code(fd.path):
        # Committed build output that was rebuilt: judge it against the real source too.
        added = [s for s in added if s in new_dangerous_signals(pkg_text, read_text(src / mapped))]

    if added:
        return _finding(
            fd, Verdict.SUSPICIOUS, Severity.HIGH, ["IA-CODE-002"],
            "package version adds dangerous APIs absent from the source",
            [s.evidence() for s in added], diff=fd.diff,
        )
    if mapped:
        counts["build_output"] += 1
        return _finding(
            fd, Verdict.EXPECTED, Severity.INFO, [],
            f"rebuilt output of {mapped}", [f"maps to source {mapped}"], mapped_source=mapped,
        )
    plus, minus = fd.lines_added, fd.lines_removed
    note = " (diff truncated)" if fd.diff_truncated else ""
    if plus == 0:
        # Tools like clean-publish strip comments/docs at publish time; removing lines adds
        # no new code, so this is worth a look but not a medium-risk change.
        return _finding(
            fd, Verdict.CHANGED, Severity.LOW, ["IA-FILE-002"],
            "package version only removes lines from the source",
            [f"+0 / -{minus} lines{note}"], diff=fd.diff,
        )
    return _finding(
        fd, Verdict.CHANGED, Severity.MEDIUM, ["IA-FILE-002"],
        "file differs from the source",
        [f"+{plus} / -{minus} lines{note}"], diff=fd.diff,
    )


def _manifest_finding(fd: FileDiff, issues: list[ManifestIssue], diff: str | None) -> Finding:
    worst = max(issues, key=lambda i: i.severity.rank)
    verdict = (
        Verdict.SUSPICIOUS
        if any(i.verdict is Verdict.SUSPICIOUS for i in issues)
        else Verdict.CHANGED
    )
    reasons = {
        "IA-MANIFEST-001": "install-time script not in the source",
        "IA-MANIFEST-003": "typosquat-like new dependency",
        "IA-MANIFEST-004": "entry point to a file not in the source",
        "IA-MANIFEST-006": "registry metadata does not match the tarball",
        "IA-MANIFEST-002": "new dependency not in the source",
        "IA-MANIFEST-005": "manifest fields differ from the source",
    }
    rule_ids = sorted({i.rule_id for i in issues}, key=list(reasons).index)
    return _finding(
        fd, verdict, worst.severity, rule_ids,
        "package.json: " + ", ".join(reasons[r] for r in rule_ids),
        [i.evidence for i in sorted(issues, key=lambda i: -i.severity.rank)],
        diff=diff,
    )


def classify(
    diffs: list[FileDiff],
    package_root: Path,
    source_root: Path,
    *,
    registry_manifest: dict | None = None,
) -> ClassifyResult:
    pkg, src = Path(package_root), Path(source_root)
    src_files = {d.path for d in diffs if d.relationship is not Relationship.ONLY_IN_PACKAGE}
    counts: Counter[str] = Counter()
    findings: list[Finding] = []
    unexplained: set[str] = set()
    manifest_fd: FileDiff | None = None

    for fd in diffs:
        if fd.path == "package.json" and fd.relationship is not Relationship.ONLY_IN_SOURCE:
            manifest_fd = fd
            continue
        if fd.relationship is Relationship.IDENTICAL:
            counts["identical"] += 1
        elif fd.relationship is Relationship.ONLY_IN_SOURCE:
            counts["only_in_source"] += 1
        elif fd.relationship is Relationship.ONLY_IN_PACKAGE:
            finding, is_unexplained = _classify_package_only(fd, pkg, src, src_files, counts)
            if is_unexplained:
                unexplained.add(fd.path)
            if finding:
                findings.append(finding)
        else:
            findings.append(_classify_modified(fd, pkg, src, src_files, counts))

    if manifest_fd is not None:
        pkg_manifest = _load_json(pkg / "package.json") or {}
        src_manifest = (
            _load_json(src / "package.json")
            if manifest_fd.relationship is not Relationship.ONLY_IN_PACKAGE
            else None
        )
        issues = compare_manifests(src_manifest, pkg_manifest, unexplained_files=unexplained)
        issues += compare_registry_manifest(registry_manifest, pkg_manifest)
        if issues:
            findings.append(_manifest_finding(manifest_fd, issues, manifest_fd.diff))
        else:
            counts["manifest"] += 1
            findings.append(
                _finding(
                    manifest_fd, Verdict.EXPECTED, Severity.INFO, [],
                    "package.json matches the source (ignoring version/gitHead/_ fields)",
                    ["no meaningful manifest differences"],
                )
            )

    findings.sort(key=lambda f: (-f.severity.rank, f.path))
    return ClassifyResult(findings=findings, expected_counts=counts)
