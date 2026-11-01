"""Rule engine: turn file-level differences into findings with verdicts and severities."""

from __future__ import annotations

import json
import posixpath
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


# A "README.js" is code, not a document: only these endings count as documentation.
_DOC_EXTS = frozenset({"", ".md", ".markdown", ".txt", ".rst", ".adoc"})


def _is_doc(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    ext = name[name.index("."):].lower() if "." in name else ""
    return bool(_DOC_RE.match(name)) and ext in _DOC_EXTS


# The standard build-time entry switch (react, react-dom, scheduler, ...):
#   'use strict';
#   if (process.env.NODE_ENV === 'production') { module.exports = require('./cjs/x.prod.js'); }
#   else { module.exports = require('./cjs/x.dev.js'); }
# Every token below is allowed; anything left over means it is not just a switch.
_SHIM_TOKENS = re.compile(
    r"""\s+|/\*.*?\*/|//[^\n]*|['"]use strict['"];?"""
    r"""|if\s*\(\s*process\.env\.NODE_ENV\s*[!=]==?\s*['"][\w-]+['"]\s*\)\s*\{?"""
    r"""|\}?\s*else\s*\{?|\}"""
    r"""|module\.exports\s*=\s*require\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)\s*;?""",
    re.DOTALL,
)


def _entry_shim_targets(path: str, text: str, pkg: Path) -> list[str] | None:
    """Files an environment entry switch loads, if ``text`` is only such a switch and every
    file it loads exists inside the package; else None."""
    targets: list[str] = []
    pos = 0
    for m in _SHIM_TOKENS.finditer(text):
        if m.start() != pos:
            return None
        if m.group(1):
            targets.append(m.group(1))
        pos = m.end()
    if pos != len(text) or not targets:
        return None
    folder = posixpath.dirname(path)
    found = []
    for target in targets:
        rel = posixpath.normpath(posixpath.join(folder, target))
        if rel.startswith("../") or rel == "..":
            return None
        for cand in (rel, rel + ".js", rel + "/index.js"):
            if cand.endswith((".js", ".cjs", ".mjs")) and (pkg / cand).is_file():
                found.append(cand)
                break
        else:
            return None
    return found


def _repo_roots(src: Path, max_up: int = 4) -> list[Path]:
    """Folders above a monorepo package's source dir, up to the clone's root (the folder
    holding .git); empty when no .git is close above, so nothing outside a repo is read."""
    chain = []
    cur = src.resolve()
    for _ in range(max_up):
        cur = cur.parent
        chain.append(cur)
        if (cur / ".git").exists():
            return chain
    return []


def _loose(text: str | None) -> str | None:
    return " ".join(text.lower().split()) if text is not None else None


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
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
    if folder:
        return None
    # Monorepos keep LICENSE/README at the repository root; npm copies them into the package.
    for up, root in enumerate(_repo_roots(src), start=1):
        for entry in sorted(root.iterdir()):
            if entry.name.lower() == name.lower() and entry.is_file() and not entry.is_symlink():
                if _loose(read_text(entry)) == pkg_text:
                    return "../" * up + entry.name
    return None


# Fields a nested "subpath" package.json (e.g. rxjs/ajax/package.json) uses to redirect
# imports. npm only runs lifecycle scripts from the root package.json.
_STUB_FIELDS = frozenset(
    {"name", "version", "private", "main", "module", "types", "typings", "browser",
     "exports", "type", "sideEffects", "es2015", "esm5", "esm2015", "fesm2015", "fesm5"}
)


def _is_subpath_stub(fd: FileDiff, pkg: Path) -> bool:
    if not fd.path.endswith("/package.json"):
        return False
    data = _load_json(pkg / fd.path)
    return bool(data) and set(data) <= _STUB_FIELDS


def _classify_package_only(
    fd: FileDiff,
    pkg: Path,
    src: Path,
    src_files: set[str],
    counts: Counter[str],
    package_name: str | None = None,
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

    if _is_doc(fd.path) and not fd.is_binary:
        # Documentation is never executed, so a missing or different copy is low risk.
        return (
            _finding(
                fd, Verdict.CHANGED, Severity.LOW, ["IA-FILE-001"],
                "document not found in the repo",
                [f"{fd.size} bytes; documentation files are never executed"],
            ),
            True,
        )

    if _is_subpath_stub(fd, pkg):
        counts["subpath_stub"] += 1
        return (
            _finding(
                fd, Verdict.EXPECTED, Severity.INFO, [],
                "subpath package.json that only points imports at published files",
                ["nested package.json with resolution fields only (npm never runs its scripts)"],
            ),
            False,
        )

    mapped = map_to_source(fd.path, src_files, package_name)
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

    shim = text is not None and is_code(fd.path) and _entry_shim_targets(fd.path, text, pkg)
    if shim:
        counts["entry_shim"] += 1
        return (
            _finding(
                fd, Verdict.EXPECTED, Severity.INFO, [],
                "build-time entry switch that loads published build files",
                ["loads " + ", ".join(shim) + " depending on NODE_ENV"],
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
    fd: FileDiff,
    pkg: Path,
    src: Path,
    src_files: set[str],
    counts: Counter[str],
    package_name: str | None = None,
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

    if _is_doc(fd.path):
        if _loose(pkg_text) == _loose(src_text):
            counts["docs"] += 1
            return _finding(
                fd, Verdict.EXPECTED, Severity.INFO, [],
                "only case/whitespace differences", ["case/whitespace-only change"],
            )
        # Documentation is never executed: report the change, at low severity.
        return _finding(
            fd, Verdict.CHANGED, Severity.LOW, ["IA-FILE-002"],
            "documentation differs from the source",
            [f"+{fd.lines_added} / -{fd.lines_removed} lines"], diff=fd.diff,
        )

    added = new_dangerous_signals(pkg_text, src_text)
    mapped = map_to_source(fd.path, src_files, package_name)
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
    shim = is_code(fd.path) and _entry_shim_targets(fd.path, pkg_text, pkg)
    if shim:
        counts["entry_shim"] += 1
        return _finding(
            fd, Verdict.EXPECTED, Severity.INFO, [],
            "source entry replaced by a build-time switch that loads published build files",
            ["loads " + ", ".join(shim) + " depending on NODE_ENV"], diff=fd.diff,
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

    pkg_manifest = _load_json(pkg / "package.json") or {}
    name = pkg_manifest.get("name")
    package_name = name if isinstance(name, str) else None

    for fd in diffs:
        if fd.path == "package.json" and fd.relationship is not Relationship.ONLY_IN_SOURCE:
            manifest_fd = fd
            continue
        if fd.relationship is Relationship.IDENTICAL:
            counts["identical"] += 1
        elif fd.relationship is Relationship.ONLY_IN_SOURCE:
            counts["only_in_source"] += 1
        elif fd.relationship is Relationship.ONLY_IN_PACKAGE:
            finding, is_unexplained = _classify_package_only(
                fd, pkg, src, src_files, counts, package_name
            )
            if is_unexplained:
                unexplained.add(fd.path)
            if finding:
                findings.append(finding)
        else:
            findings.append(_classify_modified(fd, pkg, src, src_files, counts, package_name))

    if manifest_fd is not None:
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
