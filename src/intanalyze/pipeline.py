"""Runs the stages in order: resolve -> fetch -> extract -> diff -> classify -> score."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx

from intanalyze import __version__
from intanalyze.classify import classify, rule_explanation
from intanalyze.diff import compare_trees
from intanalyze.fetch import (
    FetchError,
    Workdir,
    clone_source,
    download_tarball,
    source_root,
    verify_integrity,
)
from intanalyze.models import (
    Finding,
    IntegrityResult,
    PackageSpec,
    Relationship,
    Report,
    Severity,
    SourceInfo,
    Verdict,
)
from intanalyze.resolve import (
    ResolvedPackage,
    ResolveError,
    fetch_metadata,
    list_remote_tags,
    normalize_repo_url,
    parse_metadata,
    resolve_ref,
)
from intanalyze.safe_extract import UnsafeArchiveError, safe_extract
from intanalyze.score import risk_score, status_for

Progress = Callable[[str], None]


class CheckError(Exception):
    """Any failure that should end the run with exit code 2."""


def _noop(_: str) -> None:
    pass


def _integrity_finding(name: str, result: IntegrityResult) -> Finding:
    f = Finding(
        path=name,
        verdict=Verdict.SUSPICIOUS,
        severity=Severity.HIGH,
        relationship=Relationship.ONLY_IN_PACKAGE,
        rule_ids=["IA-INTEGRITY-001"],
        reason="tarball hash does not match the registry's integrity value",
        evidence=[f"expected {result.expected}", f"actual   {result.actual}"],
    )
    f.explanation = rule_explanation(f)
    return f


def analyze(
    tarball: Path,
    src_root: Path,
    workdir: Path,
    *,
    spec: PackageSpec | None,
    resolved: ResolvedPackage | None,
    source: SourceInfo,
) -> Report:
    """Shared tail of both modes: verify, extract, diff, classify and score."""
    integrity = (
        verify_integrity(tarball, resolved.integrity, resolved.shasum)
        if resolved
        else IntegrityResult()
    )
    try:
        extracted = safe_extract(tarball, workdir / "package")
    except UnsafeArchiveError as exc:
        raise CheckError(f"unsafe package archive: {exc}") from exc

    pkg_json = workdir / "package" / "package.json"
    if spec is None:
        try:
            meta = json.loads(pkg_json.read_text(encoding="utf-8"))
            spec = PackageSpec(name=str(meta["name"]), version=str(meta["version"]))
        except (OSError, ValueError, KeyError) as exc:
            raise CheckError("could not read name/version from the package.json") from exc

    diffs = compare_trees(extracted.root, src_root)
    result = classify(
        diffs,
        extracted.root,
        src_root,
        registry_manifest=resolved.manifest if resolved and resolved.manifest else None,
    )
    findings = result.findings
    if integrity.checked and integrity.ok is False:
        findings.insert(0, _integrity_finding(tarball.name, integrity))

    score = risk_score(findings)
    return Report(
        tool_version=__version__,
        package=spec,
        tarball_url=resolved.tarball_url if resolved else None,
        source=source,
        integrity=integrity,
        findings=findings,
        expected_counts=dict(sorted(result.expected_counts.items())),
        files_in_package=sum(1 for d in diffs if d.relationship is not Relationship.ONLY_IN_SOURCE),
        files_in_source=sum(1 for d in diffs if d.relationship is not Relationship.ONLY_IN_PACKAGE),
        score=score,
        status=status_for(score),
    )


def check_offline(
    tarball: Path,
    source: Path,
    *,
    registry_json: Path | None = None,
    keep_workdir: bool = False,
    progress: Progress = _noop,
) -> Report:
    """Compare a local tarball with a local source directory (no network)."""
    tarball, source = Path(tarball), Path(source)
    if not tarball.is_file():
        raise CheckError(f"tarball not found: {tarball}")
    if not source.is_dir():
        raise CheckError(f"source directory not found: {source}")

    resolved = None
    spec = None
    if registry_json:
        try:
            data = json.loads(Path(registry_json).read_text(encoding="utf-8"))
            spec = PackageSpec(name=str(data["name"]), version=str(data["version"]))
        except (OSError, ValueError, KeyError) as exc:
            raise CheckError(f"could not read registry metadata {registry_json}: {exc}") from exc
        resolved = parse_metadata(spec, data)

    info = SourceInfo(
        repo_url=(resolved.repo_url if resolved else None) or str(source),
        ref=str(source),
        ref_kind="local",
        directory=resolved.directory if resolved else None,
    )
    with Workdir(keep=keep_workdir) as wd:
        progress("analysing")
        return analyze(tarball, source, wd, spec=spec, resolved=resolved, source=info)


def check_online(
    spec: PackageSpec,
    *,
    repo: str | None = None,
    ref: str | None = None,
    keep_workdir: bool = False,
    client: httpx.Client | None = None,
    progress: Progress = _noop,
) -> Report:
    """Resolve ``spec`` on the npm registry and compare it with its source repository."""
    own_client = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True)
    try:
        progress(f"resolving {spec}")
        resolved = fetch_metadata(spec, client)
        if repo:
            resolved.repo_url = normalize_repo_url(repo) or repo
        if not resolved.repo_url:
            raise ResolveError("no source repository declared")
        if not resolved.tarball_url:
            raise ResolveError(f"registry metadata for {spec} has no dist.tarball")

        with Workdir(keep=keep_workdir) as wd:
            progress("downloading tarball")
            tarball = download_tarball(resolved.tarball_url, wd / "package.tgz", client)

            the_ref, kind = resolve_ref(resolved, cli_ref=ref)
            progress(f"fetching source at {the_ref[:12]}")
            try:
                clone = clone_source(resolved.repo_url, the_ref, wd / "source")
            except FetchError:
                if kind != "gitHead":
                    raise
                # The gitHead commit may be gone (force-push, private fork); try the tags.
                the_ref, kind = resolve_ref(
                    resolved, use_git_head=False, ls_remote=list_remote_tags
                )
                progress(f"gitHead unavailable, fetching tag {the_ref}")
                clone = clone_source(resolved.repo_url, the_ref, wd / "source2")
            src_root = source_root(clone, resolved.directory)

            info = SourceInfo(
                repo_url=resolved.repo_url,
                ref=the_ref,
                ref_kind=kind,
                directory=resolved.directory,
            )
            progress("analysing")
            return analyze(tarball, src_root, wd, spec=spec, resolved=resolved, source=info)
    except (ResolveError, FetchError) as exc:
        raise CheckError(str(exc)) from exc
    finally:
        if own_client:
            client.close()
