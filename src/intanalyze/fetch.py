"""Download the published tarball, verify it, and fetch the source tree at a ref.

Nothing fetched here is ever executed: tarballs are only hashed and safely extracted, and
git runs with hooks disabled, no prompts and no LFS filters.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from intanalyze.models import IntegrityResult
from intanalyze.resolve import git_env

MAX_TARBALL_BYTES = 200 * 1024 * 1024
GIT_TIMEOUT = 300
_ALGOS = ("sha512", "sha384", "sha256", "sha1")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_REF_RE = re.compile(r"^[\w][\w./@+-]*$")


class FetchError(Exception):
    """Downloading the package or the source failed."""


def download_tarball(
    url: str, dest: Path, client: httpx.Client, *, max_bytes: int = MAX_TARBALL_BYTES
) -> Path:
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS tarball URL: {url}")
    try:
        with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise FetchError(f"tarball download returned HTTP {resp.status_code}: {url}")
            declared = int(resp.headers.get("content-length") or 0)
            if declared > max_bytes:
                raise FetchError(f"tarball is larger than {max_bytes // (1024 * 1024)} MB")
            written = 0
            with open(dest, "wb") as fh:
                for chunk in resp.iter_bytes():
                    written += len(chunk)
                    if written > max_bytes:
                        raise FetchError(
                            f"tarball is larger than {max_bytes // (1024 * 1024)} MB"
                        )
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise FetchError(f"tarball download failed: {exc}") from exc
    return dest


def _digest(path: Path, algo: str) -> bytes:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.digest()


def verify_integrity(path: Path, integrity: str | None, shasum: str | None) -> IntegrityResult:
    """Check the tarball against npm's ``dist.integrity`` (SRI) or ``dist.shasum`` (sha1 hex)."""
    if integrity:
        entries = {}
        for item in integrity.split():
            algo, _, value = item.partition("-")
            if algo in _ALGOS and value:
                entries.setdefault(algo, value)
        for algo in _ALGOS:
            if algo in entries:
                actual = base64.b64encode(_digest(path, algo)).decode()
                expected = entries[algo]
                return IntegrityResult(
                    checked=True,
                    algorithm=algo,
                    expected=f"{algo}-{expected}",
                    actual=f"{algo}-{actual}",
                    ok=actual == expected,
                )
    if shasum:
        actual = _digest(path, "sha1").hex()
        return IntegrityResult(
            checked=True,
            algorithm="sha1",
            expected=shasum.lower(),
            actual=actual,
            ok=actual == shasum.lower(),
        )
    return IntegrityResult(checked=False)


def _git(args: list[str], cwd: Path | None = None) -> str:
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            env=git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"git {args[0]} failed: {exc}") from exc
    if proc.returncode != 0:
        raise FetchError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def clone_source(
    repo_url: str, ref: str, dest: Path, *, allow_local: bool = False
) -> Path:
    """Shallow-fetch ``repo_url`` at ``ref`` (a full commit sha, a tag or a branch)."""
    if not (repo_url.startswith("https://") or (allow_local and repo_url.startswith("file://"))):
        raise FetchError(f"refusing to clone non-HTTPS repository URL: {repo_url}")
    if not _SAFE_REF_RE.match(ref):
        raise FetchError(f"refusing suspicious git ref: {ref!r}")
    dest = Path(dest)
    if _SHA_RE.match(ref):
        dest.mkdir(parents=True, exist_ok=True)
        _git(["init", "-q"], cwd=dest)
        _git(["remote", "add", "origin", repo_url], cwd=dest)
        _git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", ref], cwd=dest)
        _git(["checkout", "-q", "FETCH_HEAD"], cwd=dest)
    else:
        _git(
            [
                "clone", "-q", "--depth", "1", "--no-tags", "--single-branch",
                "--branch", ref, "--", repo_url, str(dest),
            ]
        )
    return dest


def source_root(clone_dir: Path, directory: str | None) -> Path:
    """The package's directory inside the clone (``repository.directory`` for monorepos)."""
    if not directory:
        return clone_dir
    root = (clone_dir / directory).resolve()
    if not root.is_relative_to(clone_dir.resolve()):
        raise FetchError(f"repository.directory escapes the repository: {directory!r}")
    if not root.is_dir():
        raise FetchError(f"repository.directory {directory!r} does not exist at this ref")
    return root


class Workdir:
    """Temporary working directory, removed on exit unless ``keep`` is set."""

    def __init__(self, keep: bool = False) -> None:
        self.keep = keep
        self.path = Path(tempfile.mkdtemp(prefix="intanalyze-"))

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *exc: object) -> None:
        if not self.keep:
            shutil.rmtree(self.path, ignore_errors=True)
