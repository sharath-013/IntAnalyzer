"""Resolve an npm package version to its tarball and its declared source repository."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from intanalyze.models import PackageSpec

REGISTRY_URL = os.environ.get("INTANALYZE_REGISTRY", "https://registry.npmjs.org").rstrip("/")
GIT_TIMEOUT = 120

_HOST_SHORTCUTS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}
_SHORTHAND_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
_SCP_RE = re.compile(r"^(?:[\w.-]+@)?(?P<host>[\w.-]+):(?P<path>[^/].*)$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ResolveError(Exception):
    """Could not work out what to compare (registry, repository or ref problem)."""


class ResolvedPackage(BaseModel):
    spec: PackageSpec
    tarball_url: str | None = None
    integrity: str | None = None
    shasum: str | None = None
    repo_url: str | None = None
    directory: str | None = None
    git_head: str | None = None
    manifest: dict = Field(default_factory=dict)


def registry_url(spec: PackageSpec) -> str:
    """Registry URL for one version; the "/" in scoped names must be encoded."""
    return f"{REGISTRY_URL}/{quote(spec.name, safe='@')}/{quote(spec.version, safe='')}"


def normalize_repo_url(value: object) -> str | None:
    """Turn any npm ``repository`` form into a plain ``https://host/owner/repo`` URL."""
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url:
        return None

    prefix, _, rest = url.partition(":")
    if prefix in _HOST_SHORTCUTS and rest and not rest.startswith("//"):
        url = f"https://{_HOST_SHORTCUTS[prefix]}/{rest}"
    elif _SHORTHAND_RE.match(url):
        url = f"https://github.com/{url}"
    else:
        url = re.sub(r"^git\+", "", url)
        if m := re.match(r"^(?:git|ssh|https?)://(?:[^@/]+@)?(?P<rest>.+)$", url):
            url = "https://" + m["rest"]
        elif m := _SCP_RE.match(url):
            url = f"https://{m['host']}/{m['path']}"
        else:
            return None

    url = url.split("#", 1)[0].rstrip("/")
    url = re.sub(r"\.git$", "", url)
    # Drop an explicit port left over from ssh:// URLs (e.g. host:22/owner/repo).
    url = re.sub(r"^https://([^/:]+):\d+/", r"https://\1/", url)
    if not re.match(r"^https://[\w.-]+/[^\s]+$", url):
        return None
    return url


def parse_metadata(spec: PackageSpec, data: dict) -> ResolvedPackage:
    dist = data.get("dist") or {}
    repo = data.get("repository")
    directory = repo.get("directory") if isinstance(repo, dict) else None
    git_head = data.get("gitHead")
    return ResolvedPackage(
        spec=spec,
        tarball_url=dist.get("tarball"),
        integrity=dist.get("integrity"),
        shasum=dist.get("shasum"),
        repo_url=normalize_repo_url(repo),
        directory=directory.strip("/") if isinstance(directory, str) and directory else None,
        git_head=git_head if isinstance(git_head, str) and _SHA_RE.match(git_head) else None,
        manifest=data,
    )


def fetch_metadata(spec: PackageSpec, client: httpx.Client) -> ResolvedPackage:
    url = registry_url(spec)
    try:
        resp = client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise ResolveError(f"could not reach the npm registry: {exc}") from exc
    if resp.status_code == 404:
        raise ResolveError(f"{spec} was not found on the npm registry")
    if resp.status_code != 200:
        raise ResolveError(f"npm registry returned HTTP {resp.status_code} for {url}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise ResolveError("npm registry returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise ResolveError("npm registry returned an unexpected response")
    return parse_metadata(spec, data)


def git_env() -> dict[str, str]:
    """Environment for every git call: never prompt, never use LFS filters."""
    env = dict(os.environ)
    env.update(
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
        SSH_ASKPASS="",
        GIT_LFS_SKIP_SMUDGE="1",
        GIT_CONFIG_NOSYSTEM="1",
    )
    return env


def list_remote_tags(repo_url: str) -> set[str]:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null",
             "ls-remote", "--tags", "--refs", "--", repo_url],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            env=git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResolveError(f"git ls-remote failed for {repo_url}: {exc}") from exc
    if proc.returncode != 0:
        raise ResolveError(f"git ls-remote failed for {repo_url}: {proc.stderr.strip()}")
    tags = set()
    for line in proc.stdout.splitlines():
        _, _, ref = line.partition("\t")
        if ref.startswith("refs/tags/"):
            tags.add(ref.removeprefix("refs/tags/"))
    return tags


def tag_candidates(name: str, version: str) -> list[str]:
    cands = [f"v{version}", version, f"{name}@{version}"]
    if name.startswith("@"):
        cands.append(f"{name.split('/', 1)[1]}@{version}")
    return cands


def resolve_ref(
    resolved: ResolvedPackage,
    *,
    cli_ref: str | None = None,
    use_git_head: bool = True,
    ls_remote: Callable[[str], set[str]] = list_remote_tags,
) -> tuple[str, str]:
    """Pick the source ref to compare against: --ref, then gitHead, then a version tag.

    Returns ``(ref, kind)`` with kind one of "cli", "gitHead", "tag".
    """
    if cli_ref:
        return cli_ref, "cli"
    if use_git_head and resolved.git_head:
        return resolved.git_head, "gitHead"
    if not resolved.repo_url:
        raise ResolveError("no source repository declared")
    tags = ls_remote(resolved.repo_url)
    for cand in tag_candidates(resolved.spec.name, resolved.spec.version):
        if cand in tags:
            return cand, "tag"
    tried = ", ".join(tag_candidates(resolved.spec.name, resolved.spec.version))
    raise ResolveError(
        f"no gitHead in the registry metadata and no matching tag in {resolved.repo_url} "
        f"(tried {tried}); pass --ref"
    )
