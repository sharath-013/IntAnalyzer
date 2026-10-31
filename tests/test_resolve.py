import subprocess

import httpx
import pytest
import respx

from intanalyze.models import PackageSpec
from intanalyze.resolve import (
    REGISTRY_URL,
    ResolveError,
    fetch_metadata,
    list_remote_tags,
    normalize_repo_url,
    parse_metadata,
    registry_url,
    resolve_ref,
)

SHA = "a" * 40


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("git+https://github.com/vercel/ms.git", "https://github.com/vercel/ms"),
        ("https://github.com/vercel/ms", "https://github.com/vercel/ms"),
        ("http://github.com/vercel/ms/", "https://github.com/vercel/ms"),
        ("git://github.com/vercel/ms.git", "https://github.com/vercel/ms"),
        ("git+ssh://git@github.com/vercel/ms.git", "https://github.com/vercel/ms"),
        ("ssh://git@github.com:22/vercel/ms.git", "https://github.com/vercel/ms"),
        ("git@github.com:vercel/ms.git", "https://github.com/vercel/ms"),
        ("github:vercel/ms", "https://github.com/vercel/ms"),
        ("gitlab:group/proj", "https://gitlab.com/group/proj"),
        ("bitbucket:team/repo", "https://bitbucket.org/team/repo"),
        ("vercel/ms", "https://github.com/vercel/ms"),
        ("https://github.com/babel/babel.git#main", "https://github.com/babel/babel"),
        ({"type": "git", "url": "git+https://github.com/x/y.git"}, "https://github.com/x/y"),
    ],
)
def test_normalize_repo_url(raw, expected):
    assert normalize_repo_url(raw) == expected


@pytest.mark.parametrize("raw", [None, "", 42, {"type": "git"}, "file:///etc", "not a url"])
def test_normalize_repo_url_rejects_garbage(raw):
    assert normalize_repo_url(raw) is None


def test_registry_url_encodes_scoped_names():
    assert registry_url(PackageSpec.parse("@types/node@20.0.0")) == (
        f"{REGISTRY_URL}/@types%2Fnode/20.0.0"
    )
    assert registry_url(PackageSpec.parse("ms@2.1.3")) == f"{REGISTRY_URL}/ms/2.1.3"


def _meta(**over):
    data = {
        "name": "@acme/widget",
        "version": "1.2.3",
        "gitHead": SHA,
        "repository": {
            "type": "git",
            "url": "git+https://github.com/acme/monorepo.git",
            "directory": "packages/widget/",
        },
        "dist": {
            "tarball": "https://registry.npmjs.org/@acme/widget/-/widget-1.2.3.tgz",
            "integrity": "sha512-abc",
            "shasum": "def",
        },
    }
    data.update(over)
    return data


def test_parse_metadata_reads_dist_repo_directory_and_githead():
    spec = PackageSpec.parse("@acme/widget@1.2.3")
    r = parse_metadata(spec, _meta())
    assert r.tarball_url.endswith("widget-1.2.3.tgz")
    assert (r.integrity, r.shasum) == ("sha512-abc", "def")
    assert r.repo_url == "https://github.com/acme/monorepo"
    assert r.directory == "packages/widget"
    assert r.git_head == SHA


def test_parse_metadata_ignores_malformed_githead():
    r = parse_metadata(PackageSpec.parse("x@1.0.0"), _meta(gitHead="not-a-sha"))
    assert r.git_head is None


@respx.mock
def test_fetch_metadata_scoped_package():
    spec = PackageSpec.parse("@acme/widget@1.2.3")
    route = respx.get(f"{REGISTRY_URL}/@acme%2Fwidget/1.2.3").mock(
        return_value=httpx.Response(200, json=_meta())
    )
    with httpx.Client() as client:
        r = fetch_metadata(spec, client)
    assert route.called
    assert r.repo_url == "https://github.com/acme/monorepo"


@respx.mock
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404), "not found"),
        (httpx.Response(500), "HTTP 500"),
        (httpx.Response(200, text="<html>"), "invalid JSON"),
        (httpx.Response(200, json=["list"]), "unexpected"),
    ],
)
def test_fetch_metadata_errors(response, message):
    respx.get(f"{REGISTRY_URL}/ms/2.1.3").mock(return_value=response)
    with httpx.Client() as client, pytest.raises(ResolveError, match=message):
        fetch_metadata(PackageSpec.parse("ms@2.1.3"), client)


@respx.mock
def test_fetch_metadata_network_error():
    respx.get(f"{REGISTRY_URL}/ms/2.1.3").mock(side_effect=httpx.ConnectError("boom"))
    with httpx.Client() as client, pytest.raises(ResolveError, match="could not reach"):
        fetch_metadata(PackageSpec.parse("ms@2.1.3"), client)


def _resolved(**over):
    return parse_metadata(PackageSpec.parse("@acme/widget@1.2.3"), _meta(**over))


def test_ref_priority_cli_then_githead():
    def no_tags(url):
        raise AssertionError("tags should not be listed")

    assert resolve_ref(_resolved(), cli_ref="v9", ls_remote=no_tags) == ("v9", "cli")
    assert resolve_ref(_resolved(), ls_remote=no_tags) == (SHA, "gitHead")


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ({"v1.2.3", "1.2.3"}, "v1.2.3"),
        ({"1.2.3"}, "1.2.3"),
        ({"@acme/widget@1.2.3"}, "@acme/widget@1.2.3"),
        ({"widget@1.2.3"}, "widget@1.2.3"),
    ],
)
def test_ref_tag_fallbacks(tags, expected):
    ref = resolve_ref(_resolved(gitHead=None), ls_remote=lambda url: tags)
    assert ref == (expected, "tag")


def test_ref_no_tag_found():
    with pytest.raises(ResolveError, match="no matching tag"):
        resolve_ref(_resolved(gitHead=None), ls_remote=lambda url: {"v0.0.1"})


def test_ref_no_repository():
    with pytest.raises(ResolveError, match="no source repository declared"):
        resolve_ref(_resolved(gitHead=None, repository=None), ls_remote=lambda url: set())


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_list_remote_tags_on_local_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    (repo / "a.txt").write_text("a")
    _git("add", ".", cwd=repo)
    _git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init", cwd=repo)
    _git("tag", "v1.0.0", cwd=repo)
    _git("tag", "pkg@1.0.0", cwd=repo)
    assert list_remote_tags(repo.as_uri()) == {"v1.0.0", "pkg@1.0.0"}


def test_list_remote_tags_failure(tmp_path):
    with pytest.raises(ResolveError, match="ls-remote failed"):
        list_remote_tags((tmp_path / "missing").as_uri())
