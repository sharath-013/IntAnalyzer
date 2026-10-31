import base64
import hashlib
import subprocess

import httpx
import pytest
import respx

from intanalyze.fetch import (
    FetchError,
    Workdir,
    clone_source,
    download_tarball,
    source_root,
    verify_integrity,
)

URL = "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"
DATA = b"pretend this is a tarball"


def _sri(data, algo="sha512"):
    return f"{algo}-" + base64.b64encode(hashlib.new(algo, data).digest()).decode()


@pytest.fixture
def tarball(tmp_path):
    path = tmp_path / "pkg.tgz"
    path.write_bytes(DATA)
    return path


def test_integrity_sha512_ok(tarball):
    result = verify_integrity(tarball, _sri(DATA), None)
    assert result.checked and result.ok and result.algorithm == "sha512"


def test_integrity_sha512_mismatch(tarball):
    result = verify_integrity(tarball, _sri(b"something else"), None)
    assert result.checked and result.ok is False
    assert result.expected != result.actual


def test_integrity_prefers_strongest_algorithm(tarball):
    both = f"{_sri(b'wrong', 'sha1')} {_sri(DATA, 'sha512')}"
    result = verify_integrity(tarball, both, None)
    assert result.algorithm == "sha512" and result.ok


def test_integrity_falls_back_to_shasum(tarball):
    good = hashlib.sha1(DATA).hexdigest()
    assert verify_integrity(tarball, None, good.upper()).ok
    assert verify_integrity(tarball, "md5-xyz", "0" * 40).ok is False


def test_integrity_unchecked_without_hashes(tarball):
    result = verify_integrity(tarball, None, None)
    assert result.checked is False and result.ok is None


@respx.mock
def test_download_tarball(tmp_path):
    respx.get(URL).mock(return_value=httpx.Response(200, content=DATA))
    with httpx.Client() as client:
        path = download_tarball(URL, tmp_path / "x.tgz", client)
    assert path.read_bytes() == DATA


@respx.mock
def test_download_rejects_oversized_by_header(tmp_path):
    respx.get(URL).mock(
        return_value=httpx.Response(200, content=DATA, headers={"content-length": "999999"})
    )
    with httpx.Client() as client, pytest.raises(FetchError, match="larger"):
        download_tarball(URL, tmp_path / "x.tgz", client, max_bytes=100)


@respx.mock
def test_download_rejects_oversized_stream(tmp_path):
    def stream():
        yield b"a" * 60
        yield b"b" * 60

    respx.get(URL).mock(return_value=httpx.Response(200, content=stream()))
    with httpx.Client() as client, pytest.raises(FetchError, match="larger"):
        download_tarball(URL, tmp_path / "x.tgz", client, max_bytes=100)


@respx.mock
def test_download_http_errors(tmp_path):
    respx.get(URL).mock(return_value=httpx.Response(404))
    with httpx.Client() as client, pytest.raises(FetchError, match="HTTP 404"):
        download_tarball(URL, tmp_path / "x.tgz", client)
    respx.get(URL).mock(side_effect=httpx.ConnectError("down"))
    with httpx.Client() as client, pytest.raises(FetchError, match="download failed"):
        download_tarball(URL, tmp_path / "x.tgz", client)


def test_download_refuses_plain_http(tmp_path):
    with httpx.Client() as client, pytest.raises(FetchError, match="non-HTTPS"):
        download_tarball("http://example.com/x.tgz", tmp_path / "x.tgz", client)


def _git(*args, cwd):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    repo = tmp_path / "upstream"
    (repo / "packages/widget").mkdir(parents=True)
    _git("init", "-q", cwd=repo)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "packages/widget/index.js").write_text("v1\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "v1", cwd=repo)
    _git("tag", "v1.0.0", cwd=repo)
    first = _git("rev-parse", "HEAD", cwd=repo)
    (repo / "packages/widget/index.js").write_text("v2\n")
    _git("commit", "-qam", "v2", cwd=repo)
    return repo, first


def test_clone_by_tag(upstream, tmp_path):
    repo, _ = upstream
    dest = clone_source(repo.as_uri(), "v1.0.0", tmp_path / "src", allow_local=True)
    assert (dest / "packages/widget/index.js").read_text() == "v1\n"


def test_clone_by_sha(upstream, tmp_path):
    repo, first = upstream
    dest = clone_source(repo.as_uri(), first, tmp_path / "src", allow_local=True)
    assert (dest / "packages/widget/index.js").read_text() == "v1\n"
    assert source_root(dest, "packages/widget") == (dest / "packages/widget").resolve()


def test_clone_missing_tag_fails(upstream, tmp_path):
    repo, _ = upstream
    with pytest.raises(FetchError, match="clone failed"):
        clone_source(repo.as_uri(), "v9.9.9", tmp_path / "src", allow_local=True)


@pytest.mark.parametrize(
    ("url", "ref", "message"),
    [
        ("file:///tmp/x", "v1", "non-HTTPS"),
        ("ssh://git@github.com/x/y", "v1", "non-HTTPS"),
        ("https://github.com/x/y", "--upload-pack=evil", "suspicious"),
        ("https://github.com/x/y", "-c", "suspicious"),
    ],
)
def test_clone_refuses_unsafe_input(tmp_path, url, ref, message):
    with pytest.raises(FetchError, match=message):
        clone_source(url, ref, tmp_path / "src")


def test_source_root_rejects_escape_and_missing(tmp_path):
    assert source_root(tmp_path, None) == tmp_path
    with pytest.raises(FetchError, match="escapes"):
        source_root(tmp_path, "../..")
    with pytest.raises(FetchError, match="does not exist"):
        source_root(tmp_path, "packages/nope")


def test_workdir_cleanup(tmp_path):
    with Workdir() as wd:
        (wd / "f").write_text("x")
    assert not wd.exists()
    keep = Workdir(keep=True)
    with keep as wd2:
        pass
    assert wd2.exists()
    wd2.rmdir()
