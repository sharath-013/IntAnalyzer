"""check_online with the registry, tarball and git all faked (no network)."""

import json
import shutil
from pathlib import Path

import httpx
import pytest
import respx

from intanalyze import pipeline
from intanalyze.fetch import FetchError
from intanalyze.models import PackageSpec, Status
from intanalyze.pipeline import CheckError, check_offline, check_online
from intanalyze.resolve import REGISTRY_URL

FIXTURES = Path(__file__).parent / "fixtures"
SPEC = PackageSpec.parse("tiny-percent@1.0.0")
META_URL = f"{REGISTRY_URL}/tiny-percent/1.0.0"
SHA = "b" * 40


def _meta(name="clean", **over):
    meta = json.loads((FIXTURES / name / "registry.json").read_text())
    meta["gitHead"] = SHA
    meta.update(over)
    return meta


def _mock_registry(meta, tarball="clean"):
    respx.get(META_URL).mock(return_value=httpx.Response(200, json=meta))
    respx.get(meta["dist"]["tarball"]).mock(
        return_value=httpx.Response(200, content=(FIXTURES / tarball / "package.tgz").read_bytes())
    )


@pytest.fixture
def fake_git(monkeypatch):
    """clone_source copies the fixture source; records the refs it was asked for."""
    calls = []

    def clone(url, ref, dest, **kw):
        calls.append(ref)
        if ref in fake_git_fail:
            raise FetchError("git fetch failed: not our ref")
        shutil.copytree(FIXTURES / "clean" / "source", dest)
        return Path(dest)

    fake_git_fail: set[str] = set()
    monkeypatch.setattr(pipeline, "clone_source", clone)
    monkeypatch.setattr(pipeline, "list_remote_tags", lambda url: {"v1.0.0"})
    return calls, fake_git_fail


@respx.mock
def test_online_clean(fake_git):
    calls, _ = fake_git
    _mock_registry(_meta())
    steps = []
    report = check_online(SPEC, progress=steps.append)
    assert report.status is Status.CLEAN
    assert report.source.ref == SHA and report.source.ref_kind == "gitHead"
    assert report.integrity.ok is True
    assert calls == [SHA] and steps[0].startswith("resolving")


@respx.mock
def test_online_malicious_tarball(fake_git):
    _mock_registry(_meta("malicious"), tarball="malicious")
    report = check_online(SPEC)
    assert report.status is Status.DANGEROUS


@respx.mock
def test_online_githead_missing_falls_back_to_tag(fake_git):
    calls, fail = fake_git
    fail.add(SHA)
    _mock_registry(_meta())
    report = check_online(SPEC)
    assert calls == [SHA, "v1.0.0"]
    assert report.source.ref_kind == "tag"


@respx.mock
def test_online_cli_ref_and_repo_override(fake_git):
    calls, _ = fake_git
    _mock_registry(_meta())
    report = check_online(SPEC, repo="github:someone/fork", ref="v1.0.0")
    assert calls == ["v1.0.0"]
    assert report.source.repo_url == "https://github.com/someone/fork"


@respx.mock
def test_online_integrity_mismatch_is_a_high_finding(fake_git):
    meta = _meta()
    meta["dist"]["integrity"] = "sha512-" + "A" * 86 + "=="
    _mock_registry(meta)
    report = check_online(SPEC)
    assert report.integrity.ok is False
    assert report.findings[0].rule_ids == ["IA-INTEGRITY-001"]
    assert report.status is Status.DANGEROUS


@respx.mock
def test_online_no_repository(fake_git):
    _mock_registry(_meta(repository=None))
    with pytest.raises(CheckError, match="no source repository declared"):
        check_online(SPEC)


@respx.mock
def test_online_no_tarball(fake_git):
    meta = _meta()
    meta["dist"] = {}
    respx.get(META_URL).mock(return_value=httpx.Response(200, json=meta))
    with pytest.raises(CheckError, match="no dist.tarball"):
        check_online(SPEC)


def test_offline_without_registry_reads_package_json():
    d = FIXTURES / "clean"
    report = check_offline(d / "package.tgz", d / "source")
    assert str(report.package) == "tiny-percent@1.0.0"
    assert report.integrity.checked is False


def test_offline_bad_registry_json(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text("{}")
    d = FIXTURES / "clean"
    with pytest.raises(CheckError, match="registry metadata"):
        check_offline(d / "package.tgz", d / "source", registry_json=bad)


def test_offline_unsafe_tarball(tmp_path):
    bogus = tmp_path / "x.tgz"
    bogus.write_bytes(b"nope")
    with pytest.raises(CheckError, match="unsafe package archive"):
        check_offline(bogus, FIXTURES / "clean" / "source")
