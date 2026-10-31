"""Real-network checks against the npm registry and GitHub.

Skipped by default; run with ``pytest -m network``.
"""

import httpx
import pytest

from intanalyze.fetch import Workdir, clone_source, download_tarball, verify_integrity
from intanalyze.models import PackageSpec
from intanalyze.resolve import fetch_metadata, resolve_ref
from intanalyze.safe_extract import safe_extract


@pytest.mark.network
def test_ms_2_1_3_end_to_end_fetch():
    spec = PackageSpec.parse("ms@2.1.3")
    with httpx.Client(timeout=30, follow_redirects=True) as client, Workdir() as wd:
        resolved = fetch_metadata(spec, client)
        assert resolved.repo_url == "https://github.com/vercel/ms"
        ref, kind = resolve_ref(resolved)
        assert kind == "gitHead"
        tgz = download_tarball(resolved.tarball_url, wd / "pkg.tgz", client)
        assert verify_integrity(tgz, resolved.integrity, resolved.shasum).ok
        assert "index.js" in safe_extract(tgz, wd / "pkg").files
        assert (clone_source(resolved.repo_url, ref, wd / "src") / "index.js").is_file()
