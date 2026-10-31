import os

import pytest

from intanalyze import diff as diff_mod
from intanalyze.diff import compare_trees, is_binary, read_text, walk_files
from intanalyze.models import Relationship


def _write(root, files):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())


@pytest.fixture
def trees(tmp_path):
    pkg, src = tmp_path / "pkg", tmp_path / "src"
    _write(pkg, {
        "same.js": "a\n",
        "crlf.js": "a\r\nb\r\n",
        "changed.js": "one\ntwo\nthree\n",
        "only-pkg.js": "x",
        "bin.dat": b"\0\1\2",
        "bin2.dat": b"\0new",
    })
    _write(src, {
        "same.js": "a\n",
        "crlf.js": "a\nb\n",
        "changed.js": "one\n2\nthree\n",
        "only-src.md": "doc",
        "bin2.dat": b"\0old",
        ".git/config": "[core]",
        "node_modules/dep/index.js": "x",
    })
    return pkg, src


def test_relationships(trees):
    by_path = {d.path: d for d in compare_trees(*trees)}
    assert by_path["same.js"].relationship is Relationship.IDENTICAL
    assert by_path["crlf.js"].relationship is Relationship.IDENTICAL
    assert by_path["changed.js"].relationship is Relationship.MODIFIED
    assert by_path["only-pkg.js"].relationship is Relationship.ONLY_IN_PACKAGE
    assert by_path["only-src.md"].relationship is Relationship.ONLY_IN_SOURCE
    assert not any(p.startswith((".git/", "node_modules/")) for p in by_path)


def test_unified_diff_for_modified_text(trees):
    changed = next(d for d in compare_trees(*trees) if d.path == "changed.js")
    assert "-2\n" in changed.diff and "+two\n" in changed.diff
    assert (changed.lines_added, changed.lines_removed) == (1, 1)
    assert changed.diff.startswith("--- source/changed.js")


def test_binary_files_are_never_text_diffed(trees):
    by_path = {d.path: d for d in compare_trees(*trees)}
    assert by_path["bin.dat"].is_binary
    assert by_path["bin2.dat"].relationship is Relationship.MODIFIED
    assert by_path["bin2.dat"].diff is None


def test_diff_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(diff_mod, "MAX_DIFF_LINES", 10)
    _write(tmp_path / "p", {"f.txt": "".join(f"p{i}\n" for i in range(50))})
    _write(tmp_path / "s", {"f.txt": "".join(f"s{i}\n" for i in range(50))})
    (fd,) = compare_trees(tmp_path / "p", tmp_path / "s")
    assert fd.diff_truncated and len(fd.diff.splitlines()) == 10
    assert fd.lines_added == 50


def test_too_large_files_are_hashed_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(diff_mod, "MAX_ANALYSIS_BYTES", 4)
    _write(tmp_path / "p", {"big.js": "0123456789"})
    _write(tmp_path / "s", {"big.js": "0123456789"})
    (fd,) = compare_trees(tmp_path / "p", tmp_path / "s")
    assert fd.too_large and fd.relationship is Relationship.IDENTICAL
    assert read_text(tmp_path / "p/big.js") is None


def test_walk_skips_symlinks(tmp_path):
    _write(tmp_path, {"real.js": "x"})
    os.symlink("/etc/hosts", tmp_path / "link.js")
    os.symlink("/etc", tmp_path / "linkdir")
    assert list(walk_files(tmp_path)) == ["real.js"]


def test_is_binary():
    assert is_binary(b"abc\0") and not is_binary(b"plain text")
