"""Compare the extracted package tree with the source tree, file by file."""

from __future__ import annotations

import difflib
import hashlib
import os
from pathlib import Path

from intanalyze.models import FileDiff, Relationship

MAX_ANALYSIS_BYTES = 20 * 1024 * 1024
MAX_DIFF_LINES = 400
IGNORED_SOURCE_DIRS = frozenset({".git", "node_modules"})
_BINARY_SNIFF = 8192


def walk_files(root: Path, ignore_dirs: frozenset[str] = frozenset()) -> dict[str, Path]:
    """Map relative POSIX path -> file for every regular file under ``root``.

    Symlinks are never followed or listed: package trees contain none (safe_extract never
    writes them) and a source checkout's links must not lead us outside the repo.
    """
    root = Path(root)
    files: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in ignore_dirs and not os.path.islink(Path(dirpath, d))
        )
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.is_symlink() or not path.is_file():
                continue
            files[path.relative_to(root).as_posix()] = path
    return files


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:_BINARY_SNIFF]


def read_for_analysis(path: Path) -> tuple[bytes | None, bool]:
    """Return (content with CRLF normalised for text, is_binary); content is None if too large."""
    if path.stat().st_size > MAX_ANALYSIS_BYTES:
        return None, False
    data = path.read_bytes()
    if is_binary(data):
        return data, True
    return data.replace(b"\r\n", b"\n"), False


def read_text(path: Path) -> str | None:
    """Decoded text of a file for the rules, or None for binary/oversized files."""
    data, binary = read_for_analysis(path)
    if data is None or binary:
        return None
    return data.decode("utf-8", errors="replace")


def _sha256_stream(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _fingerprint(path: Path) -> tuple[str, bool, bool, bytes | None]:
    """(sha256, is_binary, too_large, normalised content)."""
    data, binary = read_for_analysis(path)
    if data is None:
        return _sha256_stream(path), False, True, None
    return hashlib.sha256(data).hexdigest(), binary, False, data


def unified_diff(source: bytes, package: bytes, path: str) -> tuple[str, bool, int, int]:
    """(diff text truncated to MAX_DIFF_LINES, truncated?, lines added, lines removed)."""
    a = source.decode("utf-8", errors="replace").splitlines(keepends=True)
    b = package.decode("utf-8", errors="replace").splitlines(keepends=True)
    lines = list(
        difflib.unified_diff(a, b, fromfile=f"source/{path}", tofile=f"package/{path}", n=2)
    )
    added = sum(1 for ln in lines[2:] if ln.startswith("+"))
    removed = sum(1 for ln in lines[2:] if ln.startswith("-"))
    truncated = len(lines) > MAX_DIFF_LINES
    lines = lines[:MAX_DIFF_LINES]
    text = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    return text, truncated, added, removed


def compare_trees(package_root: Path, source_root: Path) -> list[FileDiff]:
    pkg_files = walk_files(package_root)
    src_files = walk_files(source_root, IGNORED_SOURCE_DIRS)
    diffs: list[FileDiff] = []

    for rel, pkg_path in pkg_files.items():
        p_sha, p_bin, p_big, p_data = _fingerprint(pkg_path)
        size = pkg_path.stat().st_size
        src_path = src_files.get(rel)
        if src_path is None:
            diffs.append(
                FileDiff(
                    path=rel,
                    relationship=Relationship.ONLY_IN_PACKAGE,
                    package_sha256=p_sha,
                    size=size,
                    is_binary=p_bin,
                    too_large=p_big,
                )
            )
            continue
        s_sha, s_bin, s_big, s_data = _fingerprint(src_path)
        if p_sha == s_sha:
            rel_kind = Relationship.IDENTICAL
        else:
            rel_kind = Relationship.MODIFIED
        fd = FileDiff(
            path=rel,
            relationship=rel_kind,
            package_sha256=p_sha,
            source_sha256=s_sha,
            size=size,
            is_binary=p_bin or s_bin,
            too_large=p_big or s_big,
        )
        if rel_kind is Relationship.MODIFIED and not (fd.is_binary or fd.too_large):
            assert p_data is not None and s_data is not None
            fd.diff, fd.diff_truncated, fd.lines_added, fd.lines_removed = unified_diff(
                s_data, p_data, rel
            )
        diffs.append(fd)

    for rel, src_path in src_files.items():
        if rel not in pkg_files:
            diffs.append(
                FileDiff(
                    path=rel,
                    relationship=Relationship.ONLY_IN_SOURCE,
                    source_sha256=None,
                    size=src_path.stat().st_size,
                )
            )

    diffs.sort(key=lambda d: d.path)
    return diffs
