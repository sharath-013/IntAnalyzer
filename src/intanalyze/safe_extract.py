"""Hardened extraction of package tarballs.

Downloaded tarballs are untrusted. Every member is checked with tarfile's "data" filter and
with our own rules before anything is written, and links are never materialised, so later
stages can read the extracted tree without following attacker-controlled paths.
"""

from __future__ import annotations

import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 20_000


class UnsafeArchiveError(Exception):
    """The archive tried to do something we refuse to extract."""


@dataclass
class ExtractResult:
    root: Path
    files: list[str] = field(default_factory=list)
    # Members that were safe but deliberately not written (e.g. in-tree symlinks).
    skipped: list[str] = field(default_factory=list)


def _clean_name(name: str) -> PurePosixPath:
    if not name or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchiveError(f"absolute path in archive: {name!r}")
    path = PurePosixPath(name.replace("\\", "/"))
    if ".." in path.parts:
        raise UnsafeArchiveError(f"path traversal in archive: {name!r}")
    parts = [p for p in path.parts if p not in ("", ".")]
    if not parts:
        raise UnsafeArchiveError(f"empty path in archive: {name!r}")
    return PurePosixPath(*parts)


def _link_escapes(member: tarfile.TarInfo, name: PurePosixPath) -> bool:
    target = member.linkname.replace("\\", "/")
    if target.startswith("/"):
        return True
    # Symlink targets are relative to the link's directory; hardlink targets to the archive root.
    base = name.parent.parts if member.issym() else ()
    depth = len(base)
    for part in PurePosixPath(target).parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in ("", "."):
            depth += 1
    return False


def _common_top_dir(names: list[PurePosixPath]) -> str | None:
    tops = {n.parts[0] for n in names}
    if len(tops) == 1 and all(len(n.parts) > 1 for n in names if n.parts):
        return tops.pop()
    return None


def safe_extract(
    tar_path: Path,
    dest: Path,
    *,
    strip_top_dir: bool = True,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_members: int = MAX_MEMBERS,
) -> ExtractResult:
    """Extract ``tar_path`` into ``dest`` (which must be empty or absent).

    npm tarballs keep everything under a single top-level directory (normally ``package/``);
    with ``strip_top_dir`` that directory is removed so paths match the source tree.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = dest.resolve()
    result = ExtractResult(root=dest)

    try:
        tar = tarfile.open(tar_path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise UnsafeArchiveError(f"not a readable tar archive: {exc}") from exc

    with tar:
        plan: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        total = 0
        for count, member in enumerate(tar, start=1):
            if count > max_members:
                raise UnsafeArchiveError(f"archive has more than {max_members} members")
            name = _clean_name(member.name)
            if member.isdev() or member.isfifo() or not (
                member.isfile() or member.isdir() or member.issym() or member.islnk()
            ):
                raise UnsafeArchiveError(f"device or special file in archive: {member.name!r}")
            if (member.issym() or member.islnk()) and _link_escapes(member, name):
                raise UnsafeArchiveError(
                    f"link escapes the extraction dir: {member.name!r} -> {member.linkname!r}"
                )
            try:
                tarfile.data_filter(member, str(dest_real))
            except tarfile.FilterError as exc:
                raise UnsafeArchiveError(f"rejected by tarfile data filter: {exc}") from exc
            if member.isfile():
                total += member.size
                if total > max_total_bytes:
                    raise UnsafeArchiveError(
                        f"archive expands to more than {max_total_bytes // (1024 * 1024)} MB"
                    )
            plan.append((member, name))

        top = _common_top_dir([n for _, n in plan]) if strip_top_dir else None

        for member, name in plan:
            rel = PurePosixPath(*name.parts[1:]) if top else name
            if not rel.parts:
                continue
            if member.issym() or member.islnk():
                result.skipped.append(str(rel))
                continue
            out = dest / Path(*rel.parts)
            # Defence in depth: the resolved output path must stay inside dest.
            if not out.resolve().is_relative_to(dest_real):
                raise UnsafeArchiveError(f"path escapes the extraction dir: {member.name!r}")
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:  # pragma: no cover - isfile() members always have data
                continue
            with src, open(out, "wb") as fh:
                shutil.copyfileobj(src, fh)
            out.chmod(0o644)
            result.files.append(str(rel))

    result.files.sort()
    return result
