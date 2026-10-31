from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest


def add_file(tar: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    tar.addfile(info, io.BytesIO(data))


def add_special(tar: tarfile.TarFile, name: str, kind: bytes, linkname: str = "") -> None:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    tar.addfile(info)


@pytest.fixture
def make_tar(tmp_path: Path):
    """Build a .tgz from a callback that receives the open TarFile."""
    counter = iter(range(1000))

    def _make(build) -> Path:
        path = tmp_path / f"archive{next(counter)}.tgz"
        with tarfile.open(path, "w:gz") as tar:
            build(tar)
        return path

    return _make
