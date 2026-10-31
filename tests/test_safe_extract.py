import tarfile

import pytest

from conftest import add_file, add_special
from intanalyze.safe_extract import UnsafeArchiveError, safe_extract


def test_extracts_and_strips_package_dir(make_tar, tmp_path):
    def build(tar):
        add_file(tar, "package/package.json", b'{"name": "x"}')
        add_file(tar, "package/dist/index.js", b"module.exports = 1;\n")

    out = tmp_path / "out"
    result = safe_extract(make_tar(build), out)
    assert result.files == ["dist/index.js", "package.json"]
    assert (out / "dist/index.js").read_bytes() == b"module.exports = 1;\n"
    assert not (out / "package").exists()


def test_keeps_paths_without_a_common_top_dir(make_tar, tmp_path):
    def build(tar):
        add_file(tar, "a.js")
        add_file(tar, "lib/b.js")

    result = safe_extract(make_tar(build), tmp_path / "out")
    assert result.files == ["a.js", "lib/b.js"]


def test_no_strip_when_disabled(make_tar, tmp_path):
    result = safe_extract(
        make_tar(lambda t: add_file(t, "package/a.js")), tmp_path / "out", strip_top_dir=False
    )
    assert result.files == ["package/a.js"]


@pytest.mark.parametrize(
    "name",
    ["package/../../evil.js", "../evil.js", "package/a/../../../evil.js"],
)
def test_rejects_path_traversal(make_tar, tmp_path, name):
    with pytest.raises(UnsafeArchiveError, match="traversal"):
        safe_extract(make_tar(lambda t: add_file(t, name)), tmp_path / "out")
    assert not (tmp_path / "evil.js").exists()


@pytest.mark.parametrize("name", ["/etc/evil", "\\evil", "C:/evil"])
def test_rejects_absolute_paths(make_tar, tmp_path, name):
    with pytest.raises(UnsafeArchiveError, match="absolute"):
        safe_extract(make_tar(lambda t: add_file(t, name)), tmp_path / "out")


@pytest.mark.parametrize(
    ("kind", "link"),
    [
        (tarfile.SYMTYPE, "/etc/passwd"),
        (tarfile.SYMTYPE, "../../outside"),
        (tarfile.LNKTYPE, "../outside"),
        (tarfile.LNKTYPE, "/etc/passwd"),
    ],
)
def test_rejects_escaping_links(make_tar, tmp_path, kind, link):
    def build(tar):
        add_file(tar, "package/a.js")
        add_special(tar, "package/link", kind, link)

    with pytest.raises(UnsafeArchiveError, match="link escapes"):
        safe_extract(make_tar(build), tmp_path / "out")


def test_in_tree_links_are_skipped_not_written(make_tar, tmp_path):
    def build(tar):
        add_file(tar, "package/a.js")
        add_special(tar, "package/b.js", tarfile.SYMTYPE, "a.js")

    out = tmp_path / "out"
    result = safe_extract(make_tar(build), out)
    assert result.files == ["a.js"]
    assert result.skipped == ["b.js"]
    assert not (out / "b.js").exists()


@pytest.mark.parametrize("kind", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_rejects_device_and_fifo_files(make_tar, tmp_path, kind):
    with pytest.raises(UnsafeArchiveError, match="special"):
        safe_extract(make_tar(lambda t: add_special(t, "package/dev", kind)), tmp_path / "out")


def test_rejects_archives_over_the_size_limit(make_tar, tmp_path):
    def build(tar):
        add_file(tar, "package/a.bin", b"a" * 600)
        add_file(tar, "package/b.bin", b"b" * 600)

    with pytest.raises(UnsafeArchiveError, match="more than"):
        safe_extract(make_tar(build), tmp_path / "out", max_total_bytes=1000)


def test_rejects_too_many_members(make_tar, tmp_path):
    def build(tar):
        for i in range(5):
            add_file(tar, f"package/{i}.js")

    with pytest.raises(UnsafeArchiveError, match="members"):
        safe_extract(make_tar(build), tmp_path / "out", max_members=3)


def test_rejects_non_tar_input(tmp_path):
    bogus = tmp_path / "x.tgz"
    bogus.write_bytes(b"not a tarball")
    with pytest.raises(UnsafeArchiveError, match="not a readable"):
        safe_extract(bogus, tmp_path / "out")


def test_extracted_files_are_not_executable(make_tar, tmp_path):
    def build(tar):
        info = tarfile.TarInfo("package/run.sh")
        info.size = 2
        info.mode = 0o4755
        import io

        tar.addfile(info, io.BytesIO(b"hi"))

    out = tmp_path / "out"
    safe_extract(make_tar(build), out)
    assert (out / "run.sh").stat().st_mode & 0o7777 == 0o644
