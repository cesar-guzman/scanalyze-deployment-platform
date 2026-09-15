"""Real archive parsing of synthetic, in-memory build artifacts; no extraction."""
from dataclasses import FrozenInstanceError
import gzip
import hashlib
import io
import stat
import tarfile
import zipfile

import pytest

from tooling.frontend_release_archive import (
    ArchiveLimits, FrontendArchiveRejected, inspect_frontend_archive,
)


def digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def package(rows, kind="tar", *, special=None):
    buffer = io.BytesIO()
    if kind == "tar":
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, body in rows:
                info = tarfile.TarInfo(name)
                info.size = len(body) if body is not None else 0
                if body is None:
                    info.type = tarfile.DIRTYPE
                if special:
                    special(info)
                archive.addfile(info, io.BytesIO(body or b""))
        return gzip.compress(buffer.getvalue(), mtime=0)
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in rows:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if special:
                special(info)
            archive.writestr(info, body or b"")
    return buffer.getvalue()


def inspect(payload, kind="tar", **kwargs):
    return inspect_frontend_archive(payload, expected_archive_digest=digest(payload),
                                    media_type="application/gzip" if kind == "tar" else "application/zip",
                                    **kwargs)


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_actual_archives_produce_sorted_immutable_assets_and_metadata_only(kind, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rows = [("index.html", b"<html>synthetic-page</html>"),
            ("assets/main.js", b"synthetic-source-payload"), ("assets/style.css", b"body{}")]
    payload = package(rows, kind)
    result = inspect(payload, kind)
    assert [asset.path for asset in result.assets] == sorted(name for name, _ in rows)
    assert {asset.path: asset.body for asset in result.assets} == dict(rows)
    assert result.manifest()["expanded_bytes"] == sum(len(body) for _, body in rows)
    assert result.manifest()["status"] == "VALIDATED_ARCHIVE_NOT_PUBLISHED"
    assert "synthetic-source-payload" not in repr(result)
    assert "synthetic-source-payload" not in repr(result.assets)
    assert "synthetic-source-payload" not in repr(result.manifest())
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(FrozenInstanceError):
        result.assets[0].path = "changed"
    changed_manifest = result.manifest()
    changed_manifest["assets"].clear()
    assert len(result.manifest()["assets"]) == 3


@pytest.mark.parametrize("kind", ["tar", "zip"])
@pytest.mark.parametrize("name", ["../outside", "/outside", "a/../../x", "a//b", "a/./b", "a\\b",
                                 "C:/absolute", "a%2fb", ".hidden", "a/.hidden", "a?x", "a#x",
                                 "a\nname", "caf\N{LATIN SMALL LETTER E WITH ACUTE}", "././index.html"])
def test_unsafe_paths_fail_without_echoing_archive_values(kind, name):
    payload = package([("index.html", b"safe"), (name, b"not-returned")], kind)
    with pytest.raises(FrontendArchiveRejected) as failure:
        inspect(payload, kind)
    assert "not-returned" not in str(failure.value)
    assert str(failure.value) == "ARCHIVE_PATH_INVALID"


@pytest.mark.parametrize("kind", ["tar", "zip"])
@pytest.mark.parametrize("names", [
    ["index.html", "index.html"], ["index.html", "./index.html"],
    ["index.html", "INDEX.html"], ["index.html", "assets", "assets/main.js"],
    ["index.html", "assets/main.js", "assets"], ["index.html", "A/x", "a/y"],
])
def test_duplicates_and_implicit_parent_collisions_fail(kind, names):
    with pytest.warns(UserWarning) if kind == "zip" and names[0] == names[1] else _no_warning():
        payload = package([(name, b"a") for name in names], kind)
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_(PATH_COLLISION|PARENT_IS_FILE)"):
        inspect(payload, kind)


from contextlib import nullcontext as _no_warning


def test_tar_dot_wrapper_and_directories_are_accepted_without_extraction():
    result = inspect(package([("./", None), ("./assets/", None), ("./assets/main.js", b"x"),
                              ("./index.html", b"html")]))
    assert {asset.path for asset in result.assets} == {"assets/main.js", "index.html"}


@pytest.mark.parametrize("kind", ["tar", "zip"])
@pytest.mark.parametrize("limits,rows,error", [
    (ArchiveLimits(max_entries=1), [("index.html", b"x"), ("x.js", b"x")], "ENTRY_LIMIT"),
    (ArchiveLimits(max_file_bytes=3), [("index.html", b"1234")], "FILE_LIMIT"),
    (ArchiveLimits(max_expanded_bytes=3), [("index.html", b"12"), ("x.js", b"34")], "EXPANSION_LIMIT"),
])
def test_resource_limits(kind, limits, rows, error):
    with pytest.raises(FrontendArchiveRejected, match=error):
        inspect(package(rows, kind), kind, limits=limits)


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_exact_limit_is_allowed_and_missing_index_fails(kind):
    assert inspect(package([("index.html", b"123")], kind), kind,
                   limits=ArchiveLimits(max_file_bytes=3, max_expanded_bytes=3)).assets[0].body == b"123"
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_INDEX_REQUIRED"):
        inspect(package([("dist/index.html", b"x")], kind), kind)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                                        tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_tar_special_files_are_rejected(member_type):
    def special(info):
        if info.name != "index.html":
            info.type = member_type
            info.size = 0
            info.linkname = "index.html"
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_MEMBER_TYPE_INVALID"):
        inspect(package([("index.html", b"safe"), ("link", b"")], special=special))


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK])
def test_zip_special_files_rejected(mode):
    def special(info):
        if info.filename == "special":
            info.create_system = 3
            info.external_attr = (mode | 0o644) << 16
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_MEMBER_TYPE_INVALID"):
        inspect(package([("index.html", b"safe"), ("special", b"x")], "zip", special=special), "zip")


def test_digest_mismatch_precedes_any_archive_parser(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("parser must not be called")
    monkeypatch.setattr(tarfile, "open", forbidden)
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_DIGEST_MISMATCH"):
        inspect_frontend_archive(b"not-an-archive", expected_archive_digest="sha256:" + "0" * 64,
                                 media_type="application/gzip")


@pytest.mark.parametrize("payload", [b"garbage", b"", b"PK\x03\x04"])
@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_malformed_archives_have_sanitized_errors(payload, kind):
    with pytest.raises(FrontendArchiveRejected):
        inspect(payload, kind)


@pytest.mark.parametrize("mutation", ["truncated", "trailing", "concatenated", "tar_tail"])
def test_gzip_and_tar_end_of_stream_are_checked(mutation):
    payload = package([("index.html", b"hello")])
    if mutation == "truncated":
        payload = payload[:-1]
    elif mutation == "trailing":
        payload += b"trailing"
    elif mutation == "concatenated":
        payload += gzip.compress(b"second")
    else:
        payload = gzip.compress(gzip.decompress(payload) + b"x" * 512)
    with pytest.raises(FrontendArchiveRejected):
        inspect(payload)


def test_bomb_is_bounded_before_tar_parser(monkeypatch):
    payload = gzip.compress(b"0" * 40000)
    monkeypatch.setattr(tarfile, "open", lambda **kwargs: pytest.fail("decompression must fail first"))
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_EXPANSION_LIMIT"):
        inspect(payload, limits=ArchiveLimits(max_expanded_bytes=10, max_entries=1))


@pytest.mark.parametrize("mutation", ["trailing", "prefix", "truncated", "multidisk", "huge_count"])
def test_zip_layout_and_directory_count_checked_before_allocation(mutation):
    payload = package([("index.html", b"safe")], "zip")
    if mutation == "trailing":
        payload += b"trailer"
    elif mutation == "prefix":
        payload = b"prefix" + payload
    elif mutation == "truncated":
        payload = payload[:-1]
    else:
        change = bytearray(payload)
        if mutation == "multidisk":
            change[-18] = 1
        else:
            change[-14:-10] = (20000).to_bytes(2, "little") * 2
        payload = bytes(change)
    with pytest.raises(FrontendArchiveRejected):
        inspect(payload, "zip")


def test_zip_crc_failure_does_not_return_partial_assets():
    payload = bytearray(package([("index.html", b"safe")], "zip"))
    payload[40] ^= 255
    with pytest.raises(FrontendArchiveRejected):
        inspect(bytes(payload), "zip")


@pytest.mark.parametrize("kwargs", [{"max_entries": True}, {"max_archive_bytes": 0},
                                  {"max_expanded_bytes": 129 * 1024 * 1024},
                                  {"max_file_bytes": -1}])
def test_limits_cannot_be_loosened(kwargs):
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_LIMITS_INVALID"):
        ArchiveLimits(**kwargs)


def test_nested_gnu_metadata_rejected_before_tarfile_recursive_parser(monkeypatch):
    # A small gzip can encode more nested GNU headers than Python's recursion
    # limit. TarInfo iteration/entry counting occurs only after tarfile resolves
    # those headers, so the physical preflight must reject before opening it.
    long_name = tarfile.TarInfo("././@LongLink")
    long_name.type = tarfile.GNUTYPE_LONGNAME
    long_name.size = 11
    metadata_block = (long_name.tobuf(format=tarfile.GNU_FORMAT)
                      + b"index.html\0" + b"\0" * 501)
    regular = tarfile.TarInfo("index.html")
    regular.size = 1
    raw = (metadata_block * 1100 + regular.tobuf(format=tarfile.USTAR_FORMAT)
           + b"x" + b"\0" * 511 + b"\0" * 1024)
    payload = gzip.compress(raw, mtime=0)

    def forbidden(*args, **kwargs):
        pytest.fail("physical TAR metadata must be rejected before tarfile.open")

    monkeypatch.setattr(tarfile, "open", forbidden)
    with pytest.raises(FrontendArchiveRejected,
                       match="ARCHIVE_(EXTENDED_METADATA_REJECTED|MEMBER_TYPE_INVALID)"):
        inspect(payload)


def test_underreported_zip_directory_count_rejected_before_zipfile_allocations(monkeypatch):
    # EOCD lies about both entry counts while its byte-size/offset stay valid.
    # ZipFile would still allocate 2500 ZipInfo objects with max_entries=1.
    rows = [("index.html", b"x")] + [(f"assets/a{index}.js", b"x") for index in range(2499)]
    payload = bytearray(package(rows, "zip"))
    payload[-14:-10] = (1).to_bytes(2, "little") * 2

    def forbidden(*args, **kwargs):
        pytest.fail("physical central directory must be bounded before ZipFile")

    monkeypatch.setattr(zipfile, "ZipFile", forbidden)
    with pytest.raises(FrontendArchiveRejected, match="ARCHIVE_(ENTRY_LIMIT|ZIP_LAYOUT_INVALID)"):
        inspect(bytes(payload), "zip", limits=ArchiveLimits(max_entries=1))
