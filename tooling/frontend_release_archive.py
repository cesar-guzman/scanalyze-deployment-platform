"""Inspect the exact frontend release bytes without extracting or publishing files.

This is a bounded archive parser, not release admission or publication authority.
The caller must independently verify release provenance and authorize any writes.
The returned bodies stay in memory; repr and manifests contain metadata only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import re
import stat
import struct
import tarfile
import zipfile
import zlib


class FrontendArchiveRejected(ValueError):
    """Errors contain fixed codes, never archive names or contents."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise FrontendArchiveRejected(code)


def _digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_archive_bytes: int = 64 * 1024 * 1024
    max_expanded_bytes: int = 128 * 1024 * 1024
    max_file_bytes: int = 16 * 1024 * 1024
    max_entries: int = 10000

    def __post_init__(self) -> None:
        ceilings = (64 * 1024 * 1024, 128 * 1024 * 1024, 16 * 1024 * 1024, 10000)
        values = (self.max_archive_bytes, self.max_expanded_bytes,
                  self.max_file_bytes, self.max_entries)
        _require(all(type(value) is int and 0 < value <= cap
                     for value, cap in zip(values, ceilings)), "ARCHIVE_LIMITS_INVALID")


_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".json": "application/json", ".map": "application/json", ".svg": "image/svg+xml",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".avif": "image/avif",
    ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2",
    ".ttf": "font/ttf", ".wasm": "application/wasm", ".txt": "text/plain; charset=utf-8",
    ".webmanifest": "application/manifest+json", ".xml": "application/xml",
}
_SEGMENT = re.compile(r"[A-Za-z0-9_@+-][A-Za-z0-9_@.+-]*\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class FrontendAsset:
    path: str
    digest: str
    content_type: str
    body: bytes = field(repr=False)

    def metadata(self) -> dict:
        return {"path": self.path, "digest": self.digest, "size": len(self.body),
                "content_type": self.content_type}


@dataclass(frozen=True, slots=True)
class ValidatedFrontendArchive:
    archive_digest: str
    media_type: str
    assets: tuple[FrontendAsset, ...] = field(repr=False)

    def manifest(self) -> dict:
        return {"schema_version": "frontend-archive-inspection.v1",
                "status": "VALIDATED_ARCHIVE_NOT_PUBLISHED",
                "archive_digest": self.archive_digest, "media_type": self.media_type,
                "asset_count": len(self.assets),
                "expanded_bytes": sum(len(asset.body) for asset in self.assets),
                "assets": [asset.metadata() for asset in self.assets]}


def _path(raw: str, directory: bool) -> str:
    # Accept tar's conventional './' wrapper, but no arbitrary normalization.
    _require(isinstance(raw, str) and 0 < len(raw) <= 1024, "ARCHIVE_PATH_INVALID")
    name = raw[2:] if raw.startswith("./") else raw
    if directory and name in {"", "."}:
        return ""
    if directory and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    _require(all(part not in {"", ".", ".."} and _SEGMENT.fullmatch(part)
                 for part in parts), "ARCHIVE_PATH_INVALID")
    _require(len(parts) <= 32 and len(name.encode("ascii")) <= 1024, "ARCHIVE_PATH_INVALID")
    return name


class _Inventory:
    def __init__(self, limits: ArchiveLimits):
        self.limits = limits
        self.entries = 0
        self.total = 0
        self.names: dict[str, bool] = {}
        self.folded: set[str] = set()
        self.assets: list[FrontendAsset] = []

    def add(self, raw: str, directory: bool, size: int, reader) -> None:
        self.entries += 1
        _require(self.entries <= self.limits.max_entries, "ARCHIVE_ENTRY_LIMIT")
        name = _path(raw, directory)
        _require(name.casefold() not in self.folded, "ARCHIVE_PATH_COLLISION")
        self.folded.add(name.casefold())
        self.names[name] = directory
        _require(type(size) is int and size >= 0, "ARCHIVE_SIZE_INVALID")
        if directory:
            _require(size == 0, "ARCHIVE_DIRECTORY_PAYLOAD")
            return
        _require(size <= self.limits.max_file_bytes, "ARCHIVE_FILE_LIMIT")
        self.total += size
        _require(self.total <= self.limits.max_expanded_bytes, "ARCHIVE_EXPANSION_LIMIT")
        # The read bound is independent of a potentially hostile declared size.
        with reader() as stream:
            body = stream.read(size + 1)
        _require(len(body) == size, "ARCHIVE_SIZE_MISMATCH")
        suffix = "." + name.rsplit(".", 1)[1].lower() if "." in name else ""
        self.assets.append(FrontendAsset(name, _digest(body),
                                        _CONTENT_TYPES.get(suffix, "application/octet-stream"), body))

    def finish(self) -> tuple[FrontendAsset, ...]:
        _require(self.names.get("index.html") is False, "ARCHIVE_INDEX_REQUIRED")
        # Include implicit parents in the collision check: a/A/x is ambiguous too.
        seen: dict[str, str] = {}
        for name, directory in self.names.items():
            parts = name.split("/")
            for end in range(1, len(parts) + 1):
                parent = "/".join(parts[:end])
                folded = parent.casefold()
                _require(seen.get(folded, parent) == parent, "ARCHIVE_PATH_COLLISION")
                seen[folded] = parent
                if end < len(parts):
                    _require(self.names.get(parent, True), "ARCHIVE_PARENT_IS_FILE")
        return tuple(sorted(self.assets, key=lambda asset: asset.path))


def _preflight_tar(expanded: bytes, limits: ArchiveLimits) -> None:
    """Walk physical headers before tarfile can recurse through GNU/PAX records."""
    offset = entries = total = 0
    while offset + 512 <= len(expanded):
        header = expanded[offset:offset + 512]
        if not any(header):
            _require(len(expanded) - offset >= 1024 and len(expanded) % 512 == 0
                     and not any(expanded[offset:]), "ARCHIVE_TAR_TRAILING_DATA")
            return
        entries += 1
        _require(entries <= limits.max_entries, "ARCHIVE_ENTRY_LIMIT")
        # Extended records can form an unbounded recursive chain inside tarfile.
        # No extension is needed for the supported short ASCII frontend paths.
        _require(header[156:157] in {b"0", b"\x00", b"5"}, "ARCHIVE_MEMBER_TYPE_INVALID")
        size_field = header[124:136].strip(b"\x00 ")
        _require(bool(size_field) and all(character in b"01234567" for character in size_field),
                 "ARCHIVE_SIZE_INVALID")
        size = int(size_field, 8)
        _require(size <= limits.max_file_bytes, "ARCHIVE_FILE_LIMIT")
        _require(header[156:157] != b"5" or size == 0, "ARCHIVE_DIRECTORY_PAYLOAD")
        total += size
        _require(total <= limits.max_expanded_bytes, "ARCHIVE_EXPANSION_LIMIT")
        offset += 512 + ((size + 511) // 512) * 512
    raise FrontendArchiveRejected("ARCHIVE_TAR_TRAILING_DATA")


def _inspect_tar(payload: bytes, inventory: _Inventory) -> None:
    # Bound decompression before tarfile processes extended headers or metadata.
    maximum = inventory.limits.max_expanded_bytes + inventory.limits.max_entries * 2048 + 10240
    decoder = zlib.decompressobj(wbits=31)
    expanded = decoder.decompress(payload, maximum + 1)
    _require(len(expanded) <= maximum and not decoder.unconsumed_tail, "ARCHIVE_EXPANSION_LIMIT")
    _require(decoder.eof and not decoder.unused_data, "ARCHIVE_GZIP_INVALID")
    _preflight_tar(expanded, inventory.limits)
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:", encoding="utf-8", errors="strict") as archive:
        for member in archive:
            _require((member.isfile() or member.isdir()) and member.sparse is None,
                     "ARCHIVE_MEMBER_TYPE_INVALID")
            _require(not member.pax_headers, "ARCHIVE_EXTENDED_METADATA_REJECTED")
            inventory.add(member.name, member.isdir(), member.size,
                          lambda member=member: archive.extractfile(member))
        # tarfile stops at the first zero header; no second archive or hidden tail.
        _require(len(expanded) % 512 == 0 and not any(expanded[archive.offset:]),
                 "ARCHIVE_TAR_TRAILING_DATA")


def _inspect_zip(payload: bytes, inventory: _Inventory) -> None:
    # Bound the central directory before ZipFile allocates one object per entry.
    _require(len(payload) >= 22 and payload[:4] == b"PK\x03\x04"
             and payload[-22:-18] == b"PK\x05\x06", "ARCHIVE_ZIP_LAYOUT_INVALID")
    _, disk, central_disk, disk_entries, entries, central_size, central_offset, comment_size = \
        struct.unpack("<4s4H2LH", payload[-22:])
    _require(disk == central_disk == comment_size == 0 and disk_entries == entries
             and entries != 65535 and central_offset + central_size == len(payload) - 22,
             "ARCHIVE_ZIP_LAYOUT_INVALID")
    _require(entries <= inventory.limits.max_entries, "ARCHIVE_ENTRY_LIMIT")
    # EOCD can lie about the count. ZipFile walks every physical central header,
    # so count and bound those records before allowing it to allocate ZipInfo.
    position, end, physical_entries = central_offset, central_offset + central_size, 0
    while position < end:
        physical_entries += 1
        _require(physical_entries <= inventory.limits.max_entries, "ARCHIVE_ENTRY_LIMIT")
        _require(position + 46 <= end and payload[position:position + 4] == b"PK\x01\x02",
                 "ARCHIVE_ZIP_LAYOUT_INVALID")
        name_size, extra_size, entry_comment_size = struct.unpack("<3H", payload[position + 28:position + 34])
        _require(0 < name_size <= 1024, "ARCHIVE_PATH_INVALID")
        _require(extra_size == entry_comment_size == 0, "ARCHIVE_EXTENDED_METADATA_REJECTED")
        position += 46 + name_size + extra_size + entry_comment_size
        _require(position <= end, "ARCHIVE_ZIP_LAYOUT_INVALID")
    _require(physical_entries == entries, "ARCHIVE_ZIP_LAYOUT_INVALID")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()
        _require(len(members) == entries, "ARCHIVE_ZIP_LAYOUT_INVALID")
        _require(not archive.comment, "ARCHIVE_EXTENDED_METADATA_REJECTED")
        for member in members:
            directory = member.is_dir()
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            _require(kind in ({0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}),
                     "ARCHIVE_MEMBER_TYPE_INVALID")
            _require(not member.flag_bits & 1 and member.compress_type in
                     {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "ARCHIVE_ZIP_ENCODING_INVALID")
            _require(member.orig_filename == member.filename, "ARCHIVE_PATH_INVALID")
            _require(not member.comment and not member.extra, "ARCHIVE_EXTENDED_METADATA_REJECTED")
            inventory.add(member.filename, directory, member.file_size,
                          lambda member=member: archive.open(member))


def inspect_frontend_archive(
    payload: bytes, *, expected_archive_digest: str, media_type: str,
    limits: ArchiveLimits = ArchiveLimits(),
) -> ValidatedFrontendArchive:
    """Hash before parsing; return immutable assets only after the entire archive passes.

    Limits may be tightened, never expanded above the fixed implementation caps.
    Paths are ASCII and case-unambiguous, rooted at index.html. Links, special
    files, hidden paths, extended metadata and encrypted ZIPs are unsupported.
    A digest match establishes byte identity only, not trusted provenance.
    """
    try:
        _require(type(limits) is ArchiveLimits, "ARCHIVE_LIMITS_INVALID")
        _require(type(payload) is bytes and 0 < len(payload) <= limits.max_archive_bytes,
                 "ARCHIVE_INPUT_LIMIT")
        _require(isinstance(expected_archive_digest, str) and
                 _SHA256.fullmatch(expected_archive_digest) is not None, "ARCHIVE_DIGEST_INVALID")
        _require(_digest(payload) == expected_archive_digest, "ARCHIVE_DIGEST_MISMATCH")
        inventory = _Inventory(limits)
        if media_type == "application/gzip":
            _inspect_tar(payload, inventory)
        elif media_type == "application/zip":
            _inspect_zip(payload, inventory)
        else:
            raise FrontendArchiveRejected("ARCHIVE_MEDIA_UNSUPPORTED")
        return ValidatedFrontendArchive(expected_archive_digest, media_type, inventory.finish())
    except FrontendArchiveRejected:
        raise
    except (ValueError, TypeError, AttributeError, OSError, EOFError, OverflowError,
            tarfile.TarError, zipfile.BadZipFile, zlib.error, UnicodeError, struct.error, RecursionError):
        raise FrontendArchiveRejected("ARCHIVE_MALFORMED") from None
