"""Minimal, dependency-free RPM header parser.

An RPM file is laid out as: lead (96 bytes) -> signature header -> main header
-> compressed payload. The *header* (which sits near the front of the file)
already carries the package's dependency facts, because rpmbuild's automatic
dependency generator runs ELF extraction at build time and bakes the results
into header tags. In particular ``RPMTAG_REQUIRENAME`` holds the dynamic
``DT_NEEDED`` sonames (``libssl.so.3()(64bit)`` and friends) and
``RPMTAG_PROVIDENAME`` holds the sonames the package exports.

This means dynamic-linkage evidence is obtainable from the *header alone* -- no
payload, no ELF parsing -- which is exactly what makes an HTTP Range read of an
RPM cheap (see ``rpm_remote``). This module only parses; it never fetches.

These sonames are RPM's *recorded* dependency facts, not an independent ELF
parse, so callers should label the evidence accordingly ("rpm_header_soname")
rather than implying the binary itself was inspected.
"""

from __future__ import annotations

from dataclasses import dataclass

# RPM header tag numbers (subset we read).
_TAG_NAME = 1000
_TAG_VERSION = 1001
_TAG_RELEASE = 1002
_TAG_LICENSE = 1014
_TAG_ARCH = 1022
_TAG_SUMMARY = 1004
_TAG_DESCRIPTION = 1005
_TAG_URL = 1020
_TAG_VENDOR = 1011
_TAG_SOURCERPM = 1044
_TAG_PROVIDENAME = 1047
_TAG_REQUIREFLAGS = 1048
_TAG_REQUIRENAME = 1049
_TAG_REQUIREVERSION = 1050
_TAG_PROVIDEFLAGS = 1112
_TAG_PROVIDEVERSION = 1113
_TAG_PAYLOADFORMAT = 1124
_TAG_PAYLOADCOMPRESSOR = 1125

# RPM header data types.
_TYPE_INT16 = 3
_TYPE_INT32 = 4
_TYPE_STRING = 6
_TYPE_STRING_ARRAY = 8
_TYPE_I18NSTRING = 9

_LEAD_MAGIC = b"\xed\xab\xee\xdb"
_HEADER_MAGIC = b"\x8e\xad\xe8"
_LEAD_SIZE = 96
_INTRO_SIZE = 16  # 8 (magic+version+reserved) + 4 (nindex) + 4 (store size)
_MAX_HEADER_BYTES = 64 * 1024 * 1024


class RpmHeaderError(ValueError):
    """Raised when a buffer is not a parseable RPM header (or is truncated)."""


@dataclass(frozen=True)
class RpmDependency:
    name: str  # full capability expression, e.g. "libssl.so.3()(64bit)"
    flags: int
    version: str
    kind: str  # one of: soname, package, file, rpmlib, rich, config
    soname: str | None  # e.g. "libssl.so.3" when kind == "soname"


@dataclass(frozen=True)
class RpmHeader:
    name: str | None
    version: str | None
    release: str | None
    arch: str | None
    sourcerpm: str | None
    requires: tuple[RpmDependency, ...]
    provides: tuple[RpmDependency, ...]
    header_bytes: int  # total lead+signature+main header size consumed
    payload_format: str | None = None  # e.g. "cpio"
    payload_compressor: str | None = None  # e.g. "zstd", "gzip", "xz"
    license: str | None = None  # RPMTAG_LICENSE (1014), e.g. "BSD-2-Clause"
    summary: str | None = None  # RPMTAG_SUMMARY (1004)
    description: str | None = None  # RPMTAG_DESCRIPTION (1005)
    url: str | None = None  # RPMTAG_URL (1020)
    vendor: str | None = None  # RPMTAG_VENDOR (1011)

    @property
    def soname_requires(self) -> tuple[RpmDependency, ...]:
        return tuple(dep for dep in self.requires if dep.kind == "soname")

    @property
    def payload_offset(self) -> int:
        """Byte offset where the compressed payload begins (end of main header)."""

        return self.header_bytes


def required_header_length(data: bytes) -> int:
    """Bytes needed to fully cover lead + signature + main header.

    Grows as more of the structure becomes readable, so a caller can fetch
    incrementally: fetch, call this, fetch the remainder, repeat. Returns a
    value <= len(data) once the whole header is present.
    """

    if len(data) < _LEAD_SIZE + _INTRO_SIZE:
        return _LEAD_SIZE + _INTRO_SIZE

    sig_offset = _LEAD_SIZE
    sig_nindex = _u32(data, sig_offset + 8)
    sig_hsize = _u32(data, sig_offset + 12)
    sig_section = _INTRO_SIZE + sig_nindex * 16 + sig_hsize
    sig_pad = (8 - (sig_hsize % 8)) % 8  # signature header is padded to 8 bytes
    sig_end = sig_offset + sig_section + sig_pad

    if len(data) < sig_end + _INTRO_SIZE:
        return sig_end + _INTRO_SIZE

    main_nindex = _u32(data, sig_end + 8)
    main_hsize = _u32(data, sig_end + 12)
    return sig_end + _INTRO_SIZE + main_nindex * 16 + main_hsize


def parse_rpm_header(data: bytes) -> RpmHeader:
    """Parse the main RPM header out of a buffer that covers it.

    Raises :class:`RpmHeaderError` if the lead magic is wrong or the buffer is
    too short to contain the full header.
    """

    if len(data) < _LEAD_SIZE + _INTRO_SIZE:
        raise RpmHeaderError("buffer too small for RPM lead + header intro")
    if data[:4] != _LEAD_MAGIC:
        raise RpmHeaderError("missing RPM lead magic (edabeedb)")

    needed = required_header_length(data)
    if needed > _MAX_HEADER_BYTES:
        raise RpmHeaderError(f"implausible header size {needed} bytes")
    if len(data) < needed:
        raise RpmHeaderError(f"need {needed} header bytes, have {len(data)}")

    # Skip the signature header to find the main header offset.
    sig_offset = _LEAD_SIZE
    sig_hsize = _u32(data, sig_offset + 12)
    sig_nindex = _u32(data, sig_offset + 8)
    sig_pad = (8 - (sig_hsize % 8)) % 8
    main_offset = sig_offset + _INTRO_SIZE + sig_nindex * 16 + sig_hsize + sig_pad

    tags, end = _parse_section(data, main_offset)
    requires = _dependencies(
        tags.get(_TAG_REQUIRENAME), tags.get(_TAG_REQUIREFLAGS), tags.get(_TAG_REQUIREVERSION)
    )
    provides = _dependencies(
        tags.get(_TAG_PROVIDENAME), tags.get(_TAG_PROVIDEFLAGS), tags.get(_TAG_PROVIDEVERSION)
    )
    return RpmHeader(
        name=_as_string(tags.get(_TAG_NAME)),
        version=_as_string(tags.get(_TAG_VERSION)),
        release=_as_string(tags.get(_TAG_RELEASE)),
        arch=_as_string(tags.get(_TAG_ARCH)),
        sourcerpm=_as_string(tags.get(_TAG_SOURCERPM)),
        requires=requires,
        provides=provides,
        header_bytes=end,
        payload_format=_as_string(tags.get(_TAG_PAYLOADFORMAT)),
        payload_compressor=_as_string(tags.get(_TAG_PAYLOADCOMPRESSOR)),
        license=_as_string(tags.get(_TAG_LICENSE)),
        summary=_as_string(tags.get(_TAG_SUMMARY)),
        description=_as_string(tags.get(_TAG_DESCRIPTION)),
        url=_as_string(tags.get(_TAG_URL)),
        vendor=_as_string(tags.get(_TAG_VENDOR)),
    )


def classify_capability(name: str) -> tuple[str, str | None]:
    """Classify an RPM capability expression and extract a soname if present."""

    if name.startswith("rpmlib("):
        return "rpmlib", None
    if name.startswith("config("):
        return "config", None
    if name.startswith("("):
        return "rich", None
    if name.startswith("/"):
        return "file", None
    if ".so" in name:
        return "soname", name.split("(", 1)[0]
    # Other parenthesised capabilities (rtld(GNU_HASH), feature(...)) are synthetic
    # rpm features, not real package names -- never emit them as package requires.
    if "(" in name:
        return "rpmlib", None
    return "package", None


def _dependencies(
    names: object, flags: object, versions: object
) -> tuple[RpmDependency, ...]:
    name_list = _as_string_list(names)
    flag_list = _as_int_list(flags)
    version_list = _as_string_list(versions)
    deps: list[RpmDependency] = []
    for index, name in enumerate(name_list):
        kind, soname = classify_capability(name)
        deps.append(
            RpmDependency(
                name=name,
                flags=flag_list[index] if index < len(flag_list) else 0,
                version=version_list[index] if index < len(version_list) else "",
                kind=kind,
                soname=soname,
            )
        )
    return tuple(deps)


def _parse_section(data: bytes, offset: int) -> tuple[dict[int, object], int]:
    if data[offset : offset + 3] != _HEADER_MAGIC:
        raise RpmHeaderError("missing RPM header magic (8eade8)")
    nindex = _u32(data, offset + 8)
    hsize = _u32(data, offset + 12)
    index_start = offset + _INTRO_SIZE
    store_start = index_start + nindex * 16
    store_end = store_start + hsize
    if store_end > len(data):
        raise RpmHeaderError("truncated RPM header store")
    store = data[store_start:store_end]
    tags: dict[int, object] = {}
    for i in range(nindex):
        entry = index_start + i * 16
        tag = _u32(data, entry)
        dtype = _u32(data, entry + 4)
        value_offset = _u32(data, entry + 8)
        count = _u32(data, entry + 12)
        tags[tag] = _read_value(store, value_offset, dtype, count)
    return tags, store_end


def _read_value(store: bytes, offset: int, dtype: int, count: int) -> object:
    if dtype == _TYPE_STRING:
        return _cstring(store, offset)
    if dtype in (_TYPE_STRING_ARRAY, _TYPE_I18NSTRING):
        values: list[str] = []
        cursor = offset
        for _ in range(count):
            text, cursor = _cstring_advance(store, cursor)
            values.append(text)
        return values
    if dtype == _TYPE_INT32:
        return [int.from_bytes(store[offset + i * 4 : offset + i * 4 + 4], "big") for i in range(count)]
    if dtype == _TYPE_INT16:
        return [int.from_bytes(store[offset + i * 2 : offset + i * 2 + 2], "big") for i in range(count)]
    return None


def _cstring(store: bytes, offset: int) -> str:
    end = store.find(b"\x00", offset)
    if end == -1:
        end = len(store)
    return store[offset:end].decode("utf-8", "replace")


def _cstring_advance(store: bytes, offset: int) -> tuple[str, int]:
    end = store.find(b"\x00", offset)
    if end == -1:
        end = len(store)
    return store[offset:end].decode("utf-8", "replace"), end + 1


def _as_string(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and isinstance(value[0], str):
        return value[0]
    return None


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _as_int_list(value: object) -> list[int]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, int)]
    return []


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")
