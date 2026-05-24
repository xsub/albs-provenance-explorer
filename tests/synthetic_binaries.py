"""Hand-built ELF and RPM byte structures for offline rung-4 tests.

No network, no real binaries: just enough valid structure for the parsers in
``albs_graph.adapters.elf`` / ``rpm_header`` / ``rpm_payload`` to exercise.
"""

from __future__ import annotations

import gzip
import struct

# RPM header data types.
_STRING = 6
_INT32 = 4
_STRING_ARRAY = 8


def build_elf(
    *,
    needed: tuple[str, ...] = ("libc.so.6", "libssl.so.3"),
    runpath: str = "/opt/lib:/usr/lib",
    soname: str = "mylib.so.1",
    with_dlopen: bool = True,
) -> bytes:
    """A minimal 64-bit little-endian ELF (ET_DYN) with .dynamic/.dynstr/.dynsym."""

    shstr = b"\x00.shstrtab\x00.dynstr\x00.dynamic\x00.dynsym\x00"
    n_shstrtab = shstr.index(b".shstrtab")
    n_dynstr = shstr.index(b".dynstr")
    n_dynamic = shstr.index(b".dynamic")
    n_dynsym = shstr.index(b".dynsym")

    dynstr = bytearray(b"\x00")
    offsets: dict[str, int] = {}

    def add(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode() + b"\x00")
        offsets[text] = offset
        return offset

    for lib in needed:
        add(lib)
    off_runpath = add(runpath)
    off_soname = add(soname)
    off_dlopen = add("dlopen")

    dyn = b""
    for lib in needed:
        dyn += struct.pack("<qQ", 1, offsets[lib])  # DT_NEEDED
    dyn += struct.pack("<qQ", 14, off_soname)  # DT_SONAME
    dyn += struct.pack("<qQ", 29, off_runpath)  # DT_RUNPATH
    dyn += struct.pack("<qQ", 0, 0)  # DT_NULL

    sym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)  # null symbol
    if with_dlopen:
        sym += struct.pack("<IBBHQQ", off_dlopen, 0x12, 0, 0, 0, 0)

    ehsize = 64
    body = bytearray()
    o_dynstr = ehsize + len(body)
    body += bytes(dynstr)
    o_dyn = ehsize + len(body)
    body += dyn
    o_sym = ehsize + len(body)
    body += sym
    o_shstr = ehsize + len(body)
    body += shstr
    while (ehsize + len(body)) % 8:
        body += b"\x00"
    o_sh = ehsize + len(body)

    def shdr(name: int, stype: int, offset: int, size: int, link: int, entsize: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, stype, 0, 0, offset, size, link, 0, 1, entsize)

    sh = b""
    sh += shdr(0, 0, 0, 0, 0, 0)
    sh += shdr(n_shstrtab, 3, o_shstr, len(shstr), 0, 0)
    sh += shdr(n_dynstr, 3, o_dynstr, len(dynstr), 0, 0)
    sh += shdr(n_dynamic, 6, o_dyn, len(dyn), 2, 16)
    sh += shdr(n_dynsym, 11, o_sym, len(sym), 2, 24)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,  # e_type = ET_DYN
        0x3E,  # e_machine = x86-64
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        o_sh,  # e_shoff
        0,  # e_flags
        ehsize,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        5,  # e_shnum
        1,  # e_shstrndx
    )
    assert len(ehdr) == 64
    return ehdr + bytes(body) + sh


def _rpm_section(entries: list[tuple[int, int, object]]) -> bytes:
    store = bytearray()
    index: list[tuple[int, int, int, int]] = []
    for tag, dtype, value in entries:
        offset = len(store)
        if dtype == _STRING and isinstance(value, str):
            store += value.encode() + b"\x00"
            count = 1
        elif dtype == _STRING_ARRAY and isinstance(value, list):
            for item in value:
                store += str(item).encode() + b"\x00"
            count = len(value)
        elif dtype == _INT32 and isinstance(value, list):
            for number in value:
                store += int(number).to_bytes(4, "big")
            count = len(value)
        else:  # pragma: no cover - test data only
            raise AssertionError(f"unsupported test tag type {dtype}")
        index.append((tag, dtype, offset, count))
    out = bytearray(b"\x8e\xad\xe8\x01" + b"\x00" * 4)
    out += len(index).to_bytes(4, "big") + len(store).to_bytes(4, "big")
    for tag, dtype, offset, count in index:
        out += tag.to_bytes(4, "big") + dtype.to_bytes(4, "big")
        out += offset.to_bytes(4, "big") + count.to_bytes(4, "big")
    out += store
    return bytes(out)


def _cpio_entry(path: str, data: bytes, *, mode: int = 0o100644) -> bytes:
    name = path.encode() + b"\x00"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    block = bytearray(header + name)
    block += b"\x00" * ((4 - (len(block) % 4)) % 4)
    block += data
    block += b"\x00" * ((4 - (len(block) % 4)) % 4)
    return bytes(block)


def _cpio(files: dict[str, bytes]) -> bytes:
    out = bytearray()
    for path, data in files.items():
        out += _cpio_entry(path, data)
    trailer = b"TRAILER!!!\x00"
    fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    block = bytearray(header + trailer)
    block += b"\x00" * ((4 - (len(block) % 4)) % 4)
    out += block
    return bytes(out)


def build_rpm(
    files: dict[str, bytes],
    *,
    compressor: str = "gzip",
    name: str = "demo",
    version: str = "1.0",
    release: str = "1.el9",
    arch: str = "x86_64",
) -> bytes:
    """A minimal RPM: lead + signature header + main header + compressed cpio."""

    lead = b"\xed\xab\xee\xdb" + b"\x00" * 92
    sig = _rpm_section([(62, _STRING, "sig")])
    sig += b"\x00" * ((8 - (len(sig) % 8)) % 8)
    main = _rpm_section(
        [
            (1000, _STRING, name),
            (1001, _STRING, version),
            (1002, _STRING, release),
            (1022, _STRING, arch),
            (1124, _STRING, "cpio"),
            (1125, _STRING, compressor),
        ]
    )
    cpio = _cpio(files)
    if compressor == "gzip":
        payload = gzip.compress(cpio)
    else:  # pragma: no cover - tests use gzip
        raise AssertionError(f"test builder only supports gzip, not {compressor}")
    return lead + sig + main + payload
