"""Minimal, dependency-free ELF parser for rung-4 linkage analysis.

Rung 3 (``rpm_header``) reads the RPM header's recorded sonames. Rung 4 reads
the *actual ELF bytes* from the payload, which yields facts the header cannot:

- ``DT_NEEDED`` confirmed by the binary itself (not just RPM's auto-deps),
- ``DT_RPATH`` / ``DT_RUNPATH`` library search paths,
- whether the object is dynamically or statically linked,
- a best-effort ``dlopen`` capability flag,
- the build toolchain (Go / Rust) for static binaries.

The parser uses ELF *section* headers (present in essentially all distro RPM
binaries) to locate ``.dynamic`` / ``.dynstr`` / ``.dynsym``. Binaries stripped
of section headers return ``is_elf=True`` with empty analysis rather than
raising. It depends on nothing outside the standard library.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass, field

_ELF_MAGIC = b"\x7fELF"

# Dynamic tags.
_DT_NULL = 0
_DT_NEEDED = 1
_DT_SONAME = 14
_DT_RPATH = 15
_DT_RUNPATH = 29

# Section types.
_SHT_DYNAMIC = 6
_SHT_DYNSYM = 11

_DLOPEN_SYMBOLS = frozenset({"dlopen", "dlmopen"})


@dataclass(frozen=True)
class ElfInfo:
    is_elf: bool = False
    bits: int = 0
    endian: str = ""
    e_type: str = "unknown"
    has_dynamic: bool = False
    has_interp: bool = False
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    dlopen: bool = False
    toolchains: tuple[str, ...] = field(default_factory=tuple)

    def linkage_kind(self) -> str:
        """Plain-string linkage classification (mapped to the Linkage enum by callers)."""

        if self.needed:
            return "dynamic"
        if self.has_dynamic:
            return "dynamic"
        if self.is_elf and not self.has_interp:
            return "static"
        return "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "bits": self.bits,
            "e_type": self.e_type,
            "linkage": self.linkage_kind(),
            "needed": list(self.needed),
            "soname": self.soname,
            "rpath": list(self.rpath),
            "runpath": list(self.runpath),
            "dlopen": self.dlopen,
            "toolchains": list(self.toolchains),
        }


def is_elf(data: bytes) -> bool:
    return data[:4] == _ELF_MAGIC


def parse_elf(data: bytes) -> ElfInfo:
    """Parse an ELF object from its leading bytes. Never raises on bad input."""

    if not is_elf(data) or len(data) < 64:
        return ElfInfo(is_elf=False)
    try:
        return _parse(data)
    except (struct.error, IndexError, ValueError):
        # Truncated or unusual object: report it is ELF but analysis failed.
        return ElfInfo(is_elf=True)


def _parse(data: bytes) -> ElfInfo:
    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]  # 1 = little, 2 = big
    bits = 64 if ei_class == 2 else 32
    endian = "big" if ei_data == 2 else "little"
    en = ">" if ei_data == 2 else "<"

    if bits == 64:
        # from e_type(H): skip e_machine+e_version+e_entry+e_phoff (2+4+8+8=22),
        # read e_shoff(Q), skip e_flags+e_ehsize+e_phentsize+e_phnum (4+2+2+2=10),
        # read e_shentsize/e_shnum/e_shstrndx (HHH).
        e_type, e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            en + "H22xQ10xHHH", data, 16
        )
    else:
        # 32-bit: skip e_machine+e_version+e_entry+e_phoff (2+4+4+4=14), read e_shoff(I).
        e_type, e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            en + "H14xI10xHHH", data, 16
        )

    type_name = {0: "none", 1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, "unknown")
    if e_shoff == 0 or e_shnum == 0:
        return ElfInfo(is_elf=True, bits=bits, endian=endian, e_type=type_name)

    sections = _read_sections(data, en, bits, e_shoff, e_shentsize, e_shnum)
    shstr = sections[e_shstrndx] if e_shstrndx < len(sections) else None
    names = {
        _cstr(data, shstr[2] + s[0]): s for s in sections
    } if shstr else {}

    has_dynamic = ".dynamic" in names or any(s[1] == _SHT_DYNAMIC for s in sections)
    has_interp = ".interp" in names
    toolchains = _detect_toolchains(names)

    needed: list[str] = []
    rpath: list[str] = []
    runpath: list[str] = []
    soname: str | None = None
    dlopen = False

    dynstr = names.get(".dynstr")
    dynamic = names.get(".dynamic")
    if dynamic and dynstr:
        strtab = data[dynstr[2] : dynstr[2] + dynstr[3]]
        for tag, val in _read_dynamic(data, en, bits, dynamic[2], dynamic[3]):
            if tag == _DT_NEEDED:
                needed.append(_cstr_from(strtab, val))
            elif tag == _DT_SONAME:
                soname = _cstr_from(strtab, val)
            elif tag == _DT_RPATH:
                rpath.extend(_split_paths(_cstr_from(strtab, val)))
            elif tag == _DT_RUNPATH:
                runpath.extend(_split_paths(_cstr_from(strtab, val)))

    dynsym = names.get(".dynsym")
    if dynsym and dynstr:
        dlopen = _has_dlopen(data, en, bits, dynsym, dynstr)

    return ElfInfo(
        is_elf=True,
        bits=bits,
        endian=endian,
        e_type=type_name,
        has_dynamic=has_dynamic,
        has_interp=has_interp,
        needed=tuple(needed),
        soname=soname,
        rpath=tuple(rpath),
        runpath=tuple(runpath),
        dlopen=dlopen,
        toolchains=toolchains,
    )


# Section header tuple: (name_offset, type, file_offset, size, link, entsize)
def _read_sections(
    data: bytes, en: str, bits: int, shoff: int, entsize: int, num: int
) -> list[tuple[int, int, int, int, int, int]]:
    sections: list[tuple[int, int, int, int, int, int]] = []
    for i in range(num):
        base = shoff + i * entsize
        if bits == 64:
            name, stype, _flags, _addr, offset, size, link, _info, _align, ent = struct.unpack_from(
                en + "IIQQQQIIQQ", data, base
            )
        else:
            name, stype, _flags, _addr, offset, size, link, _info, _align, ent = struct.unpack_from(
                en + "IIIIIIIIII", data, base
            )
        sections.append((name, stype, offset, size, link, ent))
    return sections


def _read_dynamic(
    data: bytes, en: str, bits: int, offset: int, size: int
) -> list[tuple[int, int]]:
    entries: list[tuple[int, int]] = []
    step = 16 if bits == 64 else 8
    fmt = en + ("qQ" if bits == 64 else "iI")
    for pos in range(offset, offset + size, step):
        tag, val = struct.unpack_from(fmt, data, pos)
        if tag == _DT_NULL:
            break
        entries.append((tag, val))
    return entries


def _has_dlopen(
    data: bytes,
    en: str,
    bits: int,
    dynsym: tuple[int, int, int, int, int, int],
    dynstr: tuple[int, int, int, int, int, int],
) -> bool:
    sym_offset, sym_size, entsize = dynsym[2], dynsym[3], dynsym[5]
    if entsize == 0:
        entsize = 24 if bits == 64 else 16
    strtab = data[dynstr[2] : dynstr[2] + dynstr[3]]
    for pos in range(sym_offset, sym_offset + sym_size, entsize):
        st_name = struct.unpack_from(en + "I", data, pos)[0]
        if _cstr_from(strtab, st_name) in _DLOPEN_SYMBOLS:
            return True
    return False


def _detect_toolchains(names: Mapping[str, object]) -> tuple[str, ...]:
    found: list[str] = []
    if ".go.buildinfo" in names or ".note.go.buildid" in names:
        found.append("go")
    if ".rustc" in names or ".rodata.rustc" in names:
        found.append("rust")
    return tuple(found)


def _split_paths(value: str) -> list[str]:
    return [part for part in value.split(":") if part]


def _cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def _cstr_from(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", "replace")
