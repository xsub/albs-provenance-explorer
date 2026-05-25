from albs_graph.adapters.elf import is_elf, parse_elf
from synthetic_binaries import build_elf, build_go_elf


def test_parse_elf_extracts_needed_soname_runpath_and_dlopen() -> None:
    info = parse_elf(build_elf())

    assert info.is_elf
    assert info.bits == 64
    assert info.e_type == "dyn"
    assert set(info.needed) == {"libc.so.6", "libssl.so.3"}
    assert info.soname == "mylib.so.1"
    assert info.runpath == ("/opt/lib", "/usr/lib")
    assert info.dlopen is True
    assert info.linkage_kind() == "dynamic"


def test_parse_elf_without_dlopen_symbol() -> None:
    info = parse_elf(build_elf(with_dlopen=False))

    assert info.dlopen is False
    assert set(info.needed) == {"libc.so.6", "libssl.so.3"}


def test_non_elf_bytes_are_rejected() -> None:
    assert is_elf(b"not elf") is False
    info = parse_elf(b"not an elf file" + b"\x00" * 200)
    assert info.is_elf is False
    assert info.needed == ()


def test_elf_to_dict_is_serializable() -> None:
    data = parse_elf(build_elf()).to_dict()
    assert data["linkage"] == "dynamic"
    assert "libc.so.6" in data["needed"]
    assert data["runpath"] == ["/opt/lib", "/usr/lib"]


def test_parse_go_buildinfo_extracts_modules() -> None:
    info = parse_elf(build_go_elf())

    assert info.go_version == "go1.21.0"
    assert ("github.com/foo/bar", "v1.2.3") in info.go_deps
    assert ("golang.org/x/sys", "v0.10.0") in info.go_deps
