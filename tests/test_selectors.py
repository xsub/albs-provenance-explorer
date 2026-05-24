from albs_graph.model import Node, NodeType
from albs_graph.provenance import make_binary_rpm_selector


def _node(name: str, arch: str) -> Node:
    return Node(f"rpm:{name}:{arch}", NodeType.BINARY_RPM, f"{name}.{arch}.rpm", {"name": name, "arch": arch})


_X86 = _node("nginx-core", "x86_64")
_AARCH = _node("nginx-core", "aarch64")
_NOARCH = _node("nginx-filesystem", "noarch")


def test_default_selector_keeps_x86_64_and_noarch() -> None:
    select = make_binary_rpm_selector()
    assert select(_X86) is True
    assert select(_NOARCH) is True
    assert select(_AARCH) is False


def test_all_archs_keeps_everything() -> None:
    select = make_binary_rpm_selector(all_archs=True)
    assert select(_X86) is True
    assert select(_AARCH) is True
    assert select(_NOARCH) is True


def test_explicit_arch_pins_one() -> None:
    select = make_binary_rpm_selector(arch="aarch64")
    assert select(_AARCH) is True
    assert select(_X86) is False


def test_package_filter() -> None:
    select = make_binary_rpm_selector(package="nginx-filesystem", all_archs=True)
    assert select(_NOARCH) is True
    assert select(_X86) is False
