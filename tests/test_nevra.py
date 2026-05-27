from albs_graph.dependency import ArtifactIdentity, Ecosystem
from albs_graph.nevra import (
    RpmNevra,
    distro_generation,
    distro_version,
    rpm_metadata_from_filename,
)


def test_from_filename_parses_canonical_nvra() -> None:
    nevra = RpmNevra.from_filename("nginx-core-1.20.1-16.el9_4.1.x86_64.rpm")
    assert nevra is not None
    assert nevra.name == "nginx-core"
    assert nevra.version == "1.20.1"
    assert nevra.release == "16.el9_4.1"
    assert nevra.arch == "x86_64"
    assert nevra.epoch is None  # filenames never encode an epoch
    assert nevra.version_release == "1.20.1-16.el9_4.1"
    assert nevra.evr == "1.20.1-16.el9_4.1"


def test_from_filename_handles_noarch_src_and_dashed_names() -> None:
    assert RpmNevra.from_filename("nginx-all-modules-1.20.1-16.el10_2.noarch.rpm") == RpmNevra(
        name="nginx-all-modules", version="1.20.1", release="16.el10_2", arch="noarch"
    )
    src = RpmNevra.from_filename("nginx-1.20.1-16.el9_4.1.src.rpm")
    assert src is not None and src.arch == "src" and src.name == "nginx"


def test_from_filename_rejects_non_nvra_shapes() -> None:
    assert RpmNevra.from_filename("noarchitecture") is None  # no dot -> no arch
    assert RpmNevra.from_filename("foo.x86_64.rpm") is None  # arch but no n-v-r


def test_from_token_parses_nevra_with_and_without_epoch() -> None:
    epoch = RpmNevra.from_token("openssl-libs-1:3.0.7-27.el9.x86_64")
    assert (epoch.name, epoch.epoch, epoch.version, epoch.release, epoch.arch) == (
        "openssl-libs",
        "1",
        "3.0.7",
        "27.el9",
        "x86_64",
    )
    assert epoch.evr == "1:3.0.7-27.el9"  # the form dnf reports as the version
    assert epoch.version_release == "3.0.7-27.el9"  # epoch stripped

    plain = RpmNevra.from_token("zlib-1.2.11-40.el9.x86_64")
    assert plain.epoch is None
    assert plain.evr == "1.2.11-40.el9"


def test_from_token_drops_capability_tails_and_bare_names() -> None:
    assert RpmNevra.from_token("openssl-libs >= 1:3.0.7") == RpmNevra(name="openssl-libs")
    assert RpmNevra.from_token("glibc") == RpmNevra(name="glibc")
    # A name-shaped token with no digit in the version slot stays a bare name.
    assert RpmNevra.from_token("ca-certificates").evr is None


def test_distro_generation_only_takes_the_major() -> None:
    assert distro_generation("16.el9_4.1") == "el9"
    assert distro_generation("121.el10_2.alma.1") == "el10"
    assert distro_generation("1:3.0.7-27.el9") == "el9"
    assert distro_generation("2.39") is None
    # No leading dot -> not a dist tag (avoids matching stray "elNN").
    assert distro_generation("model-3") is None


def test_distro_version_keeps_major_and_optional_minor() -> None:
    assert distro_version("16.el9_4.1") == "9.4"
    assert distro_version("27.el9") == "9"
    assert distro_version("121.el10_2") == "10.2"
    assert distro_version("nope") is None


def test_nevra_distro_properties_read_from_release() -> None:
    nevra = RpmNevra.from_filename("glibc-2.39-121.el10_2.x86_64.rpm")
    assert nevra is not None
    assert nevra.distro == "el10"
    assert nevra.distro_version == "10.2"


def test_rpm_metadata_from_filename_is_lenient() -> None:
    full = rpm_metadata_from_filename("nginx-core-1.20.1-16.el9_4.1.x86_64.rpm")
    assert full == {
        "filename": "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm",
        "arch": "x86_64",
        "name": "nginx-core",
        "version": "1.20.1",
        "release": "16.el9_4.1",
    }
    # Arch is still reported even when the n-v-r split fails (legacy contract).
    partial = rpm_metadata_from_filename("foo.x86_64.rpm")
    assert partial == {"filename": "foo.x86_64.rpm", "arch": "x86_64"}
    # No final dot segment -> arch is None, no name/version/release.
    assert rpm_metadata_from_filename("bare") == {"filename": "bare", "arch": None}


def _nevra(filename: str) -> RpmNevra:
    nevra = RpmNevra.from_filename(filename)
    assert nevra is not None
    return nevra


def test_artifact_identity_renders_binary_purl_and_package_identity() -> None:
    identity = ArtifactIdentity(
        nevra=_nevra("nginx-core-1.20.1-16.el9_4.1.x86_64.rpm"), distro="almalinux-9"
    )
    assert identity.purl() == (
        "pkg:rpm/almalinux/nginx-core@1.20.1-16.el9_4.1?arch=x86_64&distro=almalinux-9"
    )
    pkg = identity.package_identity()
    assert pkg.ecosystem == Ecosystem.RPM
    assert pkg.namespace == "almalinux"
    assert pkg.version == "1.20.1-16.el9_4.1"  # version-release, no epoch
    assert pkg.purl == identity.purl()
    assert pkg.qualifiers == {"arch": "x86_64", "distro": "almalinux-9"}


def test_artifact_identity_marks_source_rpm_arch_src() -> None:
    identity = ArtifactIdentity(
        nevra=_nevra("nginx-1.20.1-16.el9_4.1.src.rpm"), distro="almalinux-9", is_srpm=True
    )
    assert identity.purl_arch == "src"
    assert identity.purl() == (
        "pkg:rpm/almalinux/nginx@1.20.1-16.el9_4.1?arch=src&distro=almalinux-9"
    )


def test_artifact_identity_carries_epoch_as_a_qualifier_not_in_version() -> None:
    # RPM convention: the epoch rides as a PURL qualifier, never in the version.
    identity = ArtifactIdentity(
        nevra=RpmNevra(name="openssl-libs", epoch="1", version="3.0.7", release="27.el9", arch="x86_64"),
        distro="almalinux-9",
    )
    assert identity.purl() == (
        "pkg:rpm/almalinux/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=almalinux-9&epoch=1"
    )
    assert identity.package_identity().version == "3.0.7-27.el9"
