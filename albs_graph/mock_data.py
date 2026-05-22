from __future__ import annotations

from .model import Node, NodeType, ProvenanceGraph, Relation


def build_mock_package_graph(package: str = "openssl") -> ProvenanceGraph:
    if package != "openssl":
        return build_generic_mock_graph(package)
    return build_mock_openssl_graph()


def build_mock_openssl_graph() -> ProvenanceGraph:
    g = ProvenanceGraph()

    g.add_node(Node("src:openssl", NodeType.SOURCE_PACKAGE, "openssl", {"ecosystem": "rpm"}))
    g.add_node(
        Node(
            "repo:git.almalinux.org/rpms/openssl",
            NodeType.GIT_REPOSITORY,
            "git.almalinux.org/rpms/openssl",
            {"origin": "git.almalinux.org", "modified_package_possible": True},
        )
    )
    g.add_node(
        Node(
            "commit:openssl:abc123",
            NodeType.GIT_COMMIT,
            "abc123",
            {"branch": "a9", "example": True},
        )
    )
    g.add_node(
        Node(
            "cas:source:openssl:xyz789",
            NodeType.CAS_ATTESTATION,
            "CAS source attestation xyz789",
            {
                "system": "Codenotary CAS",
                "subject_type": "source_commit",
                "cas_hash": "xyz789",
                "trusted": True,
                "example": True,
            },
        )
    )
    g.add_node(
        Node(
            "buildenv:alma9:x86_64",
            NodeType.BUILD_ENVIRONMENT,
            "AlmaLinux 9 x86_64 mock build environment",
            {"distribution": "AlmaLinux", "major_version": "9", "arch": "x86_64"},
        )
    )
    g.add_node(
        Node(
            "build:albs:123456",
            NodeType.BUILD_TASK,
            "ALBS build task 123456",
            {"system": "ALBS", "status": "completed", "example": True},
        )
    )
    g.add_node(
        Node(
            "srpm:openssl:3.0.7-28.el9_4",
            NodeType.SRPM,
            "openssl-3.0.7-28.el9_4.src.rpm",
            {"nevra": "openssl-1:3.0.7-28.el9_4.src"},
        )
    )
    g.add_node(
        Node(
            "rpm:openssl-libs:3.0.7-28.el9_4:x86_64",
            NodeType.BINARY_RPM,
            "openssl-libs-3.0.7-28.el9_4.x86_64.rpm",
            {
                "name": "openssl-libs",
                "epoch": "1",
                "version": "3.0.7",
                "release": "28.el9_4",
                "arch": "x86_64",
            },
        )
    )
    g.add_node(
        Node(
            "cas:artifact:openssl-libs:x86_64",
            NodeType.CAS_ATTESTATION,
            "CAS artifact attestation for openssl-libs",
            {
                "system": "Codenotary CAS",
                "subject_type": "rpm_artifact",
                "cas_hash": "openssl-libs-x86_64-cas",
                "trusted": True,
                "example": True,
            },
        )
    )
    g.add_node(
        Node(
            "test:openssl:albs:123456",
            NodeType.TEST_RESULT,
            "ALBS test result for openssl build 123456",
            {"status": "passed", "example": True},
        )
    )
    g.add_node(
        Node(
            "sig:gpg:alma9",
            NodeType.SIGNATURE,
            "AlmaLinux 9 GPG signature",
            {"status": "signed", "example": True},
        )
    )
    g.add_node(
        Node(
            "repo:alma9:baseos:x86_64",
            NodeType.REPOSITORY_RELEASE,
            "AlmaLinux 9 BaseOS x86_64",
            {"distribution": "AlmaLinux", "major_version": "9", "repository": "BaseOS"},
        )
    )
    g.add_node(
        Node(
            "errata:ALSA-2026-0001",
            NodeType.ERRATA,
            "ALSA-2026-0001",
            {"type": "security", "example": True},
        )
    )
    g.add_node(Node("cve:CVE-2026-0001", NodeType.CVE, "CVE-2026-0001", {"example": True}))
    g.add_node(
        Node(
            "sbom:openssl:cyclonedx",
            NodeType.SBOM,
            "CycloneDX SBOM for openssl",
            {"format": "CycloneDX", "example": True},
        )
    )
    g.add_node(
        Node(
            "external:zlib",
            NodeType.EXTERNAL_PACKAGE,
            "zlib runtime dependency",
            {"ecosystem": "rpm", "scope": "runtime"},
        )
    )

    g.add_edge("src:openssl", "repo:git.almalinux.org/rpms/openssl", Relation.STORED_IN)
    g.add_edge("repo:git.almalinux.org/rpms/openssl", "commit:openssl:abc123", Relation.POINTS_TO)
    g.add_edge("commit:openssl:abc123", "cas:source:openssl:xyz789", Relation.AUTHENTICATED_BY)
    g.add_edge("cas:source:openssl:xyz789", "build:albs:123456", Relation.BUILT_BY)
    g.add_edge("build:albs:123456", "buildenv:alma9:x86_64", Relation.BUILT_IN)
    g.add_edge("build:albs:123456", "srpm:openssl:3.0.7-28.el9_4", Relation.PRODUCES)
    g.add_edge("build:albs:123456", "rpm:openssl-libs:3.0.7-28.el9_4:x86_64", Relation.PRODUCES)
    g.add_edge(
        "rpm:openssl-libs:3.0.7-28.el9_4:x86_64",
        "cas:artifact:openssl-libs:x86_64",
        Relation.AUTHENTICATED_BY,
    )
    g.add_edge("build:albs:123456", "test:openssl:albs:123456", Relation.TESTED_BY)
    g.add_edge("rpm:openssl-libs:3.0.7-28.el9_4:x86_64", "sig:gpg:alma9", Relation.SIGNED_AS)
    g.add_edge(
        "rpm:openssl-libs:3.0.7-28.el9_4:x86_64", "repo:alma9:baseos:x86_64", Relation.RELEASED_TO
    )
    g.add_edge("rpm:openssl-libs:3.0.7-28.el9_4:x86_64", "errata:ALSA-2026-0001", Relation.FIXES)
    g.add_edge("errata:ALSA-2026-0001", "cve:CVE-2026-0001", Relation.FIXES)
    g.add_edge(
        "rpm:openssl-libs:3.0.7-28.el9_4:x86_64", "sbom:openssl:cyclonedx", Relation.DESCRIBED_BY
    )
    g.add_edge("rpm:openssl-libs:3.0.7-28.el9_4:x86_64", "external:zlib", Relation.REQUIRES_RUNTIME)

    return g


def build_generic_mock_graph(package: str) -> ProvenanceGraph:
    g = ProvenanceGraph()
    g.add_node(Node(f"src:{package}", NodeType.SOURCE_PACKAGE, package, {"ecosystem": "rpm"}))
    g.add_node(
        Node(
            f"repo:git.almalinux.org/rpms/{package}",
            NodeType.GIT_REPOSITORY,
            f"git.almalinux.org/rpms/{package}",
            {"origin": "git.almalinux.org", "example": True},
        )
    )
    g.add_node(Node(f"commit:{package}:abc123", NodeType.GIT_COMMIT, "abc123", {"example": True}))
    g.add_node(
        Node(
            f"cas:source:{package}:xyz789",
            NodeType.CAS_ATTESTATION,
            "CAS source attestation xyz789",
            {
                "system": "Codenotary CAS",
                "subject_type": "source_commit",
                "cas_hash": "xyz789",
                "trusted": True,
                "example": True,
            },
        )
    )
    g.add_node(Node(f"build:albs:{package}:1", NodeType.BUILD_TASK, f"ALBS build for {package}"))
    g.add_node(Node(f"rpm:{package}:x86_64", NodeType.BINARY_RPM, f"{package}.x86_64.rpm"))
    g.add_node(
        Node(
            f"cas:artifact:{package}:x86_64",
            NodeType.CAS_ATTESTATION,
            f"CAS artifact attestation for {package}",
            {
                "system": "Codenotary CAS",
                "subject_type": "rpm_artifact",
                "cas_hash": f"{package}-x86_64-cas",
                "trusted": True,
                "example": True,
            },
        )
    )
    g.add_node(Node(f"sig:gpg:{package}", NodeType.SIGNATURE, "GPG signature"))
    g.add_node(
        Node("repo:alma9:baseos:x86_64", NodeType.REPOSITORY_RELEASE, "AlmaLinux 9 BaseOS x86_64")
    )
    g.add_node(Node(f"sbom:{package}:cyclonedx", NodeType.SBOM, f"CycloneDX SBOM for {package}"))

    g.add_edge(f"src:{package}", f"repo:git.almalinux.org/rpms/{package}", Relation.STORED_IN)
    g.add_edge(
        f"repo:git.almalinux.org/rpms/{package}", f"commit:{package}:abc123", Relation.POINTS_TO
    )
    g.add_edge(
        f"commit:{package}:abc123", f"cas:source:{package}:xyz789", Relation.AUTHENTICATED_BY
    )
    g.add_edge(f"cas:source:{package}:xyz789", f"build:albs:{package}:1", Relation.BUILT_BY)
    g.add_edge(f"build:albs:{package}:1", f"rpm:{package}:x86_64", Relation.PRODUCES)
    g.add_edge(f"rpm:{package}:x86_64", f"cas:artifact:{package}:x86_64", Relation.AUTHENTICATED_BY)
    g.add_edge(f"rpm:{package}:x86_64", f"sig:gpg:{package}", Relation.SIGNED_AS)
    g.add_edge(f"rpm:{package}:x86_64", "repo:alma9:baseos:x86_64", Relation.RELEASED_TO)
    g.add_edge(f"rpm:{package}:x86_64", f"sbom:{package}:cyclonedx", Relation.DESCRIBED_BY)
    return g
