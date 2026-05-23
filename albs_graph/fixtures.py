from __future__ import annotations

from .model import Node, NodeType, ProvenanceGraph, Relation


SYNTHETIC_PACKAGE = "synthetic"
SYNTHETIC_RPM_ID = "rpm:synthetic-core:1.0.0-1.el9:x86_64"


def build_synthetic_package_graph(package: str = SYNTHETIC_PACKAGE) -> ProvenanceGraph:
    if package != SYNTHETIC_PACKAGE:
        return build_generic_synthetic_graph(package)
    return build_synthetic_fixture_graph()


def build_synthetic_fixture_graph() -> ProvenanceGraph:
    g = ProvenanceGraph()

    g.add_node(Node("src:synthetic", NodeType.SOURCE_PACKAGE, "synthetic", {"ecosystem": "rpm"}))
    g.add_node(
        Node(
            "repo:git.almalinux.org/rpms/synthetic",
            NodeType.GIT_REPOSITORY,
            "git.almalinux.org/rpms/synthetic",
            {"origin": "git.almalinux.org", "fixture": True},
        )
    )
    g.add_node(
        Node(
            "commit:synthetic:abc123",
            NodeType.GIT_COMMIT,
            "abc123",
            {"branch": "a9", "fixture": True},
        )
    )
    g.add_node(
        Node(
            "cas:source:synthetic:xyz789",
            NodeType.CAS_ATTESTATION,
            "CAS source attestation xyz789",
            _cas_fixture_metadata("source_commit", "xyz789"),
        )
    )
    g.add_node(
        Node(
            "buildenv:alma9:x86_64",
            NodeType.BUILD_ENVIRONMENT,
            "AlmaLinux 9 x86_64 fixture build environment",
            {"distribution": "AlmaLinux", "major_version": "9", "arch": "x86_64"},
        )
    )
    g.add_node(
        Node(
            "build:albs:123456",
            NodeType.BUILD_TASK,
            "ALBS build task 123456",
            {"system": "ALBS", "status": "completed", "fixture": True},
        )
    )
    g.add_node(
        Node(
            "srpm:synthetic:1.0.0-1.el9",
            NodeType.SRPM,
            "synthetic-1.0.0-1.el9.src.rpm",
            {"nevra": "synthetic-1:1.0.0-1.el9.src"},
        )
    )
    g.add_node(
        Node(
            SYNTHETIC_RPM_ID,
            NodeType.BINARY_RPM,
            "synthetic-core-1.0.0-1.el9.x86_64.rpm",
            {
                "name": "synthetic-core",
                "epoch": "1",
                "version": "1.0.0",
                "release": "1.el9",
                "arch": "x86_64",
            },
        )
    )
    g.add_node(
        Node(
            "cas:artifact:synthetic-core:x86_64",
            NodeType.CAS_ATTESTATION,
            "CAS artifact attestation for synthetic-core",
            _cas_fixture_metadata("rpm_artifact", "synthetic-core-x86_64-cas"),
        )
    )
    g.add_node(
        Node(
            "test:synthetic:albs:123456",
            NodeType.TEST_RESULT,
            "ALBS test result for synthetic fixture build 123456",
            {"status": "passed", "fixture": True},
        )
    )
    g.add_node(
        Node(
            "sig:gpg:alma9",
            NodeType.SIGNATURE,
            "AlmaLinux 9 GPG signature",
            {"status": "signed", "fixture": True},
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
            {"type": "security", "fixture": True},
        )
    )
    g.add_node(Node("cve:CVE-2026-0001", NodeType.CVE, "CVE-2026-0001", {"fixture": True}))
    g.add_node(
        Node(
            "sbom:synthetic:cyclonedx",
            NodeType.SBOM,
            "CycloneDX SBOM for synthetic fixture",
            {"format": "CycloneDX", "fixture": True},
        )
    )
    g.add_node(
        Node(
            "external:fixture-runtime",
            NodeType.EXTERNAL_PACKAGE,
            "fixture runtime dependency",
            {"ecosystem": "rpm", "scope": "runtime"},
        )
    )

    g.add_edge("src:synthetic", "repo:git.almalinux.org/rpms/synthetic", Relation.STORED_IN)
    g.add_edge(
        "repo:git.almalinux.org/rpms/synthetic", "commit:synthetic:abc123", Relation.POINTS_TO
    )
    g.add_edge("commit:synthetic:abc123", "cas:source:synthetic:xyz789", Relation.AUTHENTICATED_BY)
    g.add_edge("cas:source:synthetic:xyz789", "build:albs:123456", Relation.BUILT_BY)
    g.add_edge("build:albs:123456", "buildenv:alma9:x86_64", Relation.BUILT_IN)
    g.add_edge("build:albs:123456", "srpm:synthetic:1.0.0-1.el9", Relation.PRODUCES)
    g.add_edge("build:albs:123456", SYNTHETIC_RPM_ID, Relation.PRODUCES)
    g.add_edge(
        SYNTHETIC_RPM_ID,
        "cas:artifact:synthetic-core:x86_64",
        Relation.AUTHENTICATED_BY,
    )
    g.add_edge("build:albs:123456", "test:synthetic:albs:123456", Relation.TESTED_BY)
    g.add_edge(SYNTHETIC_RPM_ID, "sig:gpg:alma9", Relation.SIGNED_AS)
    g.add_edge(SYNTHETIC_RPM_ID, "repo:alma9:baseos:x86_64", Relation.RELEASED_TO)
    g.add_edge(SYNTHETIC_RPM_ID, "errata:ALSA-2026-0001", Relation.FIXES)
    g.add_edge("errata:ALSA-2026-0001", "cve:CVE-2026-0001", Relation.FIXES)
    g.add_edge(SYNTHETIC_RPM_ID, "sbom:synthetic:cyclonedx", Relation.DESCRIBED_BY)
    g.add_edge(SYNTHETIC_RPM_ID, "external:fixture-runtime", Relation.REQUIRES_RUNTIME)

    return g


def build_generic_synthetic_graph(package: str) -> ProvenanceGraph:
    g = ProvenanceGraph()
    g.add_node(Node(f"src:{package}", NodeType.SOURCE_PACKAGE, package, {"ecosystem": "rpm"}))
    g.add_node(
        Node(
            f"repo:git.almalinux.org/rpms/{package}",
            NodeType.GIT_REPOSITORY,
            f"git.almalinux.org/rpms/{package}",
            {"origin": "git.almalinux.org", "fixture": True},
        )
    )
    g.add_node(Node(f"commit:{package}:abc123", NodeType.GIT_COMMIT, "abc123", {"fixture": True}))
    g.add_node(
        Node(
            f"cas:source:{package}:xyz789",
            NodeType.CAS_ATTESTATION,
            "CAS source attestation xyz789",
            _cas_fixture_metadata("source_commit", "xyz789"),
        )
    )
    g.add_node(Node(f"build:albs:{package}:1", NodeType.BUILD_TASK, f"ALBS build for {package}"))
    g.add_node(Node(f"rpm:{package}:x86_64", NodeType.BINARY_RPM, f"{package}.x86_64.rpm"))
    g.add_node(
        Node(
            f"cas:artifact:{package}:x86_64",
            NodeType.CAS_ATTESTATION,
            f"CAS artifact attestation for {package}",
            _cas_fixture_metadata("rpm_artifact", f"{package}-x86_64-cas"),
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


def _cas_fixture_metadata(subject_type: str, cas_hash: str) -> dict[str, object]:
    return {
        "system": "Codenotary CAS",
        "subject_type": subject_type,
        "cas_hash": cas_hash,
        "evidence_present": True,
        "reported_by": "synthetic_fixture",
        "externally_verified": False,
        "fixture": True,
    }
