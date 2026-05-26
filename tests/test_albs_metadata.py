from __future__ import annotations

from albs_graph.adapters.albs import graph_from_build_metadata, parse_build_metadata
from albs_graph.model import NodeType, Relation


def test_multi_source_build_attributes_each_binary_to_its_own_source() -> None:
    # A batch build with two source packages: each binary must trace to ITS own
    # source, not a single build-level package (regression: nginx-core -> nghttp2).
    metadata = parse_build_metadata(
        {
            "id": 99,
            "tasks": [
                {
                    "id": 1,
                    "arch": "x86_64",
                    "ref": {"url": "https://git.almalinux.org/rpms/nginx.git", "git_commit_hash": "aaa"},
                    "artifacts": [
                        {"id": 10, "type": "rpm", "name": "nginx-1.26.3-6.el10.src.rpm"},
                        {"id": 11, "type": "rpm", "name": "nginx-core-1.26.3-6.el10.x86_64.rpm"},
                    ],
                },
                {
                    "id": 2,
                    "arch": "x86_64",
                    "ref": {"url": "https://git.almalinux.org/rpms/nghttp2.git", "git_commit_hash": "bbb"},
                    "artifacts": [
                        {"id": 20, "type": "rpm", "name": "nghttp2-1.68.0-3.el10.src.rpm"},
                        {"id": 21, "type": "rpm", "name": "libnghttp2-1.68.0-3.el10.x86_64.rpm"},
                    ],
                },
            ],
        }
    )
    graph = graph_from_build_metadata(metadata)

    def source_of(label_substr: str) -> str:
        rpm = next(
            n for n in graph.find_by_type(NodeType.BINARY_RPM) if label_substr in n.label
        )
        path = graph.source_to_artifact_path(rpm.id)
        return graph.nodes[path[0]].label  # path[0] is the source_package node

    assert source_of("nginx-core") == "nginx"
    assert source_of("libnghttp2") == "nghttp2"
    assert "src:nginx" in graph.nodes
    assert "src:nghttp2" in graph.nodes


def test_shared_repo_across_sources_still_gets_each_stored_in_edge() -> None:
    # Two source packages sharing one git repo: the second source must still get
    # its STORED_IN edge even though the repo node already exists. Edges are
    # ensured independently of node creation (add_edge does not dedup).
    repo = "https://git.almalinux.org/rpms/shared.git"
    metadata = parse_build_metadata(
        {
            "id": 77,
            "tasks": [
                {
                    "id": 1,
                    "arch": "x86_64",
                    "ref": {"url": repo, "git_commit_hash": "aaa"},
                    "artifacts": [
                        {"id": 10, "type": "rpm", "name": "pkga-1.0-1.el10.src.rpm"},
                        {"id": 11, "type": "rpm", "name": "pkga-1.0-1.el10.x86_64.rpm"},
                    ],
                },
                {
                    "id": 2,
                    "arch": "x86_64",
                    "ref": {"url": repo, "git_commit_hash": "bbb"},
                    "artifacts": [
                        {"id": 20, "type": "rpm", "name": "pkgb-1.0-1.el10.src.rpm"},
                        {"id": 21, "type": "rpm", "name": "pkgb-1.0-1.el10.x86_64.rpm"},
                    ],
                },
            ],
        }
    )
    graph = graph_from_build_metadata(metadata)
    repo_id = f"git:{repo}"

    def stored_in(src_id: str) -> int:
        return sum(
            1
            for edge in graph.outgoing(src_id)
            if edge.target == repo_id and edge.relation == Relation.STORED_IN
        )

    assert "src:pkgb" in graph.nodes
    assert stored_in("src:pkgb") == 1  # previously missing (node already existed)
    assert stored_in("src:pkga") == 1  # not duplicated by build-level + per-task


def test_parse_build_metadata_extracts_package_from_srpm_artifact() -> None:
    metadata = parse_build_metadata(
        {
            "id": 42,
            "tasks": [
                {
                    "id": 1001,
                    "arch": "x86_64",
                    "ref": {
                        "url": "https://git.almalinux.org/rpms/not-authoritative.git",
                        "git_commit_hash": "abc123",
                    },
                    "artifacts": [
                        {
                            "id": 1,
                            "type": "rpm",
                            "name": "bash-5.1.8-9.el9.src.rpm",
                        }
                    ],
                }
            ],
        }
    )

    graph = graph_from_build_metadata(metadata)

    assert metadata.package == "bash"
    assert metadata.package_source == "srpm_artifact"
    assert "src:bash" in graph.nodes
    assert graph.nodes["src:bash"].metadata["albs_package_source"] == "srpm_artifact"
    assert "src:not-authoritative" not in graph.nodes


def test_parse_build_metadata_extracts_package_from_git_ref_before_repository_url() -> None:
    metadata = parse_build_metadata(
        {
            "id": 43,
            "tasks": [
                {
                    "ref": {
                        "url": "https://git.almalinux.org/rpms/not-authoritative.git",
                        "git_ref": "imports/c9/systemd-252-32.el9",
                        "git_commit_hash": "def456",
                    },
                    "artifacts": [],
                }
            ],
        }
    )

    assert metadata.package == "systemd"
    assert metadata.package_source == "git_ref"


def test_albs_api_rpm_artifacts_include_purl_cpe_and_cas_identity_metadata() -> None:
    metadata = parse_build_metadata(
        {
            "id": 100,
            "owner": {"username": "builder", "email": "builder@example.test"},
            "tasks": [
                {
                    "id": 200,
                    "arch": "x86_64",
                    "is_cas_authenticated": True,
                    "alma_commit_cas_hash": "sourcecas",
                    "platform": {"name": "AlmaLinux-9"},
                    "ref": {
                        "url": "https://git.almalinux.org/rpms/bash.git",
                        "git_ref": "imports/c9/bash-5.1.8-9.el9",
                        "git_commit_hash": "abc123",
                    },
                    "artifacts": [
                        {
                            "id": 1,
                            "type": "rpm",
                            "name": "bash-5.1.8-9.el9.src.rpm",
                            "cas_hash": "srpmcas",
                            "href": "/srpm",
                        },
                        {
                            "id": 2,
                            "type": "rpm",
                            "name": "bash-5.1.8-9.el9.x86_64.rpm",
                            "cas_hash": "rpmcas",
                            "href": "/rpm",
                        },
                    ],
                }
            ],
        }
    )

    graph = graph_from_build_metadata(metadata)

    srpm = graph.nodes["srpm:1:bash-5.1.8-9.el9.src.rpm"]
    rpm = graph.nodes["rpm:2:bash-5.1.8-9.el9.x86_64.rpm"]
    artifact_cas = graph.nodes["cas:artifact:rpmcas"]

    assert srpm.metadata["purl"] == (
        "pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=src&distro=almalinux-9"
    )
    assert rpm.metadata["purl"] == (
        "pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9"
    )
    assert rpm.metadata["identity"]["ecosystem"] == "rpm"
    assert rpm.metadata["identity"]["namespace"] == "almalinux"
    assert rpm.metadata["identity"]["qualifiers"] == {
        "arch": "x86_64",
        "distro": "almalinux-9",
    }
    assert rpm.metadata["security_identity"]["purl"] == rpm.metadata["purl"]
    assert rpm.metadata["security_identity"]["cpe"] is None
    assert rpm.metadata["security_identity"]["cpe_status"] == "candidate_only"
    assert rpm.metadata["security_identity"]["cpe_candidates"][0]["verified"] is False

    assert artifact_cas.metadata["build_id"] == "100"
    assert artifact_cas.metadata["source_type"] == "git"
    assert artifact_cas.metadata["alma_commit_sbom_hash"] == "sourcecas"
    assert artifact_cas.metadata["git_url"] == "https://git.almalinux.org/rpms/bash.git"
    assert artifact_cas.metadata["git_ref"] == "imports/c9/bash-5.1.8-9.el9"
    assert artifact_cas.metadata["git_commit"] == "abc123"
    assert artifact_cas.metadata["build_arch"] == "x86_64"
    assert artifact_cas.metadata["name"] == "bash"
    assert artifact_cas.metadata["version"] == "5.1.8"
    assert artifact_cas.metadata["release"] == "9.el9"
    assert artifact_cas.metadata["arch"] == "x86_64"
    assert artifact_cas.metadata["sourcerpm"] == "bash-5.1.8-9.el9.src.rpm"
    assert artifact_cas.metadata["purl"] == rpm.metadata["purl"]
    assert artifact_cas.metadata["built_by"] == "builder <builder@example.test>"
    assert artifact_cas.metadata["sbom_api_ver"] == "0.1"
