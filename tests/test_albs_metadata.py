from __future__ import annotations

from albs_graph.adapters.albs import graph_from_build_metadata, parse_build_metadata


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
