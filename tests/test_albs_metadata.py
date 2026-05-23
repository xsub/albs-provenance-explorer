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
