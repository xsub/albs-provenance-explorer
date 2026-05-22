from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    SOURCE_PACKAGE = "source_package"
    GIT_REPOSITORY = "git_repository"
    GIT_COMMIT = "git_commit"
    CAS_ATTESTATION = "cas_attestation"
    BUILD_TASK = "build_task"
    BUILD_ENVIRONMENT = "build_environment"
    SRPM = "srpm"
    BINARY_RPM = "binary_rpm"
    SIGNATURE = "signature"
    REPOSITORY_RELEASE = "repository_release"
    ERRATA = "errata"
    CVE = "cve"
    SBOM = "sbom"
    TEST_RESULT = "test_result"
    EXTERNAL_PACKAGE = "external_package"


@dataclass(frozen=True)
class Node:
    id: str
    type: NodeType | str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": str(self.type),
            "label": self.label,
            "metadata": self.metadata,
        }
