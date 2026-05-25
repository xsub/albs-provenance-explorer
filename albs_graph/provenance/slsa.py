"""Export a binary RPM's provenance backbone as an in-toto / SLSA statement.

The graph already holds the full backbone (source -> git commit -> build task ->
artifact -> signature). This renders it as an in-toto Statement v1 carrying a
SLSA provenance v1 predicate, the standard interchange format for supply-chain
attestations - so the graph's provenance becomes consumable by SLSA-aware
tooling, not just this CLI.

It reports only what the graph contains (no fabricated fields). The subject
digest uses the artifact CAS hash (a sha256) when present; resolved dependencies
record the git source; and the signature-verification status (if D27 ran) is
surfaced under run metadata.
"""

from __future__ import annotations

from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph, Relation

_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
_BUILDER_ID = "https://build.almalinux.org"
_BUILD_TYPE = "https://build.almalinux.org/albs"


def slsa_provenance(graph: ProvenanceGraph, rpm_node_id: str) -> dict[str, Any]:
    """Build an in-toto Statement v1 with a SLSA provenance v1 predicate."""

    if rpm_node_id not in graph.nodes:
        raise ValueError(f"Unknown RPM node: {rpm_node_id}")
    rpm = graph.nodes[rpm_node_id]
    metadata = rpm.metadata

    subject_digest: dict[str, str] = {}
    sha256 = _artifact_sha256(graph, rpm_node_id)
    if sha256:
        subject_digest["sha256"] = sha256
    subject = [{"name": str(metadata.get("filename") or rpm.label), "digest": subject_digest}]

    git = _git_source(graph, rpm_node_id)
    resolved: list[dict[str, Any]] = []
    if git.get("repo") or git.get("commit"):
        uri = "git+" + str(git.get("repo", ""))
        if git.get("ref"):
            uri += f"@{git['ref']}"
        entry: dict[str, Any] = {"uri": uri}
        if git.get("commit"):
            entry["digest"] = {"gitCommit": git["commit"]}
        resolved.append(entry)

    external: dict[str, Any] = {"package": metadata.get("name")}
    build_id = _build_id(graph, rpm_node_id)
    if build_id:
        external["build_id"] = build_id

    run_metadata: dict[str, Any] = {}
    if build_id:
        run_metadata["invocationId"] = str(build_id)
    if "signature_verified" in metadata:
        run_metadata["signatureVerified"] = bool(metadata["signature_verified"])

    return {
        "_type": _STATEMENT_TYPE,
        "subject": subject,
        "predicateType": _PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": _BUILD_TYPE,
                "externalParameters": {k: v for k, v in external.items() if v is not None},
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": _BUILDER_ID},
                "metadata": run_metadata,
            },
        },
    }


def _artifact_sha256(graph: ProvenanceGraph, rpm_node_id: str) -> str | None:
    direct = graph.nodes[rpm_node_id].metadata.get("cas_hash")
    if direct:
        return str(direct)
    for edge in graph.outgoing(rpm_node_id, Relation.AUTHENTICATED_BY):
        node = graph.nodes[edge.target]
        if node.type == NodeType.CAS_ATTESTATION and node.metadata.get("cas_hash"):
            return str(node.metadata["cas_hash"])
    return None


def _git_source(graph: ProvenanceGraph, rpm_node_id: str) -> dict[str, str]:
    source: dict[str, str] = {}
    for node_id in graph.source_to_artifact_path(rpm_node_id):
        node = graph.nodes[node_id]
        if node.type == NodeType.GIT_REPOSITORY:
            source["repo"] = node.label
        elif node.type == NodeType.GIT_COMMIT:
            source["commit"] = node.label
            ref = node.metadata.get("git_ref")
            if ref:
                source["ref"] = str(ref)
        elif node.type == NodeType.CAS_ATTESTATION:
            for key, meta_key in (("repo", "git_url"), ("commit", "git_commit"), ("ref", "git_ref")):
                value = node.metadata.get(meta_key)
                if value and key not in source:
                    source[key] = str(value)
    return source


def _build_id(graph: ProvenanceGraph, rpm_node_id: str) -> str | None:
    for node_id in graph.source_to_artifact_path(rpm_node_id):
        node = graph.nodes[node_id]
        if node.type == NodeType.BUILD_TASK:
            value = node.metadata.get("albs_build_id") or node.label
            return str(value) if value else None
    return None
