from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


@dataclass(frozen=True)
class AlbsBuildMetadata:
    build_id: str
    package: str
    source_repository: str
    commit: str
    source_cas_hash: str | None
    source_rpm: str | None
    binary_rpms: list[str]
    release_repository: str | None
    arch: str | None
    raw: dict[str, Any]


def load_mock_build(path: str | Path) -> ProvenanceGraph:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return graph_from_build_metadata(parse_build_metadata(data))


def fetch_build_metadata(
    build_id: int | str,
    base_url: str = "https://build.almalinux.org",
    progress: Callable[[str], None] | None = None,
) -> AlbsBuildMetadata:
    import requests

    root = base_url.rstrip("/")
    api_url = f"{root}/api/v1/builds/{build_id}/"
    if progress:
        progress(f"Fetching ALBS build metadata from {api_url}")
    api_response = requests.get(api_url, timeout=20)
    if api_response.ok and "application/json" in api_response.headers.get("content-type", ""):
        if progress:
            progress("Parsing ALBS API JSON response")
        return parse_build_metadata(api_response.json())

    url = f"{root}/build/{build_id}"
    if progress:
        progress(f"ALBS API JSON unavailable; fetching HTML fallback from {url}")
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    if progress:
        progress("Parsing ALBS build HTML fallback")
    return parse_build_page(build_id=str(build_id), html=response.text, url=url)


def parse_build_metadata(data: dict[str, Any]) -> AlbsBuildMetadata:
    first_task = _first_task(data)
    first_ref = first_task.get("ref", {}) if first_task else {}
    package = str(
        data.get("package")
        or data.get("name")
        or data.get("source_package")
        or _package_from_repository(str(first_ref.get("url", "")))
    )
    if not package or package == "None":
        raise ValueError("ALBS build metadata is missing package/source_package")
    build_id = str(data.get("build_id") or data.get("id") or f"mock:{package}")
    artifacts = _rpm_artifacts(data)
    return AlbsBuildMetadata(
        build_id=build_id,
        package=package,
        source_repository=str(
            data.get("source_repository")
            or data.get("git_repository")
            or first_ref.get("url")
            or f"git.almalinux.org/rpms/{package}"
        ),
        commit=str(
            data.get("commit")
            or data.get("git_commit")
            or first_ref.get("git_commit_hash")
            or "unknown"
        ),
        source_cas_hash=(
            data.get("source_cas_hash")
            or data.get("alma_commit_cas_hash")
            or (first_task.get("alma_commit_cas_hash") if first_task else None)
        ),
        source_rpm=data.get("source_rpm") or data.get("srpm") or _first_source_rpm(artifacts),
        binary_rpms=[str(item) for item in data.get("binary_rpms", [])]
        or _binary_rpm_names(artifacts),
        release_repository=data.get("release_repository") or _release_label(data),
        arch=data.get("arch") or first_task.get("arch") if first_task else data.get("arch"),
        raw=data,
    )


def parse_build_page(build_id: str, html: str, url: str) -> AlbsBuildMetadata:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text("\n", strip=True)
    title = soup.title.get_text(" ", strip=True) if soup.title else f"ALBS build {build_id}"
    package = _extract_after(text, ("Package", "Source package", "Name")) or title.split()[0]
    commit = _extract_after(text, ("Commit", "Git commit", "Ref")) or "unknown"
    repository = _extract_after(text, ("Repository", "Git repository", "Source repository"))
    binary_rpms = [
        link.get_text(strip=True)
        for link in soup.find_all("a")
        if link.get_text(strip=True).endswith(".rpm")
    ]
    source_rpm = next((rpm for rpm in binary_rpms if rpm.endswith(".src.rpm")), None)
    binaries = [rpm for rpm in binary_rpms if not rpm.endswith(".src.rpm")]
    return AlbsBuildMetadata(
        build_id=build_id,
        package=package,
        source_repository=repository or f"unknown-albs-source:{package}",
        commit=commit,
        source_cas_hash=_extract_after(text, ("Codenotary CAS", "CAS hash", "Source CAS hash")),
        source_rpm=source_rpm,
        binary_rpms=binaries,
        release_repository=_extract_after(text, ("Release repository", "Repository release")),
        arch=_extract_after(text, ("Architecture", "Arch")),
        raw={"source_url": url, "title": title},
    )


def graph_from_build_metadata(build: AlbsBuildMetadata) -> ProvenanceGraph:
    if "tasks" in build.raw:
        return _graph_from_albs_api_build(build)

    graph = ProvenanceGraph()
    package = build.package
    source_id = f"src:{package}"
    repo_id = f"git:{build.source_repository}"
    commit_id = f"commit:{package}:{build.commit}"
    cas_value = build.source_cas_hash
    cas_id = f"cas:source:{package}:{cas_value or build.commit}"
    build_id = f"build:albs:{build.build_id}"

    graph.add_node(Node(source_id, NodeType.SOURCE_PACKAGE, package, {"ecosystem": "rpm"}))
    graph.add_node(
        Node(repo_id, NodeType.GIT_REPOSITORY, build.source_repository, {"system": "ALBS"})
    )
    graph.add_node(Node(commit_id, NodeType.GIT_COMMIT, build.commit, {"package": package}))
    graph.add_node(
        Node(
            cas_id,
            NodeType.CAS_ATTESTATION,
            cas_value or f"unverified source commit {build.commit}",
            {
                "system": "Codenotary CAS",
                "subject_type": "source_commit",
                "cas_hash": cas_value,
                "trusted": build.source_cas_hash is not None,
            },
        )
    )
    graph.add_node(Node(build_id, NodeType.BUILD_TASK, f"ALBS build {build.build_id}", build.raw))

    graph.add_edge(source_id, repo_id, Relation.STORED_IN)
    graph.add_edge(repo_id, commit_id, Relation.POINTS_TO)
    graph.add_edge(commit_id, cas_id, Relation.AUTHENTICATED_BY)
    graph.add_edge(cas_id, build_id, Relation.BUILT_BY)

    if build.arch:
        env_id = f"buildenv:alma:{build.arch}"
        graph.add_node(
            Node(env_id, NodeType.BUILD_ENVIRONMENT, f"ALBS {build.arch}", {"arch": build.arch})
        )
        graph.add_edge(build_id, env_id, Relation.BUILT_IN)

    if build.source_rpm:
        srpm_id = f"srpm:{build.source_rpm}"
        graph.add_node(Node(srpm_id, NodeType.SRPM, build.source_rpm, {"package": package}))
        graph.add_edge(build_id, srpm_id, Relation.PRODUCES)

    for rpm in build.binary_rpms:
        rpm_id = f"rpm:{rpm}"
        graph.add_node(Node(rpm_id, NodeType.BINARY_RPM, rpm, _rpm_metadata_from_filename(rpm)))
        graph.add_edge(build_id, rpm_id, Relation.PRODUCES)
        if build.release_repository:
            release_id = f"repo-release:{build.release_repository}"
            if release_id not in graph.nodes:
                graph.add_node(
                    Node(
                        release_id,
                        NodeType.REPOSITORY_RELEASE,
                        build.release_repository,
                        {"source": "ALBS"},
                    )
                )
            graph.add_edge(rpm_id, release_id, Relation.RELEASED_TO)

    return graph


def _graph_from_albs_api_build(build: AlbsBuildMetadata) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    source_id = f"src:{build.package}"
    repo_id = f"git:{build.source_repository}"
    commit_id = f"commit:{build.package}:{build.commit}"
    source_cas_value = build.source_cas_hash
    source_cas_id = f"cas:source:{build.package}:{source_cas_value or build.commit}"
    build_id = f"build:albs:{build.build_id}"

    graph.add_node(Node(source_id, NodeType.SOURCE_PACKAGE, build.package, {"ecosystem": "rpm"}))
    graph.add_node(
        Node(repo_id, NodeType.GIT_REPOSITORY, build.source_repository, {"system": "ALBS"})
    )
    graph.add_node(Node(commit_id, NodeType.GIT_COMMIT, build.commit, {"package": build.package}))
    graph.add_node(
        Node(
            source_cas_id,
            NodeType.CAS_ATTESTATION,
            source_cas_value or f"unverified source commit {build.commit}",
            {
                "system": "Codenotary CAS",
                "subject_type": "source_commit",
                "cas_hash": source_cas_value,
                "trusted": build.source_cas_hash is not None,
            },
        )
    )
    graph.add_node(
        Node(
            build_id,
            NodeType.BUILD_TASK,
            f"ALBS build {build.build_id}",
            {
                "created_at": build.raw.get("created_at"),
                "finished_at": build.raw.get("finished_at"),
                "released": build.raw.get("released"),
                "release_id": build.raw.get("release_id"),
            },
        )
    )
    graph.add_edge(source_id, repo_id, Relation.STORED_IN)
    graph.add_edge(repo_id, commit_id, Relation.POINTS_TO)
    graph.add_edge(commit_id, source_cas_id, Relation.AUTHENTICATED_BY)
    graph.add_edge(source_cas_id, build_id, Relation.BUILT_BY)

    release_id = _release_label(build.raw)
    if release_id:
        graph.add_node(
            Node(
                f"repo-release:{release_id}",
                NodeType.REPOSITORY_RELEASE,
                release_id,
                {"source": "ALBS"},
            )
        )

    signature_nodes = _add_signature_nodes(graph, build.raw)
    for task in build.raw.get("tasks", []):
        task_id = f"build:albs-task:{task['id']}"
        arch = str(task.get("arch") or "unknown")
        platform = task.get("platform") or {}
        ref = task.get("ref") or {}
        task_cas = task.get("alma_commit_cas_hash") or build.source_cas_hash
        task_cas_id = f"cas:source:{build.package}:{task_cas or build.commit}"
        if task_cas_id not in graph.nodes:
            graph.add_node(
                Node(
                    task_cas_id,
                    NodeType.CAS_ATTESTATION,
                    str(task_cas or f"unverified source commit {build.commit}"),
                    {
                        "system": "Codenotary CAS",
                        "subject_type": "source_commit",
                        "cas_hash": task_cas,
                        "trusted": bool(task.get("is_cas_authenticated")),
                        "git_commit": ref.get("git_commit_hash"),
                        "git_ref": ref.get("git_ref"),
                        "git_url": ref.get("url"),
                    },
                )
            )
            graph.add_edge(commit_id, task_cas_id, Relation.AUTHENTICATED_BY)

        graph.add_node(
            Node(
                task_id,
                NodeType.BUILD_TASK,
                f"ALBS task {task['id']} {arch}",
                {
                    "albs_build_id": build.build_id,
                    "arch": arch,
                    "status": task.get("status"),
                    "started_at": task.get("started_at"),
                    "finished_at": task.get("finished_at"),
                    "git_ref": ref.get("git_ref"),
                    "platform": platform.get("name"),
                    "secure_boot": task.get("is_secure_boot"),
                },
            )
        )
        graph.add_edge(task_cas_id, task_id, Relation.BUILT_BY)
        graph.add_edge(build_id, task_id, Relation.DERIVED_FROM, role="albs_build_task")

        env_id = f"buildenv:{platform.get('name', 'albs')}:{arch}"
        if env_id not in graph.nodes:
            graph.add_node(
                Node(
                    env_id,
                    NodeType.BUILD_ENVIRONMENT,
                    f"{platform.get('name', 'ALBS')} {arch}",
                    {"platform": platform, "arch": arch},
                )
            )
        graph.add_edge(task_id, env_id, Relation.BUILT_IN)

        for artifact in task.get("artifacts", []):
            if artifact.get("type") != "rpm":
                continue
            name = str(artifact.get("name"))
            node_type = NodeType.SRPM if name.endswith(".src.rpm") else NodeType.BINARY_RPM
            node_id = (
                f"{'srpm' if node_type == NodeType.SRPM else 'rpm'}:{artifact.get('id')}:{name}"
            )
            graph.add_node(
                Node(
                    node_id,
                    node_type,
                    name,
                    _rpm_metadata_from_filename(name)
                    | {
                        "artifact_id": artifact.get("id"),
                        "href": artifact.get("href"),
                        "cas_hash": artifact.get("cas_hash"),
                        "task_id": task.get("id"),
                    },
                )
            )
            graph.add_edge(task_id, node_id, Relation.PRODUCES)
            artifact_cas_hash = artifact.get("cas_hash")
            if artifact_cas_hash:
                cas_subject = "srpm_artifact" if node_type == NodeType.SRPM else "rpm_artifact"
                artifact_cas_id = f"cas:artifact:{artifact_cas_hash}"
                if artifact_cas_id not in graph.nodes:
                    graph.add_node(
                        Node(
                            artifact_cas_id,
                            NodeType.CAS_ATTESTATION,
                            str(artifact_cas_hash),
                            {
                                "system": "Codenotary CAS",
                                "subject_type": cas_subject,
                                "cas_hash": artifact_cas_hash,
                                "trusted": True,
                                "artifact_id": artifact.get("id"),
                                "artifact_name": name,
                                "href": artifact.get("href"),
                            },
                        )
                    )
                graph.add_edge(node_id, artifact_cas_id, Relation.AUTHENTICATED_BY)
            if node_type == NodeType.BINARY_RPM and release_id:
                graph.add_edge(node_id, f"repo-release:{release_id}", Relation.RELEASED_TO)
            if node_type == NodeType.BINARY_RPM:
                for signature_id in signature_nodes:
                    graph.add_edge(node_id, signature_id, Relation.SIGNED_AS)

        for test_task in task.get("test_tasks", []):
            test_id = f"test:{test_task.get('id')}"
            graph.add_node(
                Node(
                    test_id,
                    NodeType.TEST_RESULT,
                    f"ALBS test task {test_task.get('id')}",
                    {"status": test_task.get("status"), "revision": test_task.get("revision")},
                )
            )
            graph.add_edge(task_id, test_id, Relation.TESTED_BY)

    return graph


def _extract_after(text: str, labels: tuple[str, ...]) -> str | None:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        for label in labels:
            normalized = label.lower().rstrip(":")
            if line.lower().rstrip(":") == normalized and index + 1 < len(lines):
                return lines[index + 1]
            prefix = f"{normalized}:"
            if line.lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
    return None


def _first_task(data: dict[str, Any]) -> dict[str, Any]:
    tasks = data.get("tasks")
    if isinstance(tasks, list) and tasks and isinstance(tasks[0], dict):
        return tasks[0]
    return {}


def _rpm_artifacts(data: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for task in data.get("tasks", []):
        for artifact in task.get("artifacts", []):
            if artifact.get("type") == "rpm":
                artifacts.append(artifact)
    return artifacts


def _first_source_rpm(artifacts: list[dict[str, Any]]) -> str | None:
    for artifact in artifacts:
        name = str(artifact.get("name", ""))
        if name.endswith(".src.rpm"):
            return name
    return None


def _binary_rpm_names(artifacts: list[dict[str, Any]]) -> list[str]:
    return [
        str(artifact.get("name"))
        for artifact in artifacts
        if not str(artifact.get("name", "")).endswith(".src.rpm")
    ]


def _package_from_repository(repository_url: str) -> str | None:
    if not repository_url:
        return None
    path = urlparse(repository_url).path.rstrip("/")
    if not path:
        return None
    return Path(path).name.removesuffix(".git") or None


def _release_label(data: dict[str, Any]) -> str | None:
    if data.get("release_repository"):
        return str(data["release_repository"])
    if data.get("release_id"):
        return f"ALBS release {data['release_id']}"
    if data.get("released"):
        return "released"
    return None


def _add_signature_nodes(graph: ProvenanceGraph, data: dict[str, Any]) -> list[str]:
    signature_ids: list[str] = []
    for sign_task in data.get("sign_tasks", []):
        signature_id = f"sig:albs:{sign_task.get('id')}"
        graph.add_node(
            Node(
                signature_id,
                NodeType.SIGNATURE,
                f"ALBS sign task {sign_task.get('id')}",
                {
                    "status": sign_task.get("status"),
                    "started_at": sign_task.get("started_at"),
                    "finished_at": sign_task.get("finished_at"),
                    "stats": sign_task.get("stats"),
                },
            )
        )
        signature_ids.append(signature_id)
    return signature_ids


def _rpm_metadata_from_filename(filename: str) -> dict[str, Any]:
    stem = filename.removesuffix(".rpm")
    parts = stem.rsplit(".", 1)
    arch = parts[1] if len(parts) == 2 else None
    nevra = parts[0] if len(parts) == 2 else stem
    name_version_release = nevra.rsplit("-", 2)
    metadata: dict[str, Any] = {"filename": filename, "arch": arch}
    if len(name_version_release) == 3:
        metadata |= {
            "name": name_version_release[0],
            "version": name_version_release[1],
            "release": name_version_release[2],
        }
    return metadata
