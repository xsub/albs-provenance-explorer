from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse
from typing import Any, Callable

from albs_graph.dependency import Ecosystem, PackageIdentity
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.security import cpe_security_identity


@dataclass(frozen=True)
class AlbsBuildMetadata:
    build_id: str
    package: str
    package_source: str
    source_repository: str
    commit: str
    source_cas_hash: str | None
    source_rpm: str | None
    binary_rpms: list[str]
    release_repository: str | None
    arch: str | None
    raw: dict[str, Any]


def load_synthetic_build_fixture(path: str | Path) -> ProvenanceGraph:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return graph_from_build_metadata(parse_build_metadata(data))


def fetch_build_metadata(
    build_id: int | str,
    base_url: str = "https://build.almalinux.org",
    progress: Callable[[str], None] | None = None,
    cache_path: str | Path | None = None,
    refresh_cache: bool = False,
    cache_ttl_seconds: int = 300,
) -> AlbsBuildMetadata:
    import requests

    cache = Path(cache_path) if cache_path else None
    if cache and cache.exists() and not refresh_cache:
        cache_age = time.time() - cache.stat().st_mtime
        if cache_age <= cache_ttl_seconds:
            if progress:
                progress(f"Loading ALBS build metadata from fresh cache {cache}")
            return parse_build_metadata(json.loads(cache.read_text(encoding="utf-8")))
        if progress:
            progress(
                f"Ignoring stale ALBS metadata cache {cache} "
                f"({cache_age:.0f}s old, ttl {cache_ttl_seconds}s)"
            )

    root = base_url.rstrip("/")
    api_url = f"{root}/api/v1/builds/{build_id}/"
    if progress:
        progress(f"Fetching ALBS build metadata from {api_url}")
    api_response = requests.get(api_url, timeout=20)
    if api_response.ok and "application/json" in api_response.headers.get("content-type", ""):
        data = api_response.json()
        if cache:
            if progress:
                progress(f"Writing ALBS build metadata cache to {cache}")
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if progress:
            progress("Parsing ALBS API JSON response")
        return parse_build_metadata(data)

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
    artifacts = _rpm_artifacts(data)
    package_name = _package_from_build_metadata(data, artifacts, first_task)
    package = package_name.value
    if not package:
        raise ValueError("ALBS build metadata is missing package/source_package")
    build_id = str(data.get("build_id") or data.get("id") or f"fixture:{package}")
    return AlbsBuildMetadata(
        build_id=build_id,
        package=package,
        package_source=package_name.source,
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
        package_source="html",
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

    graph.add_node(
        Node(
            source_id,
            NodeType.SOURCE_PACKAGE,
            package,
            {"ecosystem": "rpm", "albs_package_source": build.package_source},
        )
    )
    graph.add_node(
        Node(repo_id, NodeType.GIT_REPOSITORY, build.source_repository, {"system": "ALBS"})
    )
    graph.add_node(Node(commit_id, NodeType.GIT_COMMIT, build.commit, {"package": package}))
    graph.add_node(
        Node(
            cas_id,
            NodeType.CAS_ATTESTATION,
            cas_value or f"unverified source commit {build.commit}",
            _cas_evidence_metadata("source_commit", cas_value),
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
        srpm_metadata = _rpm_artifact_metadata(
            build.source_rpm,
            node_type=NodeType.SRPM,
            distro=None,
            package=package,
        )
        graph.add_node(Node(srpm_id, NodeType.SRPM, build.source_rpm, srpm_metadata))
        graph.add_edge(build_id, srpm_id, Relation.PRODUCES)

    for rpm in build.binary_rpms:
        rpm_id = f"rpm:{rpm}"
        graph.add_node(
            Node(
                rpm_id,
                NodeType.BINARY_RPM,
                rpm,
                _rpm_artifact_metadata(rpm, node_type=NodeType.BINARY_RPM, distro=None),
            )
        )
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

    graph.add_node(
        Node(
            source_id,
            NodeType.SOURCE_PACKAGE,
            build.package,
            {"ecosystem": "rpm", "albs_package_source": build.package_source},
        )
    )
    graph.add_node(
        Node(repo_id, NodeType.GIT_REPOSITORY, build.source_repository, {"system": "ALBS"})
    )
    graph.add_node(Node(commit_id, NodeType.GIT_COMMIT, build.commit, {"package": build.package}))
    graph.add_node(
        Node(
            source_cas_id,
            NodeType.CAS_ATTESTATION,
            source_cas_value or f"unverified source commit {build.commit}",
            _cas_evidence_metadata("source_commit", source_cas_value),
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
        platform_name = str(platform.get("name") or "")
        distro = _distro_from_platform(platform_name)
        task_cas = task.get("alma_commit_cas_hash") or build.source_cas_hash
        task_cas_id = f"cas:source:{build.package}:{task_cas or build.commit}"
        task_cas_metadata = _cas_evidence_metadata(
            "source_commit",
            task_cas,
            build_id=build.build_id,
            source_type="git",
            albs_authenticated=task.get("is_cas_authenticated"),
            alma_commit_sbom_hash=task_cas,
            git_commit=ref.get("git_commit_hash"),
            git_ref=ref.get("git_ref"),
            git_url=ref.get("url"),
            sbom_api_ver=_sbom_api_version(build.raw),
        )
        if task_cas_id not in graph.nodes:
            graph.add_node(
                Node(
                    task_cas_id,
                    NodeType.CAS_ATTESTATION,
                    str(task_cas or f"unverified source commit {build.commit}"),
                    task_cas_metadata,
                )
            )
            graph.add_edge(commit_id, task_cas_id, Relation.AUTHENTICATED_BY)
        else:
            _merge_node_metadata(graph, task_cas_id, task_cas_metadata)

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

        srpm_name = _task_srpm_name(task)
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
                    _rpm_artifact_metadata(
                        name,
                        node_type=node_type,
                        distro=distro,
                        package=build.package,
                        artifact=artifact,
                        task=task,
                        source_rpm=srpm_name,
                    )
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
                            _cas_evidence_metadata(
                                cas_subject,
                                artifact_cas_hash,
                                build_id=build.build_id,
                                source_type="git",
                                alma_commit_sbom_hash=task_cas,
                                git_url=ref.get("url"),
                                git_ref=ref.get("git_ref"),
                                git_commit=ref.get("git_commit_hash"),
                                build_arch=arch,
                                artifact_id=artifact.get("id"),
                                artifact_name=name,
                                href=artifact.get("href"),
                                purl=_rpm_artifact_purl(
                                    _rpm_metadata_from_filename(name),
                                    distro=distro,
                                    node_type=node_type,
                                ),
                                **_rpm_header_cas_attrs(
                                    name,
                                    source_rpm=srpm_name,
                                ),
                                build_host=task.get("build_host"),
                                built_by=_build_owner(build.raw),
                                sbom_api_ver=_sbom_api_version(build.raw),
                            ),
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


@dataclass(frozen=True)
class _PackageName:
    value: str
    source: str


def _package_from_build_metadata(
    data: dict[str, Any],
    artifacts: list[dict[str, Any]],
    first_task: dict[str, Any],
) -> _PackageName:
    first_ref = first_task.get("ref", {}) if first_task else {}
    explicit_sources: tuple[tuple[str, dict[str, Any], tuple[str, ...]], ...] = (
        (
            "build_metadata",
            data,
            ("package", "package_name", "source_package", "source_package_name"),
        ),
        (
            "task_metadata",
            first_task,
            ("package", "package_name", "source_package", "source_package_name"),
        ),
        (
            "ref_metadata",
            first_ref,
            ("package", "package_name", "source_package", "source_package_name"),
        ),
    )
    for source, scope, keys in explicit_sources:
        for key in keys:
            value = _non_empty_string(scope.get(key))
            if value:
                return _PackageName(value, f"{source}.{key}")

    source_rpm = _first_source_rpm(artifacts)
    if source_rpm:
        source_name = _source_name_from_rpm_filename(source_rpm)
        if source_name:
            return _PackageName(source_name, "srpm_artifact")

    git_ref = _non_empty_string(first_ref.get("git_ref")) or _non_empty_string(data.get("git_ref"))
    if git_ref:
        source_name = _source_name_from_git_ref(git_ref)
        if source_name:
            return _PackageName(source_name, "git_ref")

    repository_name = _package_from_repository(
        str(
            data.get("source_repository")
            or data.get("git_repository")
            or first_ref.get("url")
            or ""
        )
    )
    if repository_name:
        return _PackageName(repository_name, "git_repository_url_fallback")

    return _PackageName("", "missing")


def _non_empty_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "None":
        return None
    return text


def _source_name_from_rpm_filename(filename: str) -> str | None:
    metadata = _rpm_metadata_from_filename(filename)
    return _non_empty_string(metadata.get("name"))


def _source_name_from_git_ref(git_ref: str) -> str | None:
    ref_name = Path(git_ref).name
    parts = ref_name.rsplit("-", 2)
    if len(parts) != 3:
        return None
    return _non_empty_string(parts[0])


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


def _cas_evidence_metadata(
    subject_type: str,
    cas_hash: Any,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "system": "Codenotary CAS",
        "subject_type": subject_type,
        "cas_hash": cas_hash,
        "evidence_present": cas_hash is not None,
        "reported_by": "ALBS",
        "externally_verified": False,
    } | {key: value for key, value in extra.items() if value is not None}


def _merge_node_metadata(
    graph: ProvenanceGraph,
    node_id: str,
    metadata: dict[str, Any],
) -> None:
    graph.nodes[node_id].metadata.update(
        {key: value for key, value in metadata.items() if value is not None}
    )


def _rpm_artifact_metadata(
    filename: str,
    *,
    node_type: NodeType,
    distro: str | None,
    package: str | None = None,
    artifact: dict[str, Any] | None = None,
    task: dict[str, Any] | None = None,
    source_rpm: str | None = None,
) -> dict[str, Any]:
    metadata = _rpm_metadata_from_filename(filename)
    if package and not metadata.get("name"):
        metadata["name"] = package
    identity = _rpm_package_identity(metadata, distro=distro, node_type=node_type)
    purl = identity.purl
    security_identity = cpe_security_identity(
        _metadata_text(metadata.get("name")),
        _metadata_text(metadata.get("version")),
        purl=purl,
    )
    data = metadata | {
        "purl": purl,
        "identity": identity.to_dict(),
        "security_identity": security_identity,
    }
    if artifact:
        data["artifact_id"] = artifact.get("id")
        data["href"] = artifact.get("href")
        data["cas_hash"] = artifact.get("cas_hash")
    if task:
        data["task_id"] = task.get("id")
        data["build_arch"] = task.get("arch")
    if source_rpm:
        data["sourcerpm"] = source_rpm
    return data


def _rpm_artifact_purl(
    metadata: dict[str, Any],
    *,
    distro: str | None,
    node_type: NodeType,
) -> str:
    name = _metadata_text(metadata.get("name")) or "unknown"
    version = _rpm_purl_version(metadata)
    qualifiers = _rpm_purl_qualifiers(metadata, distro=distro)
    if node_type == NodeType.SRPM:
        qualifiers["arch"] = "src"
    encoded_name = quote(name, safe="")
    encoded_version = quote(version, safe="") if version else ""
    purl = f"pkg:rpm/almalinux/{encoded_name}"
    if encoded_version:
        purl += f"@{encoded_version}"
    if qualifiers:
        purl += f"?{urlencode(sorted(qualifiers.items()))}"
    return purl


def _rpm_package_identity(
    metadata: dict[str, Any],
    *,
    distro: str | None,
    node_type: NodeType,
) -> PackageIdentity:
    name = _metadata_text(metadata.get("name")) or "unknown"
    qualifiers = _rpm_purl_qualifiers(metadata, distro=distro)
    if node_type == NodeType.SRPM:
        qualifiers["arch"] = "src"
    return PackageIdentity(
        Ecosystem.RPM,
        name,
        namespace="almalinux",
        version=_rpm_purl_version(metadata),
        purl=_rpm_artifact_purl(metadata, distro=distro, node_type=node_type),
        qualifiers=qualifiers,
    )


def _rpm_purl_version(metadata: dict[str, Any]) -> str | None:
    version = _metadata_text(metadata.get("version"))
    release = _metadata_text(metadata.get("release"))
    if version and release:
        return f"{version}-{release}"
    return version or release


def _rpm_purl_qualifiers(metadata: dict[str, Any], *, distro: str | None) -> dict[str, str]:
    qualifiers: dict[str, str] = {}
    arch = _metadata_text(metadata.get("arch"))
    if arch:
        qualifiers["arch"] = arch
    epoch = _metadata_text(metadata.get("epoch"))
    if epoch:
        qualifiers["epoch"] = epoch
    if distro:
        qualifiers["distro"] = distro
    return qualifiers


def _rpm_header_cas_attrs(filename: str, *, source_rpm: str | None) -> dict[str, Any]:
    metadata = _rpm_metadata_from_filename(filename)
    return {
        "name": metadata.get("name"),
        "epoch": metadata.get("epoch"),
        "version": metadata.get("version"),
        "release": metadata.get("release"),
        "arch": metadata.get("arch"),
        "sourcerpm": source_rpm,
    }


def _task_srpm_name(task: dict[str, Any]) -> str | None:
    for artifact in task.get("artifacts", []):
        name = str(artifact.get("name", ""))
        if artifact.get("type") == "rpm" and name.endswith(".src.rpm"):
            return name
    return None


def _distro_from_platform(platform_name: str) -> str | None:
    if not platform_name:
        return None
    normalized = platform_name.strip().lower().replace("_", "-").replace(" ", "-")
    if normalized.startswith("almalinux-"):
        return normalized
    if normalized.startswith("alma-"):
        return f"almalinux-{normalized.removeprefix('alma-')}"
    return normalized


def _sbom_api_version(data: dict[str, Any]) -> str:
    return str(data.get("sbom_api_ver") or data.get("sbom_api_version") or "0.1")


def _build_owner(data: dict[str, Any]) -> str | None:
    owner = data.get("owner")
    if not isinstance(owner, dict):
        return None
    username = _metadata_text(owner.get("username"))
    email = _metadata_text(owner.get("email"))
    if username and email:
        return f"{username} <{email}>"
    return username or email


def _metadata_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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
