from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Iterable

from albs_graph.adapters.albs import AlbsBuildMetadata
from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    dependency_edge_metadata,
    dependency_node_metadata,
    dependency_spec_node_id,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


class SourceCheckoutError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceEvidenceSummary:
    source_tree_id: str
    files: int
    manifests: int
    spec_files: int
    dependency_specs: int
    source_refs: int
    patch_refs: int
    ecosystems: tuple[str, ...]


_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
}

_MANIFESTS: dict[str, tuple[Ecosystem, str, ResolutionState]] = {
    "package.json": (Ecosystem.NPM, "manifest", ResolutionState.DECLARED),
    "package-lock.json": (Ecosystem.NPM, "lockfile", ResolutionState.LOCKED),
    "npm-shrinkwrap.json": (Ecosystem.NPM, "lockfile", ResolutionState.LOCKED),
    "Cargo.toml": (Ecosystem.CARGO, "manifest", ResolutionState.DECLARED),
    "Cargo.lock": (Ecosystem.CARGO, "lockfile", ResolutionState.LOCKED),
    "go.mod": (Ecosystem.GO, "manifest", ResolutionState.DECLARED),
    "go.sum": (Ecosystem.GO, "lockfile", ResolutionState.LOCKED),
    "pyproject.toml": (Ecosystem.PYPI, "manifest", ResolutionState.DECLARED),
    "poetry.lock": (Ecosystem.PYPI, "lockfile", ResolutionState.LOCKED),
    "requirements.txt": (Ecosystem.PYPI, "manifest", ResolutionState.DECLARED),
    "pom.xml": (Ecosystem.MAVEN, "manifest", ResolutionState.DECLARED),
    "build.gradle": (Ecosystem.GRADLE, "manifest", ResolutionState.DECLARED),
    "build.gradle.kts": (Ecosystem.GRADLE, "manifest", ResolutionState.DECLARED),
}

_SPEC_DEPENDENCY_RE = re.compile(
    r"^(?P<field>BuildRequires|Requires)\s*:\s*(?P<value>.+)$",
    re.IGNORECASE,
)
_SPEC_SOURCE_RE = re.compile(r"^(?P<field>Source|Patch)\d*\s*:\s*(?P<value>.+)$", re.IGNORECASE)


def checkout_git_source(
    build: AlbsBuildMetadata,
    destination: str | Path,
    *,
    refresh: bool = False,
) -> Path:
    dest = Path(destination)
    if dest.exists() and refresh:
        raise SourceCheckoutError(
            f"Refusing to delete existing source checkout {dest}; remove it manually first"
        )
    dest.mkdir(parents=True, exist_ok=True)

    _run_git(["init", "-q"], dest)
    if not (dest / ".git").exists():
        raise SourceCheckoutError(f"git init did not create a repository in {dest}")
    remotes = _run_git(["remote"], dest).stdout.splitlines()
    if "origin" not in remotes:
        _run_git(["remote", "add", "origin", build.source_repository], dest)
    else:
        _run_git(["remote", "set-url", "origin", build.source_repository], dest)
    _run_git(["fetch", "--depth=1", "origin", build.commit], dest)
    _run_git(["checkout", "--detach", "--force", build.commit], dest)
    return dest


def attach_source_evidence(
    graph: ProvenanceGraph,
    build: AlbsBuildMetadata,
    source_dir: str | Path,
    *,
    include_file_inventory: bool = True,
) -> SourceEvidenceSummary:
    root = Path(source_dir)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(root)

    source_tree_id = _source_tree_id(build)
    graph.add_node(
        Node(
            source_tree_id,
            NodeType.SOURCE_TREE,
            f"{build.package} source tree",
            {
                "path": str(root),
                "package": build.package,
                "build_id": build.build_id,
                "git_repository": build.source_repository,
                "git_commit": build.commit,
                "evidence_level": "source_tree_inventory",
            },
        )
    )
    source_package_id = f"src:{build.package}"
    if source_package_id in graph.nodes:
        graph.add_edge(source_package_id, source_tree_id, Relation.DESCRIBED_BY)

    files = 0
    manifests = 0
    spec_files = 0
    dependency_specs = 0
    source_refs = 0
    patch_refs = 0
    ecosystems: set[str] = set()

    for path in _iter_source_files(root):
        relative = path.relative_to(root).as_posix()
        file_kind = _file_kind(path)
        file_id = _source_file_id(build, relative)
        if include_file_inventory or file_kind in {"spec", "manifest"}:
            graph.add_node(
                Node(
                    file_id,
                    NodeType.SOURCE_MANIFEST if file_kind == "manifest" else NodeType.SOURCE_FILE,
                    relative,
                    _file_metadata(path, root) | {"kind": file_kind},
                )
            )
            graph.add_edge(source_tree_id, file_id, Relation.CONTAINS)
            files += 1

        if file_kind == "manifest":
            manifests += 1
            ecosystem, manifest_kind, state = _MANIFESTS[path.name]
            ecosystems.add(str(ecosystem))
            _annotate_manifest_node(graph, file_id, ecosystem, manifest_kind, state)
        if file_kind == "spec":
            spec_files += 1
            specs = _parse_spec_file(path, root)
            for spec in specs.dependencies:
                dependency_specs += 1
                _add_dependency_spec(graph, file_id, spec)
            source_refs += len(specs.sources)
            patch_refs += len(specs.patches)
            for ref in specs.sources:
                _add_spec_reference(graph, file_id, build, ref, "source")
            for ref in specs.patches:
                _add_spec_reference(graph, file_id, build, ref, "patch")

    _merge_source_tree_summary(
        graph,
        source_tree_id,
        files=files,
        manifests=manifests,
        spec_files=spec_files,
        dependency_specs=dependency_specs,
        source_refs=source_refs,
        patch_refs=patch_refs,
        ecosystems=ecosystems,
    )
    return SourceEvidenceSummary(
        source_tree_id=source_tree_id,
        files=files,
        manifests=manifests,
        spec_files=spec_files,
        dependency_specs=dependency_specs,
        source_refs=source_refs,
        patch_refs=patch_refs,
        ecosystems=tuple(sorted(ecosystems)),
    )


@dataclass(frozen=True)
class _SpecFacts:
    dependencies: tuple[DependencySpec, ...]
    sources: tuple[str, ...]
    patches: tuple[str, ...]


def _parse_spec_file(path: Path, root: Path) -> _SpecFacts:
    dependencies: list[DependencySpec] = []
    sources: list[str] = []
    patches: list[str] = []
    relative = path.relative_to(root).as_posix()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        dependency_match = _SPEC_DEPENDENCY_RE.match(line)
        if dependency_match:
            field = dependency_match.group("field").lower()
            value = dependency_match.group("value").strip()
            scope = (
                DependencyScope.BUILDTIME
                if field == "buildrequires"
                else DependencyScope.RUNTIME
            )
            for expression in _split_spec_dependency_expression(value):
                dependencies.append(
                    DependencySpec(
                        identity=PackageIdentity(Ecosystem.RPM, _rpm_requirement_name(expression)),
                        requested=expression,
                        scope=scope,
                        resolution_state=ResolutionState.DECLARED,
                        source=f"{relative}:{line_number}",
                        raw={"line": raw_line, "field": dependency_match.group("field")},
                    )
                )
            continue
        source_match = _SPEC_SOURCE_RE.match(line)
        if source_match:
            field = source_match.group("field").lower()
            value = source_match.group("value").strip()
            if field.startswith("source"):
                sources.append(value)
            else:
                patches.append(value)
    return _SpecFacts(tuple(dependencies), tuple(sources), tuple(patches))


def _split_spec_dependency_expression(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _rpm_requirement_name(expression: str) -> str:
    normalized = expression.split(maxsplit=1)[0]
    return normalized.strip()


def _add_dependency_spec(graph: ProvenanceGraph, source_file_id: str, spec: DependencySpec) -> None:
    node_id = dependency_spec_node_id(spec)
    graph.add_node(
        Node(
            node_id,
            NodeType.DEPENDENCY_SPEC,
            spec.requested or spec.identity.name,
            dependency_node_metadata(spec) | {"kind": "source_spec_requirement"},
        )
    )
    edge_metadata = dependency_edge_metadata(spec)
    graph.add_edge(source_file_id, node_id, Relation.DECLARES_DEPENDENCY, **edge_metadata)
    if spec.scope == DependencyScope.BUILDTIME:
        graph.add_edge(source_file_id, node_id, Relation.REQUIRES_BUILDTIME, **edge_metadata)
    elif spec.scope == DependencyScope.RUNTIME:
        graph.add_edge(source_file_id, node_id, Relation.REQUIRES_RUNTIME, **edge_metadata)


def _add_spec_reference(
    graph: ProvenanceGraph,
    spec_file_id: str,
    build: AlbsBuildMetadata,
    value: str,
    kind: str,
) -> None:
    reference_id = f"source-ref:{_safe_id(build.build_id)}:{kind}:{_safe_id(value)}"
    graph.add_node(
        Node(
            reference_id,
            NodeType.SOURCE_FILE,
            value,
            {"kind": f"spec_{kind}", "reference": value, "package": build.package},
        )
    )
    graph.add_edge(spec_file_id, reference_id, Relation.REFERENCES, kind=kind)


def _annotate_manifest_node(
    graph: ProvenanceGraph,
    file_id: str,
    ecosystem: Ecosystem,
    manifest_kind: str,
    state: ResolutionState,
) -> None:
    graph.update_metadata(
        file_id,
        {
            "ecosystem": str(ecosystem),
            "manifest_kind": manifest_kind,
            "resolution_state": str(state),
            "dependency_evidence": "manifest_detected",
        },
    )


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def _file_kind(path: Path) -> str:
    if path.name in _MANIFESTS:
        return "manifest"
    if path.suffix == ".spec":
        return "spec"
    return "source"


def _file_metadata(path: Path, root: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "suffix": path.suffix,
    }


def _merge_source_tree_summary(
    graph: ProvenanceGraph,
    source_tree_id: str,
    *,
    files: int,
    manifests: int,
    spec_files: int,
    dependency_specs: int,
    source_refs: int,
    patch_refs: int,
    ecosystems: set[str],
) -> None:
    graph.update_metadata(
        source_tree_id,
        {
            "files": files,
            "manifests": manifests,
            "spec_files": spec_files,
            "dependency_specs": dependency_specs,
            "source_refs": source_refs,
            "patch_refs": patch_refs,
            "ecosystems_detected": sorted(ecosystems),
        },
    )


def _source_tree_id(build: AlbsBuildMetadata) -> str:
    return f"source-tree:{_safe_id(build.build_id)}:{_safe_id(build.package)}:{_safe_id(build.commit)}"


def _source_file_id(build: AlbsBuildMetadata, relative_path: str) -> str:
    return f"source-file:{_safe_id(build.build_id)}:{_safe_id(relative_path)}"


def _safe_id(value: object) -> str:
    return str(value).replace("/", "_").replace(" ", "_").replace(":", "_")


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise SourceCheckoutError("git command not found; install git to checkout ALBS source") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SourceCheckoutError(detail or f"git {' '.join(args)} failed")
    return result
