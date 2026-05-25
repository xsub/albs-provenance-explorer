from pathlib import Path

from albs_graph.adapters.pylang import (
    attach_python_imports,
    attach_python_requirements,
    module_to_package,
    parse_imports,
    parse_requirements,
    python_import_claims,
)
from albs_graph.dependency import Ecosystem, ResolutionState
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import coverage_report, reconcile_dependency_claims

_REQUIREMENTS = """
requests==2.31.0
urllib3>=1.26,<3
flask[async]>=2.0
# a comment
-r other-requirements.txt
six ; python_version < "3.8"
git+https://example.com/pkg.git
"""

_SOURCE = """
import os
import requests
from flask import Flask
import numpy as np
from . import local_module
"""

SUBJECT = "rpm:app:x86_64"


def test_parse_requirements_extracts_names_versions_extras() -> None:
    specs = {spec.identity.name: spec for spec in parse_requirements(_REQUIREMENTS)}

    assert set(specs) == {"requests", "urllib3", "flask", "six"}
    assert specs["requests"].identity.version == "2.31.0"
    assert specs["requests"].resolution_state == ResolutionState.LOCKED
    assert specs["urllib3"].identity.version is None
    assert specs["flask"].context.extras == ("async",)
    assert specs["requests"].identity.ecosystem == Ecosystem.PYPI


def test_parse_imports_excludes_stdlib_and_relative() -> None:
    assert parse_imports(_SOURCE) == ["flask", "numpy", "requests"]


def test_module_to_package_maps_known_and_overrides() -> None:
    assert module_to_package("cv2") == "opencv-python"
    assert module_to_package("PIL") == "pillow"
    assert module_to_package("unknownmod") == "unknownmod"  # passthrough
    assert module_to_package("cv2", {"cv2": "custom-cv"}) == "custom-cv"  # override wins


def test_python_import_claims_map_module_to_package() -> None:
    claims = {c.spec.identity.name: c for c in python_import_claims("rpm:app", "import cv2\n")}
    assert "opencv-python" in claims
    assert claims["opencv-python"].spec.raw["module"] == "cv2"


def test_attach_python_imports(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("import cv2\nimport requests\nimport os\n", encoding="utf-8")
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app"}))

    result = attach_python_imports(graph, SUBJECT, path)

    assert result.imports == 2  # cv2, requests (os is stdlib)
    names = {n.metadata["name"] for n in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)}
    assert names == {"opencv-python", "requests"}


def test_attach_requirements_adds_claims_and_raises_resolution(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(_REQUIREMENTS, encoding="utf-8")
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))

    result = attach_python_requirements(graph, SUBJECT, path)
    assert result.claims_added == 4
    assert len(graph.find_by_type(NodeType.DEPENDENCY_CLAIM)) == 4

    reconcile_dependency_claims(graph)
    report = coverage_report(graph)
    # Only the pinned requests==2.31.0 resolves to a concrete version.
    assert report.resolution.total == 4
    assert report.resolution.covered == 1
