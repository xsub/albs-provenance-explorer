from pathlib import Path

from albs_graph.adapters.pylang import (
    attach_python_requirements,
    parse_imports,
    parse_requirements,
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
