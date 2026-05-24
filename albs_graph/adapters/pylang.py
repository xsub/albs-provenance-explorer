"""Python language dependencies: requirements.txt and import scanning.

The graph is not RPM-only — application dependencies declared in language
ecosystems are first-class evidence too. This adapter turns Python
``requirements.txt`` lines and top-level ``import`` statements into PyPI
dependency claims that reconcile alongside RPM/SBOM/dnf claims.

It records *evidence*, not resolution: a pinned ``==`` requirement is a LOCKED
claim with a version; a range or bare name is DECLARED; an ``import foo`` is a
DECLARED claim with no version (module name, which is not always the package
name). Running a real pip/uv resolve is rung 5 for PyPI and out of scope here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from albs_graph.dependency import (
    DependencyContext,
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import ProvenanceGraph
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;#]*?)\s*(?:;\s*(.*))?$")
_PIN = re.compile(r"==\s*([^,\s]+)")
_IMPORT = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)")
# stdlib-ish names we never treat as external dependencies
_STDLIB = frozenset(
    {
        "os", "sys", "re", "json", "typing", "dataclasses", "pathlib", "collections",
        "subprocess", "io", "abc", "enum", "functools", "itertools", "math", "time",
        "datetime", "logging", "argparse", "unittest", "asyncio", "__future__",
    }
)


@dataclass(frozen=True)
class PythonDepsResult:
    requirements: int
    imports: int
    claims_added: int

    def to_dict(self) -> dict[str, int]:
        return {
            "requirements": self.requirements,
            "imports": self.imports,
            "claims_added": self.claims_added,
        }


def parse_requirements(text: str) -> list[DependencySpec]:
    """Parse requirements.txt lines into PyPI dependency specs."""

    specs: list[DependencySpec] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        if line.startswith(("git+", "http://", "https://", "file:")):
            continue
        match = _REQ.match(line)
        if not match:
            continue
        name = match.group(1)
        extras = match.group(2)
        specifier = (match.group(3) or "").strip()
        marker = (match.group(4) or "").strip()
        pin = _PIN.search(specifier)
        version = pin.group(1) if pin else None
        state = ResolutionState.LOCKED if version else ResolutionState.DECLARED
        extras_tuple = (
            tuple(part.strip() for part in extras.strip("[]").split(",") if part.strip())
            if extras
            else ()
        )
        specs.append(
            DependencySpec(
                identity=PackageIdentity(Ecosystem.PYPI, name, version=version),
                requested=line,
                scope=DependencyScope.RUNTIME,
                resolution_state=state,
                context=DependencyContext(extras=extras_tuple),
                source="requirements.txt",
                raw={"line": line, "specifier": specifier or None, "marker": marker or None},
            )
        )
    return specs


def parse_imports(text: str) -> list[str]:
    """Best-effort: top-level imported module names (excluding the stdlib subset)."""

    modules: set[str] = set()
    for line in text.splitlines():
        match = _IMPORT.match(line)
        if match:
            module = match.group(1)
            if module not in _STDLIB:
                modules.add(module)
    return sorted(modules)


def python_requirement_claims(subject_id: str, text: str) -> list[DependencyClaim]:
    return [
        DependencyClaim(subject_id, spec, evidence="requirements.txt")
        for spec in parse_requirements(text)
    ]


def python_import_claims(subject_id: str, text: str) -> list[DependencyClaim]:
    claims: list[DependencyClaim] = []
    for module in parse_imports(text):
        spec = DependencySpec(
            identity=PackageIdentity(Ecosystem.PYPI, module),
            scope=DependencyScope.RUNTIME,
            resolution_state=ResolutionState.DECLARED,
            source="python_import",
            raw={"module": module},
        )
        claims.append(DependencyClaim(subject_id, spec, evidence="python_import"))
    return claims


def attach_python_requirements(
    graph: ProvenanceGraph, subject_id: str, path: str | Path
) -> PythonDepsResult:
    """Attach requirements.txt dependency claims to a subject node."""

    text = Path(path).read_text(encoding="utf-8")
    claims = python_requirement_claims(subject_id, text)
    for claim in claims:
        add_dependency_claim(graph, claim)
    return PythonDepsResult(requirements=len(claims), imports=0, claims_added=len(claims))
