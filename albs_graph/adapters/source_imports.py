"""Source-tree import/include scanning across languages.

Walks a checked-out source tree, detects each file's language by extension
(with a shebang fallback), parses its imports/includes with a per-language
regex extractor, and emits :class:`DependencyClaim` evidence into the graph.

This is the "source -> declared deps" rung that sits between
:mod:`albs_graph.adapters.source` (which finds the ``.spec`` and the manifest
*files*: ``go.mod``, ``Cargo.toml``, ``package.json``, ...) and the future
resolver layer (which would actually invoke ``go list`` / ``cargo metadata`` /
etc.). It records *what the source code itself says it depends on*, in the form
of import/include statements -- no resolver run, no package-manager call. The
reconciler then groups these declared claims alongside resolved/observed claims
from other adapters.

Stdlib modules are filtered per language so the claims are external-dependency
shaped, not stdlib noise; project-internal references (relative JS imports,
Ruby ``require_relative``, ``self::``/``super::``/``crate::`` in Rust) are
similarly excluded. C/C++ ``#include`` directives are recorded as
``Ecosystem.GENERIC`` evidence (the C ecosystem has no single package manager).

Regex-based by design: fast, dependency-free, lossless for the common cases
(top-level statements at column zero). It deliberately does not chase nested
conditional imports or dynamic ``__import__`` -- the reconciler is fed real
evidence, not best-guess static analysis.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Iterator

from albs_graph.adapters.pylang import parse_imports as _extract_python
from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import ProvenanceGraph
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim


class Language(StrEnum):
    """Languages the scanner can detect + extract imports from."""

    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    RUBY = "ruby"


# File extension -> language. Lowercased before lookup. Headers (.h/.hpp/...)
# count as their respective C/C++ even without a .c/.cpp counterpart: a header
# can carry its own #includes worth recording.
_EXTENSIONS: dict[str, Language] = {
    ".py": Language.PYTHON, ".pyi": Language.PYTHON,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".c": Language.C, ".h": Language.C,
    ".cc": Language.CPP, ".cpp": Language.CPP, ".cxx": Language.CPP, ".c++": Language.CPP,
    ".hpp": Language.CPP, ".hh": Language.CPP, ".hxx": Language.CPP, ".h++": Language.CPP,
    ".js": Language.JAVASCRIPT, ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".rb": Language.RUBY,
}

# Interpreter (from #! shebang) -> language. For extensionless scripts.
_SHEBANG_LANGUAGES: dict[str, Language] = {
    "python": Language.PYTHON, "python2": Language.PYTHON, "python3": Language.PYTHON,
    "node": Language.JAVASCRIPT, "nodejs": Language.JAVASCRIPT,
    "ruby": Language.RUBY,
}

# Directories never worth scanning (vendored, build, vcs caches, language artifacts).
# Pruned in-place during the walk so we never descend into them.
IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "vendor", "target", "build", "BUILD", "BUILDROOT", "rpmbuild",
    "dist", "out", "bin", "obj",
    "__pycache__", ".tox", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env",
})


def detect_language(path: Path, *, head: bytes | None = None) -> Language | None:
    """Detect a source file's language by extension, with a shebang fallback."""

    ext = path.suffix.lower()
    if ext in _EXTENSIONS:
        return _EXTENSIONS[ext]
    # Extensionless script: peek at the first line for a shebang.
    if head is None:
        try:
            with path.open("rb") as fh:
                head = fh.read(128)
        except OSError:
            return None
    if head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0].decode("utf-8", "replace")
        for interp, lang in _SHEBANG_LANGUAGES.items():
            if interp in line:
                return lang
    return None


# Per-language regexes. Each matches a top-level import/include and captures the
# imported entity; anchored at line start so a `//` comment cannot match.

# Go imports: a bare `import "pkg"` or any quoted path inside an `import ( ... )`
# block. The block form is handled in the extractor (multi-line stateful).
_GO_IMPORT = re.compile(r'^\s*import\s+"([^"]+)"')
_GO_QUOTED = re.compile(r'"([^"]+)"')

# Rust: `use crate::...` / `pub use ...` and the older `extern crate name;`.
_RUST_USE = re.compile(r"^\s*(?:pub\s+)?use\s+([A-Za-z_][\w:]*)")
_RUST_EXTERN = re.compile(r"^\s*extern\s+crate\s+([A-Za-z_][\w]*)")

# C / C++: any `#include <foo.h>` or `#include "foo.h"`. Both are recorded.
_C_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

# JavaScript / TypeScript: ES module `import ... from "pkg"` (with optional
# binding list) and bare `import "pkg"`. The mandatory `\s+` after `import`
# excludes the dynamic `import("...")` call form (which has `(` right after).
# CommonJS `require("pkg")` can appear mid-line; the others are line-anchored.
_JS_IMPORT = re.compile(r"""^\s*import\s+(?:[^"'(]+?\s+from\s+)?["']([^"']+)["']""")
_JS_REQUIRE = re.compile(r"""\brequire\(\s*["']([^"']+)["']\s*\)""")

# Java: `import [static] foo.bar.Baz;` (the trailing `.*` wildcard is stripped).
_JAVA = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*?)(?:\.\*)?\s*;")

# Ruby: only `require '...'` -- `require_relative` is project-internal and the
# `\s+` after `require` naturally excludes it (no space between `require` and `_`).
_RUBY = re.compile(r"""^\s*require\s+['"]([^'"]+)['"]""")


# Stdlib filters per language. Conservative -- if unsure, we leave the name in
# (better to over-report than silently drop a real dep).

_GO_STDLIB = frozenset({
    "fmt", "os", "io", "strings", "strconv", "time", "math", "bytes", "sort", "sync",
    "errors", "context", "encoding", "encoding/json", "encoding/base64", "encoding/hex",
    "net", "net/http", "net/url", "path", "path/filepath", "reflect", "regexp", "runtime",
    "log", "bufio", "crypto", "crypto/sha256", "crypto/sha1", "crypto/md5", "crypto/rand",
    "hash", "unicode", "testing", "flag", "syscall", "io/ioutil", "os/exec", "os/signal",
})

# Rust stdlib roots + the special path keywords that aren't external crates.
_RUST_STDLIB = frozenset({"std", "core", "alloc", "self", "super", "crate"})

# Java stdlib prefixes: a name starting with any of these is JDK-internal.
_JAVA_STDLIB_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.")

# Ruby stdlib (the common ones); not exhaustive, but covers what scripts pull.
_RUBY_STDLIB = frozenset({
    "json", "yaml", "csv", "date", "time", "fileutils", "pathname", "stringio", "logger",
    "uri", "net/http", "net/https", "openssl", "digest", "base64", "tempfile", "tmpdir",
    "set", "ostruct", "optparse", "etc", "io/console", "shellwords",
})


def _is_go_stdlib(pkg: str) -> bool:
    """Go stdlib heuristic: first path segment carries no dot (external = host/path)."""

    if pkg in _GO_STDLIB:
        return True
    first = pkg.split("/", 1)[0]
    return "." not in first


# --- per-language extractors ---


def _extract_go(text: str) -> list[str]:
    out: set[str] = set()
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("import (") or stripped == "import (":
            in_block = True
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            match = _GO_QUOTED.search(stripped)
            if match and not _is_go_stdlib(match.group(1)):
                out.add(match.group(1))
            continue
        match = _GO_IMPORT.match(line)
        if match and not _is_go_stdlib(match.group(1)):
            out.add(match.group(1))
    return sorted(out)


def _extract_rust(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        for pattern in (_RUST_USE, _RUST_EXTERN):
            match = pattern.match(line)
            if match:
                crate = match.group(1).split("::", 1)[0]
                if crate not in _RUST_STDLIB:
                    out.add(crate)
    return sorted(out)


def _extract_c(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        match = _C_INCLUDE.match(line)
        if match:
            out.add(match.group(1))
    return sorted(out)


# C++ shares the C #include syntax.
_extract_cpp = _extract_c


def _npm_root(specifier: str) -> str:
    """Reduce an npm import specifier to its package root (handles ``@scope/pkg``)."""

    if specifier.startswith("@"):
        parts = specifier.split("/", 2)
        return "/".join(parts[:2]) if len(parts) >= 2 else specifier
    return specifier.split("/", 1)[0]


# Node.js built-in modules: `require("fs")` / `import "fs"` is the runtime's own
# stdlib, not an npm package. They are filtered so downstream consumers cannot
# mistake them for missing or vulnerable npm dependencies. The list is the
# canonical set (Node 20+); `fs/promises`-style submodules collapse to their
# root via _npm_root, so the root-only set is sufficient.
_NODE_STDLIB = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "test", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
})


def _maybe_add_npm(out: set[str], specifier: str) -> None:
    """Filter then add: skip relative/absolute paths (project-internal) and
    Node stdlib (`fs` / `path` / `crypto` / ... are the runtime, not deps)."""

    if specifier.startswith((".", "/")):
        return
    root = _npm_root(specifier)
    if root not in _NODE_STDLIB:
        out.add(root)


def _extract_javascript(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        match = _JS_IMPORT.match(line)
        if match:
            _maybe_add_npm(out, match.group(1))
            continue
        for match in _JS_REQUIRE.finditer(line):
            _maybe_add_npm(out, match.group(1))
    return sorted(out)


# TypeScript shares JS import/require shapes.
_extract_typescript = _extract_javascript


def _extract_java(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        match = _JAVA.match(line)
        if not match:
            continue
        name = match.group(1)
        if not any(name.startswith(prefix) for prefix in _JAVA_STDLIB_PREFIXES):
            out.add(name)
    return sorted(out)


def _extract_ruby(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        match = _RUBY.match(line)
        if match:
            name = match.group(1)
            if name not in _RUBY_STDLIB and not name.startswith("."):
                out.add(name)
    return sorted(out)


EXTRACTORS: dict[Language, Callable[[str], list[str]]] = {
    Language.PYTHON: _extract_python,
    Language.GO: _extract_go,
    Language.RUST: _extract_rust,
    Language.C: _extract_c,
    Language.CPP: _extract_cpp,
    Language.JAVASCRIPT: _extract_javascript,
    Language.TYPESCRIPT: _extract_typescript,
    Language.JAVA: _extract_java,
    Language.RUBY: _extract_ruby,
}

# Language -> dependency ecosystem the imports map into. C/C++ have no single
# package ecosystem (autoconf/pkg-config/CMake/Conan/vcpkg/...), so #includes are
# recorded as GENERIC evidence. Ruby falls into GENERIC too (no RubyGems entry
# in the Ecosystem enum yet); the import name is preserved verbatim either way.
_ECOSYSTEM_FOR: dict[Language, Ecosystem] = {
    Language.PYTHON: Ecosystem.PYPI,
    Language.GO: Ecosystem.GO,
    Language.RUST: Ecosystem.CARGO,
    Language.JAVASCRIPT: Ecosystem.NPM,
    Language.TYPESCRIPT: Ecosystem.NPM,
    Language.JAVA: Ecosystem.MAVEN,
    Language.RUBY: Ecosystem.GENERIC,
    Language.C: Ecosystem.GENERIC,
    Language.CPP: Ecosystem.GENERIC,
}

# What *shape* of identifier the extractor recovered for each language. This
# rides on each claim's ``raw`` so a downstream consumer cannot mistake a Java
# class path (`com.google.common.collect.ImmutableList`) for a Maven artifact
# coordinate (`com.google.guava:guava`), or a C `#include` path
# (`openssl/ssl.h`) for a system package name. The other languages' extracted
# names *are* package coordinates in their ecosystem and are tagged accordingly.
_COORDINATE_KIND: dict[Language, str] = {
    Language.PYTHON: "module",        # mapped to PyPI via module_to_package
    Language.GO: "module_path",       # also the canonical Go import path
    Language.RUST: "crate",
    Language.JAVASCRIPT: "npm_package",
    Language.TYPESCRIPT: "npm_package",
    Language.RUBY: "require_name",    # best-effort; may not match gem name
    Language.JAVA: "class_path",      # NOT a Maven groupId:artifactId
    Language.C: "header_path",        # `#include` path; not a package
    Language.CPP: "header_path",
}


@dataclass(frozen=True)
class ScanSummary:
    files_scanned: int
    files_by_language: dict[str, int]
    claims_added: int
    distinct_imports: int

    def to_dict(self) -> dict[str, object]:
        return {
            "files_scanned": self.files_scanned,
            "files_by_language": self.files_by_language,
            "claims_added": self.claims_added,
            "distinct_imports": self.distinct_imports,
        }


def iter_source_files(root: Path) -> Iterator[Path]:
    """Walk ``root`` yielding files whose language we can detect (IGNORE_DIRS pruned)."""

    root = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune in-place: never descend into ignored / hidden dirs.
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            if detect_language(path) is not None:
                yield path


def attach_source_tree_imports(
    graph: ProvenanceGraph,
    subject_id: str,
    root: Path | str,
    *,
    file_limit: int = 5000,
) -> ScanSummary:
    """Scan a source tree, emit one :class:`DependencyClaim` per (language, import).

    A given import is recorded once per language (not per file), so the
    reconciler does not multiply-count a module imported in every test. The
    subject is typically the source-package node (``src:<name>``) -- the thing
    being analyzed -- which the reconciler then groups alongside other claims
    on that subject.
    """

    root = Path(root)
    files_by_language: Counter[Language] = Counter()
    imports_by_language: dict[Language, set[str]] = {}
    files_scanned = 0
    for path in iter_source_files(root):
        if files_scanned >= file_limit:
            break
        language = detect_language(path)
        if language is None:
            continue  # defensive: iter_source_files already filtered
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        files_by_language[language] += 1
        for module in EXTRACTORS[language](text):
            imports_by_language.setdefault(language, set()).add(module)

    claims_added = 0
    if subject_id in graph.nodes:
        for language, modules in imports_by_language.items():
            ecosystem = _ECOSYSTEM_FOR[language]
            evidence = f"{language}_import"
            coordinate_kind = _COORDINATE_KIND.get(language, "module")
            for module in sorted(modules):
                spec = DependencySpec(
                    identity=PackageIdentity(ecosystem, module),
                    scope=DependencyScope.RUNTIME,
                    resolution_state=ResolutionState.DECLARED,
                    source=evidence,
                    # coordinate_kind tells consumers what shape ``module`` is
                    # in. Critically: a Java entry is a class_path (e.g.
                    # `com.google.common.collect.ImmutableList`) NOT a Maven
                    # groupId:artifactId, and a C/C++ entry is a header_path
                    # (`openssl/ssl.h`) NOT a system package -- so a CVE matcher
                    # or resolver must not treat them as artifact coordinates.
                    raw={
                        "module": module,
                        "language": str(language),
                        "coordinate_kind": coordinate_kind,
                    },
                )
                add_dependency_claim(
                    graph, DependencyClaim(subject_id, spec, evidence=evidence)
                )
                claims_added += 1

    return ScanSummary(
        files_scanned=files_scanned,
        files_by_language={str(k): v for k, v in files_by_language.items()},
        claims_added=claims_added,
        distinct_imports=sum(len(v) for v in imports_by_language.values()),
    )
