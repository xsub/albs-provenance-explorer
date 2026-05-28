from pathlib import Path

from albs_graph.adapters.source_imports import (
    EXTRACTORS,
    Language,
    ScanSummary,
    attach_source_tree_imports,
    detect_language,
    iter_source_files,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph


def test_detect_language_by_extension_covers_each_language() -> None:
    cases = {
        Path("a.py"): Language.PYTHON,
        Path("a.go"): Language.GO,
        Path("a.rs"): Language.RUST,
        Path("a.c"): Language.C,
        Path("a.h"): Language.C,
        Path("a.cpp"): Language.CPP,
        Path("a.hpp"): Language.CPP,
        Path("a.js"): Language.JAVASCRIPT,
        Path("a.tsx"): Language.TYPESCRIPT,
        Path("a.java"): Language.JAVA,
        Path("a.rb"): Language.RUBY,
        Path("README.md"): None,  # not a source language
    }
    for path, expected in cases.items():
        assert detect_language(path) == expected, path


def test_detect_language_falls_back_to_shebang(tmp_path: Path) -> None:
    # Extensionless scripts: the interpreter on the shebang line picks the language.
    py = tmp_path / "tool"
    py.write_bytes(b"#!/usr/bin/env python3\nprint('hi')\n")
    rb = tmp_path / "rakefile_runner"
    rb.write_bytes(b"#!/usr/bin/env ruby\nputs 'hi'\n")
    none = tmp_path / "plain"
    none.write_bytes(b"just a plain text file\n")

    assert detect_language(py) == Language.PYTHON
    assert detect_language(rb) == Language.RUBY
    assert detect_language(none) is None


def test_python_extractor_filters_stdlib() -> None:
    text = "import os\nimport requests\nfrom flask import Flask\nimport sys\n"
    assert EXTRACTORS[Language.PYTHON](text) == ["flask", "requests"]


def test_go_extractor_handles_block_and_filters_stdlib() -> None:
    text = (
        'package main\n'
        'import "fmt"\n'                                   # stdlib -> filtered
        'import "github.com/pkg/errors"\n'                 # external
        'import (\n'
        '\t"os"\n'                                         # stdlib -> filtered
        '\t"golang.org/x/sync/errgroup"\n'                 # external
        ')\n'
    )
    assert EXTRACTORS[Language.GO](text) == [
        "github.com/pkg/errors",
        "golang.org/x/sync/errgroup",
    ]


def test_rust_extractor_filters_stdlib_and_path_keywords() -> None:
    text = (
        "use std::collections::HashMap;\n"   # stdlib -> filtered
        "use serde::{Serialize, Deserialize};\n"
        "pub use tokio::runtime::Builder;\n"
        "use self::inner::Thing;\n"          # path keyword -> filtered
        "extern crate libc;\n"
    )
    assert EXTRACTORS[Language.RUST](text) == ["libc", "serde", "tokio"]


def test_c_include_extractor_keeps_system_and_local() -> None:
    # System (<...>) and local ("...") #includes both record as evidence; the
    # extractor tolerates internal whitespace (`# include`). A plain code line
    # without a #include directive must not match.
    text = (
        '#include <stdio.h>\n'
        '#include "myheader.h"\n'
        '#  include <openssl/ssl.h>\n'
        'int main(void) { return 0; }\n'
    )
    assert EXTRACTORS[Language.C](text) == ["myheader.h", "openssl/ssl.h", "stdio.h"]


def test_javascript_extractor_npm_root_skips_relatives_scoped_and_node_stdlib() -> None:
    # Node built-ins (fs, path, crypto, fs/promises) are the runtime's stdlib,
    # not npm packages -- previously they came through as fake npm deps. Plus
    # the existing handling: relative paths skipped; @scope/pkg/sub -> @scope/pkg;
    # require() mid-line picked up; dynamic import() not matched.
    text = (
        'import React from "react";\n'              # bare -> root "react"
        'import { x } from "@scope/pkg/sub";\n'     # scoped -> "@scope/pkg"
        'import "./local";\n'                       # relative -> skipped
        'const fs = require("fs");\n'               # Node stdlib -> filtered
        'const crypto = require("crypto");\n'       # Node stdlib -> filtered
        'import { readFile } from "fs/promises";\n' # Node stdlib submodule -> filtered
        'const u = require("./util");\n'            # relative -> skipped
        'import("lodash/get");\n'                   # dynamic import -- no match (not ES static)
    )
    assert EXTRACTORS[Language.JAVASCRIPT](text) == ["@scope/pkg", "react"]


def test_java_extractor_filters_stdlib_prefixes_and_wildcards() -> None:
    text = (
        "package com.example;\n"
        "import java.util.List;\n"                       # stdlib -> filtered
        "import javax.servlet.http.HttpServlet;\n"       # stdlib -> filtered
        "import com.google.common.collect.ImmutableList;\n"
        "import org.apache.commons.lang3.StringUtils;\n"
        "import static org.junit.Assert.*;\n"            # static + .* wildcard
    )
    assert EXTRACTORS[Language.JAVA](text) == [
        "com.google.common.collect.ImmutableList",
        "org.apache.commons.lang3.StringUtils",
        "org.junit.Assert",
    ]


def test_ruby_extractor_excludes_require_relative_and_stdlib() -> None:
    text = (
        "require 'rails'\n"
        "require 'json'\n"                # stdlib -> filtered
        "require_relative 'helper'\n"     # project-internal -> excluded
        "require 'sidekiq/web'\n"
    )
    assert EXTRACTORS[Language.RUBY](text) == ["rails", "sidekiq/web"]


def test_iter_source_files_prunes_ignored_dirs(tmp_path: Path) -> None:
    # A real-shaped tree: source under src/, vendored deps under node_modules/,
    # git metadata under .git/. Only the source/ file should be yielded.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import requests\n")
    (tmp_path / "node_modules" / "react").mkdir(parents=True)
    (tmp_path / "node_modules" / "react" / "index.js").write_text('require("dep")\n')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("# ignored\n")

    found = {p.name for p in iter_source_files(tmp_path)}
    assert found == {"app.py"}  # vendored + vcs pruned


def test_attach_source_tree_imports_emits_typed_claims(tmp_path: Path) -> None:
    # A mixed tree exercises Python+Go+Rust together, proving each language's
    # imports become claims with the correct ecosystem.
    (tmp_path / "main.py").write_text("import requests\nimport os\n")
    (tmp_path / "cmd.go").write_text('import "github.com/pkg/errors"\n')
    (tmp_path / "lib.rs").write_text("use serde::Serialize;\n")

    graph = ProvenanceGraph()
    graph.add_node(Node("src:demo", NodeType.SOURCE_PACKAGE, "demo", {"name": "demo"}))

    summary = attach_source_tree_imports(graph, "src:demo", tmp_path)

    assert isinstance(summary, ScanSummary)
    assert summary.files_scanned == 3
    assert summary.distinct_imports == 3
    assert summary.claims_added == 3

    claims = graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    by_eco = {c.metadata.get("ecosystem"): c.metadata.get("name") for c in claims}
    assert by_eco == {"pypi": "requests", "go": "github.com/pkg/errors", "cargo": "serde"}


def test_attach_source_tree_imports_is_noop_for_unknown_subject(tmp_path: Path) -> None:
    # A missing subject must not raise -- the scan still walks (so the summary
    # reflects what was seen) but no claims are added to the graph.
    (tmp_path / "a.py").write_text("import requests\n")
    graph = ProvenanceGraph()

    summary = attach_source_tree_imports(graph, "src:nope", tmp_path)

    assert summary.files_scanned == 1
    assert summary.distinct_imports == 1
    assert summary.claims_added == 0
    assert graph.find_by_type(NodeType.DEPENDENCY_CLAIM) == []


def test_claims_tag_coordinate_kind_so_java_class_paths_are_not_maven_artifacts(
    tmp_path: Path,
) -> None:
    # Each extracted name's *shape* rides on the claim's raw under
    # `coordinate_kind`, so downstream consumers (CVE matcher, resolver) cannot
    # mistake a Java class path for a Maven groupId:artifactId or a C #include
    # path for a system-package name. Package-ecosystem languages keep their
    # natural kind too.
    (tmp_path / "main.py").write_text("import requests\n")
    (tmp_path / "App.java").write_text(
        "package com.example;\n"
        "import com.google.common.collect.ImmutableList;\n"
    )
    (tmp_path / "main.c").write_text('#include <openssl/ssl.h>\n')
    (tmp_path / "app.js").write_text('import x from "react";\n')

    graph = ProvenanceGraph()
    graph.add_node(Node("src:demo", NodeType.SOURCE_PACKAGE, "demo", {"name": "demo"}))

    attach_source_tree_imports(graph, "src:demo", tmp_path)

    raw_by_lang = {
        node.metadata.get("dependency", {}).get("raw", {}).get("language"): node.metadata.get(
            "dependency", {}
        ).get("raw", {}).get("coordinate_kind")
        for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    }
    assert raw_by_lang["java"] == "class_path", "Java import is a class path, not a Maven coord"
    assert raw_by_lang["c"] == "header_path", "C #include is a header path, not a system package"
    assert raw_by_lang["python"] == "module"
    assert raw_by_lang["javascript"] == "npm_package"
