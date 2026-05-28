from __future__ import annotations

from pathlib import Path

from albs_graph.gui.entry import build_parser, default_source_path


def test_default_workbench_source_exists() -> None:
    assert default_source_path().exists()


def test_workbench_parser_accepts_source_and_build_id() -> None:
    parser = build_parser()

    source_args = parser.parse_args(["--source", "fixture.json"])
    build_args = parser.parse_args(["--build-id", "57810", "--base-url", "https://example.test"])

    assert source_args.source == Path("fixture.json")
    assert build_args.build_id == 57810
    assert build_args.base_url == "https://example.test"
