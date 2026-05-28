from __future__ import annotations

import argparse
from pathlib import Path
import sys


def default_source_path() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "synthetic_build.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="albs-graph-workbench",
        description="Launch the ALBS provenance investigation workbench.",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=default_source_path(),
        help="ALBS build metadata JSON to open on startup.",
    )
    parser.add_argument(
        "--build-id",
        type=int,
        default=None,
        help="Fetch and open a live ALBS build id on startup.",
    )
    parser.add_argument(
        "--base-url",
        default="https://build.almalinux.org",
        help="ALBS API base URL for --build-id.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from .qt_app import run
    except ModuleNotFoundError as exc:
        if exc.name and (exc.name == "PyQt5" or exc.name.startswith("PyQt5.")):
            print(
                "PyQt5 is required for albs-graph-workbench. "
                "Install it with: pip install -e '.[gui]'",
                file=sys.stderr,
            )
            return 2
        raise
    return run(source=args.source, build_id=args.build_id, base_url=args.base_url)
