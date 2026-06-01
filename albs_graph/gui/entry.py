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
        default=None,
        help="ALBS build metadata JSON to open on startup. Omit to get the "
        "start launcher (choose a session / build id / file / package).",
    )
    parser.add_argument(
        "--build-id",
        type=int,
        default=None,
        help="Fetch and open a live ALBS build id on startup.",
    )
    parser.add_argument(
        "--build-sbom",
        type=Path,
        default=None,
        help="CycloneDX build SBOM JSON to enrich per-RPM evidence.",
    )
    parser.add_argument(
        "--base-url",
        default="https://build.almalinux.org",
        help="ALBS API base URL for --build-id.",
    )
    return parser


def _name_macos_app(name: str) -> None:
    """Rename the macOS application menu (otherwise "Python") to ``name``. macOS
    reads it from the bundle's ``CFBundleName``, so it must be set before Qt
    builds the menu. A no-op off macOS or when pyobjc (the ``macos`` extra) is not
    installed -- the menu then just stays "Python", which is harmless."""

    if sys.platform != "darwin":
        return
    try:
        from Foundation import NSBundle  # type: ignore[import-not-found]
    except ImportError:
        return
    bundle = NSBundle.mainBundle()
    if bundle is None:
        return
    info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
    if info is not None:
        info["CFBundleName"] = name


def main(argv: list[str] | None = None) -> int:
    _name_macos_app("ALBS Workbench")  # rename the macOS app menu (else "Python")
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
    return run(
        source=args.source,
        build_id=args.build_id,
        build_sbom=args.build_sbom,
        base_url=args.base_url,
    )
