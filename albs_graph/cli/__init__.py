from __future__ import annotations

from typing import Any


def main(argv: list[str] | None = None) -> int:
    from .main import main as cli_main

    return cli_main(argv)


def __getattr__(name: str) -> Any:
    if name == "app":
        from .main import app

        return app
    raise AttributeError(name)


__all__ = ["app", "main"]
