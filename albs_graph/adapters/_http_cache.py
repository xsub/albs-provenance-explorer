"""Content-addressed disk cache for RPM header/payload HTTP fetches.

Headers are tiny (~10-50 KB) and reused across runs; payloads are larger
(5-50 MB) and opt-in. Both adapters route their per-URL fetch through this
cache so a rerun reads disk instead of the network.

Key = sha256(url + range), bucketed by the first 2 chars to keep any single
directory small. Only successful responses are cached: an exception from the
inner fetcher (which today raises on 4xx/5xx) propagates as-is, so the mirror
cascade (rpm_remote `_try_candidates`) still self-heals when a vault URL
becomes live. Cache writes are atomic (tmp + rename) so a crash mid-write
cannot poison subsequent reads.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


def default_cache_root() -> Path:
    """Cache location: ``$ALBS_HTTP_CACHE`` if set, else XDG, else ``~/.cache``."""

    env = os.environ.get("ALBS_HTTP_CACHE")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(xdg) / "albs-provenance-explorer"


@dataclass
class HttpCache:
    """A read-through disk cache for ``get_or_fetch(url, fetcher)`` calls."""

    root: Path = field(default_factory=default_cache_root)
    enabled: bool = True
    hits: int = 0
    misses: int = 0

    def __post_init__(self) -> None:
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)

    def _key(self, url: str, range_: tuple[int, int] | None) -> str:
        material = url if range_ is None else f"{url}:{range_[0]}-{range_[1]}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / key

    def get_or_fetch(
        self,
        url: str,
        fetch: Callable[[], bytes],
        *,
        range_: tuple[int, int] | None = None,
    ) -> bytes:
        """Return cached bytes for ``(url, range_)`` or call ``fetch`` + cache.

        ``fetch`` must raise on any non-success response; only successful bytes
        are cached. With ``enabled=False`` the cache is a transparent pass-through
        (always fetches, never reads or writes disk).
        """

        if not self.enabled:
            return fetch()
        path = self._path(self._key(url, range_))
        if path.exists():
            self.hits += 1
            return path.read_bytes()
        self.misses += 1
        body = fetch()
        self._store(path, body)
        return body

    def _store(self, path: Path, body: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic: write to a sibling tmp file and rename, so a crash mid-write
        # never leaves a partial file in the cache.
        tmp = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
        try:
            tmp.write(body)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        Path(tmp.name).replace(path)


def cached_range_fetcher(
    cache: HttpCache, base: Callable[[str, int, int], bytes]
) -> Callable[[str, int, int], bytes]:
    """Wrap a ``(url, start, end) -> bytes`` fetcher to read-through ``cache``."""

    def fetch(url: str, start: int, end: int) -> bytes:
        return cache.get_or_fetch(url, lambda: base(url, start, end), range_=(start, end))

    return fetch


def cached_full_fetcher(
    cache: HttpCache, base: Callable[[str], bytes]
) -> Callable[[str], bytes]:
    """Wrap a ``url -> bytes`` fetcher to read-through ``cache``."""

    def fetch(url: str) -> bytes:
        return cache.get_or_fetch(url, lambda: base(url))

    return fetch
