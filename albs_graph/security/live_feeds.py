"""Live CPE dictionary + CVE feed fetchers, routed through HttpCache.

A1 (D21) ships ``CpeDictionary.from_file`` / ``CveFeed.from_file``: dictionary
and feed are supplied as on-disk JSON, exercised offline. This module adds
**live** fetchers so a real run can pull the upstream sources without losing
the offline-first design:

- ``fetch_cpe_dictionary(url, ..)`` -> ``CpeDictionary``: GETs a CPE dictionary
  JSON (NVD's bundled export, or any drop-in mirror with the same shape) and
  parses it the same way ``from_file`` does.
- ``fetch_cve_feed(url, ..)`` -> ``CveFeed``: GETs a CVE feed JSON and
  decodes it through the same ``CveFeed.from_entries`` pipeline used by
  ``from_file``.

Both route through the existing ``HttpCache`` (the D63/D64 cache, shared with
``rpm_remote`` / ``rpm_payload`` / ``rpmsig``). Cache hits skip the network
entirely. ``ttl_seconds`` invalidates entries older than the configured
window so the cached copy stays fresh on its own schedule (default 12 h,
matching NVD's documented refresh cadence; pass ``ttl_seconds=0`` to force
a refetch or ``ttl_seconds=None`` to disable TTL).

``fetch_or_none(.., source_file=PATH)`` is the helper the CLI uses: prefer a
``--cpe-dictionary``/``--cve-feed`` file when supplied, otherwise try the
live URL, otherwise return ``None`` and let the caller proceed without a
feed. Network errors are swallowed (with optional progress logging) so an
offline run never crashes -- it just degrades to "no live feed available",
the same way ``cas`` / ``dnf`` / ``rpmkeys`` degrade today.

The cache wrapping is deliberately minimal: HttpCache is content-addressed
on (url, range), so calling it again with the same URL hits disk; we add a
mtime check on top to enforce a TTL since feeds *do* change upstream.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from albs_graph.adapters._http_cache import HttpCache, default_cache_root

from .cpe import CpeDictionary
from .cve_feed import CveFeed

Progress = Callable[[str], None] | None
# A fetcher takes (url) -> bytes; defaults to urllib so the module is stdlib-
# only, but a test (or a caller wanting different timeouts / a session) can
# inject any callable with the same shape.
Fetcher = Callable[[str], bytes]


# Conservative defaults. NVD's bundled JSON exports are refreshed roughly
# every two hours upstream, but downstream consumers usually pin to a longer
# cadence -- a half-day cap is the documented recommendation for "stale but
# usable". A caller can always override.
_DEFAULT_TTL_SECONDS: float = 12 * 3600


def fetch_cpe_dictionary(
    url: str,
    *,
    cache: HttpCache | None = None,
    ttl_seconds: float | None = _DEFAULT_TTL_SECONDS,
    fetcher: Fetcher | None = None,
    on_progress: Progress = None,
) -> CpeDictionary:
    """Live fetch -> :class:`CpeDictionary`. Cached on disk; raises on parse fail."""

    body = _cached_get(
        url,
        cache=cache,
        ttl_seconds=ttl_seconds,
        fetcher=fetcher,
        on_progress=on_progress,
    )
    return _cpe_dictionary_from_bytes(body)


def fetch_cve_feed(
    url: str,
    *,
    cache: HttpCache | None = None,
    ttl_seconds: float | None = _DEFAULT_TTL_SECONDS,
    fetcher: Fetcher | None = None,
    on_progress: Progress = None,
) -> CveFeed:
    """Live fetch -> :class:`CveFeed`. Cached on disk; raises on parse fail."""

    body = _cached_get(
        url,
        cache=cache,
        ttl_seconds=ttl_seconds,
        fetcher=fetcher,
        on_progress=on_progress,
    )
    return _cve_feed_from_bytes(body)


def fetch_cpe_dictionary_or_none(
    *,
    source_file: str | Path | None,
    url: str | None,
    cache: HttpCache | None = None,
    ttl_seconds: float | None = _DEFAULT_TTL_SECONDS,
    fetcher: Fetcher | None = None,
    on_progress: Progress = None,
) -> CpeDictionary | None:
    """A file wins; else try the URL; else None (degrade gracefully)."""

    if source_file is not None:
        return CpeDictionary.from_file(source_file)
    if not url:
        return None
    try:
        return fetch_cpe_dictionary(
            url,
            cache=cache,
            ttl_seconds=ttl_seconds,
            fetcher=fetcher,
            on_progress=on_progress,
        )
    except Exception as exc:  # noqa: BLE001 -- live fetch must never crash a run
        if on_progress:
            on_progress(f"live CPE dictionary unavailable ({exc}); continuing without it")
        return None


def fetch_cve_feed_or_none(
    *,
    source_file: str | Path | None,
    url: str | None,
    cache: HttpCache | None = None,
    ttl_seconds: float | None = _DEFAULT_TTL_SECONDS,
    fetcher: Fetcher | None = None,
    on_progress: Progress = None,
) -> CveFeed | None:
    """A file wins; else try the URL; else None (degrade gracefully)."""

    if source_file is not None:
        return CveFeed.from_file(source_file)
    if not url:
        return None
    try:
        return fetch_cve_feed(
            url,
            cache=cache,
            ttl_seconds=ttl_seconds,
            fetcher=fetcher,
            on_progress=on_progress,
        )
    except Exception as exc:  # noqa: BLE001 -- live fetch must never crash a run
        if on_progress:
            on_progress(f"live CVE feed unavailable ({exc}); continuing without it")
        return None


# --- internals ---------------------------------------------------------------


def _cached_get(
    url: str,
    *,
    cache: HttpCache | None,
    ttl_seconds: float | None,
    fetcher: Fetcher | None,
    on_progress: Progress,
) -> bytes:
    """Cache-aware GET. TTL on top of HttpCache (since feeds *do* change).

    HttpCache itself is correctness-first (content-addressed, no TTL); this
    wrapper adds the freshness window upstream feeds expect. When the cached
    entry is stale, we delete it before delegating to ``get_or_fetch`` so the
    cache rewrites with fresh bytes (otherwise ``get_or_fetch`` would serve
    the stale copy).
    """

    cache = cache or HttpCache(root=default_cache_root() / "feeds")
    do_fetch = fetcher or _default_http_get
    cache_path = cache._path(cache._key(url, None))
    if cache.enabled and cache_path.exists() and not _within_ttl(cache_path, ttl_seconds):
        # Stale -> force a refetch by removing the cached body. The next
        # get_or_fetch will write a fresh copy atomically.
        cache_path.unlink()
    if on_progress and not cache_path.exists():
        on_progress(f"fetching {url}")
    return cache.get_or_fetch(url, lambda: do_fetch(url))


def _within_ttl(path: Path, ttl_seconds: float | None) -> bool:
    if ttl_seconds is None:
        return True  # no TTL configured -> any cached copy is fresh enough
    if ttl_seconds <= 0:
        return False  # explicit force-refresh
    age = time.time() - path.stat().st_mtime
    return age <= ttl_seconds


def _default_http_get(url: str) -> bytes:
    """Stdlib HTTP GET. Inlined here so the security module stays adapter-free."""

    from urllib.request import Request, urlopen  # lazy import (no top-level network)

    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 -- caller passes URL
        return bytes(response.read())


def _cpe_dictionary_from_bytes(body: bytes) -> CpeDictionary:
    """Decode CPE dictionary JSON the same way ``from_file`` does."""

    data: Any = json.loads(body.decode("utf-8"))
    entries = data.get("cpes", data) if isinstance(data, dict) else data
    return CpeDictionary.from_cpe23([str(item) for item in entries])


def _cve_feed_from_bytes(body: bytes) -> CveFeed:
    """Decode CVE feed JSON the same way ``from_file`` does."""

    data: Any = json.loads(body.decode("utf-8"))
    raw = data.get("cves", data) if isinstance(data, dict) else data
    return CveFeed.from_entries(list(raw))
