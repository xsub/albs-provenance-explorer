"""Live CPE / CVE feed fetcher: cache + TTL + graceful degradation (D76).

These tests never touch the network. Fetchers are injected (the same shape as
HttpCache's), so each test controls the bytes returned, the cache TTL behaviour,
and the failure paths -- everything the offline-first design promises.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from albs_graph.adapters._http_cache import HttpCache
from albs_graph.security.cpe import CpeDictionary
from albs_graph.security.cve_feed import CveFeed
from albs_graph.security.live_feeds import (
    fetch_cpe_dictionary,
    fetch_cpe_dictionary_or_none,
    fetch_cve_feed,
    fetch_cve_feed_or_none,
)

_CPE_PAYLOAD = json.dumps(
    {"cpes": ["cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"]}
).encode()
_CVE_PAYLOAD = json.dumps(
    {
        "cves": [
            {
                "id": "CVE-2026-1",
                "affected": [
                    {"vendor": "openssl", "product": "openssl", "fixed": "3.0.8"}
                ],
            }
        ]
    }
).encode()


def _make_cache(tmp_path: Path) -> HttpCache:
    return HttpCache(root=tmp_path / "feed-cache", enabled=True)


def test_fetch_cpe_dictionary_returns_parsed_dictionary(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    dictionary = fetch_cpe_dictionary(
        "https://example.invalid/cpe.json",
        cache=cache,
        fetcher=lambda _url: _CPE_PAYLOAD,
    )
    assert isinstance(dictionary, CpeDictionary)
    # Vendor index built from cpe:2.3 entry.
    assert dictionary.vendors_for("openssl") == ["openssl"]


def test_fetch_cve_feed_returns_parsed_feed(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    feed = fetch_cve_feed(
        "https://example.invalid/cve.json",
        cache=cache,
        fetcher=lambda _url: _CVE_PAYLOAD,
    )
    assert isinstance(feed, CveFeed)
    # A pre-3.0.8 openssl matches the affected range.
    assert feed.match("openssl", "openssl", "3.0.7") == ["CVE-2026-1"]


def test_cache_hit_skips_fetcher_when_within_ttl(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    calls = {"n": 0}

    def _fetcher(_url: str) -> bytes:
        calls["n"] += 1
        return _CPE_PAYLOAD

    fetch_cpe_dictionary(
        "https://example.invalid/cpe.json",
        cache=cache,
        fetcher=_fetcher,
        ttl_seconds=3600,
    )
    # Second call within TTL -- must read from disk, not refetch.
    fetch_cpe_dictionary(
        "https://example.invalid/cpe.json",
        cache=cache,
        fetcher=_fetcher,
        ttl_seconds=3600,
    )
    assert calls["n"] == 1


def test_ttl_zero_forces_a_refetch(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    calls = {"n": 0}

    def _fetcher(_url: str) -> bytes:
        calls["n"] += 1
        return _CPE_PAYLOAD

    fetch_cpe_dictionary(
        "https://example.invalid/cpe.json", cache=cache, fetcher=_fetcher, ttl_seconds=0,
    )
    fetch_cpe_dictionary(
        "https://example.invalid/cpe.json", cache=cache, fetcher=_fetcher, ttl_seconds=0,
    )
    assert calls["n"] == 2


def test_stale_cache_entry_is_refetched(tmp_path: Path) -> None:
    # Age the cache entry past the TTL by rolling its mtime back; the next
    # call must refetch (not silently serve the stale bytes).
    cache = _make_cache(tmp_path)
    calls = {"n": 0}

    def _fetcher(_url: str) -> bytes:
        calls["n"] += 1
        return _CPE_PAYLOAD

    url = "https://example.invalid/cpe.json"
    fetch_cpe_dictionary(url, cache=cache, fetcher=_fetcher, ttl_seconds=3600)
    # Locate the cached file the HttpCache wrote and roll its mtime back by 2h.
    cache_path = cache._path(cache._key(url, None))
    assert cache_path.exists()
    past = time.time() - 2 * 3600
    os.utime(cache_path, (past, past))

    fetch_cpe_dictionary(url, cache=cache, fetcher=_fetcher, ttl_seconds=3600)
    assert calls["n"] == 2  # second call refetched


def test_or_none_helper_prefers_source_file_over_url(tmp_path: Path) -> None:
    # When a --verify-cpe FILE is supplied, the URL is irrelevant and the
    # live fetcher must not be called. (Tests catch a regression where the
    # helper would fetch anyway and overwrite.)
    file_path = tmp_path / "dict.json"
    file_path.write_text(_CPE_PAYLOAD.decode(), encoding="utf-8")

    def _should_not_run(_url: str) -> bytes:
        raise AssertionError("fetcher must not run when source_file is given")

    dictionary = fetch_cpe_dictionary_or_none(
        source_file=file_path,
        url="https://example.invalid/cpe.json",
        fetcher=_should_not_run,
    )
    assert isinstance(dictionary, CpeDictionary)


def test_or_none_helper_returns_none_when_both_are_absent() -> None:
    # The whole point of the helper: no inputs -> None, no exception.
    assert fetch_cpe_dictionary_or_none(source_file=None, url=None) is None
    assert fetch_cve_feed_or_none(source_file=None, url=None) is None


def test_or_none_helper_swallows_live_fetch_failure_with_progress_log(tmp_path: Path) -> None:
    logs: list[str] = []

    def _boom(_url: str) -> bytes:
        raise OSError("connection refused")

    result = fetch_cpe_dictionary_or_none(
        source_file=None,
        url="https://example.invalid/cpe.json",
        cache=_make_cache(tmp_path),
        fetcher=_boom,
        on_progress=logs.append,
    )
    assert result is None
    # The graceful-degradation message reaches the user (matches the
    # cas/dnf/rpmkeys "unavailable; continuing" pattern).
    assert any("CPE dictionary unavailable" in line for line in logs)


def test_or_none_helper_swallows_cve_live_fetch_failure(tmp_path: Path) -> None:
    logs: list[str] = []

    def _boom(_url: str) -> bytes:
        raise OSError("network down")

    result = fetch_cve_feed_or_none(
        source_file=None,
        url="https://example.invalid/cve.json",
        cache=_make_cache(tmp_path),
        fetcher=_boom,
        on_progress=logs.append,
    )
    assert result is None
    assert any("CVE feed unavailable" in line for line in logs)


def test_unparseable_response_raises_a_clear_error(tmp_path: Path) -> None:
    # On success path the parse error is loud (it is a real failure: the URL
    # returned bytes, but they were not the expected JSON shape). The
    # or-none helper still converts that to None for the CLI.
    cache = _make_cache(tmp_path)
    with pytest.raises(json.JSONDecodeError):
        fetch_cpe_dictionary(
            "https://example.invalid/cpe.json",
            cache=cache,
            fetcher=lambda _url: b"not json",
        )

    none_result = fetch_cpe_dictionary_or_none(
        source_file=None,
        url="https://example.invalid/cpe.json",
        cache=_make_cache(tmp_path),
        fetcher=lambda _url: b"not json",
    )
    assert none_result is None


def test_default_http_get_sends_a_descriptive_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    # errata.almalinux.org returns 403 to the default "Python-urllib" agent, so
    # the stdlib fetcher must send a real User-Agent.
    import urllib.request

    from albs_graph.security.live_feeds import HTTP_USER_AGENT, _default_http_get

    captured: dict[str, str | None] = {}

    class _Resp:
        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *_: object) -> bool:
            return False

        def read(self) -> bytes:
            return b"{}"

    def _fake_urlopen(
        request: urllib.request.Request, timeout: float = 0, context: object = None
    ) -> _Resp:
        captured["ua"] = request.get_header("User-agent")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    body = _default_http_get("https://errata.almalinux.org/9/errata.full.json")

    assert body == b"{}"
    assert captured["ua"] == HTTP_USER_AGENT
    assert captured["ua"] and "albs-provenance-explorer" in captured["ua"]
