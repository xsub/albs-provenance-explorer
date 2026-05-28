from pathlib import Path

from albs_graph.adapters._http_cache import (
    HttpCache,
    cached_full_fetcher,
    cached_range_fetcher,
    default_cache_root,
)


def test_cache_miss_then_hit_calls_fetcher_only_once(tmp_path: Path) -> None:
    cache = HttpCache(root=tmp_path, enabled=True)
    calls = 0

    def fetcher() -> bytes:
        nonlocal calls
        calls += 1
        return b"the bytes"

    first = cache.get_or_fetch("https://example/x", fetcher, range_=(0, 99))
    second = cache.get_or_fetch("https://example/x", fetcher, range_=(0, 99))

    assert first == second == b"the bytes"
    assert calls == 1  # second call served from disk; fetcher untouched
    assert cache.hits == 1 and cache.misses == 1


def test_different_ranges_of_one_url_are_cached_independently(tmp_path: Path) -> None:
    # rpm_remote.fetch_rpm_header issues two range reads per RPM (tail probe,
    # then header region). Each must cache as its own entry.
    cache = HttpCache(root=tmp_path)
    calls: list[tuple[int, int]] = []

    def fetcher_for(start: int, end: int):
        def fetch() -> bytes:
            calls.append((start, end))
            return f"{start}:{end}".encode()
        return fetch

    a = cache.get_or_fetch("https://example/rpm", fetcher_for(0, 31), range_=(0, 31))
    b = cache.get_or_fetch("https://example/rpm", fetcher_for(32, 4095), range_=(32, 4095))
    a2 = cache.get_or_fetch("https://example/rpm", fetcher_for(0, 31), range_=(0, 31))

    assert a == b"0:31" and b == b"32:4095" and a2 == b"0:31"
    assert calls == [(0, 31), (32, 4095)]  # third call served from cache


def test_404_or_other_failure_is_not_cached(tmp_path: Path) -> None:
    # rpm_remote `_try_candidates` cascade relies on raised exceptions to advance
    # to the next mirror; cached "failures" would break that. A subsequent call
    # for the same URL must call the fetcher again.
    cache = HttpCache(root=tmp_path)
    attempts = 0

    def failing_then_succeeding() -> bytes:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("upstream 404")
        return b"now available"

    try:
        cache.get_or_fetch("https://example/y", failing_then_succeeding)
    except RuntimeError:
        pass
    body = cache.get_or_fetch("https://example/y", failing_then_succeeding)

    assert body == b"now available"
    assert attempts == 2  # the failure was not cached; retried on next call


def test_disabled_cache_always_fetches_and_does_not_write(tmp_path: Path) -> None:
    cache = HttpCache(root=tmp_path, enabled=False)
    calls = 0

    def fetcher() -> bytes:
        nonlocal calls
        calls += 1
        return b"live bytes"

    cache.get_or_fetch("https://example/z", fetcher)
    cache.get_or_fetch("https://example/z", fetcher)

    assert calls == 2
    assert list(tmp_path.rglob("*")) == []  # disabled cache writes nothing


def test_cache_path_is_bucketed_and_atomic(tmp_path: Path) -> None:
    # Bucketing keeps any one directory small even at 10k+ entries; atomic
    # rename means a partial write never leaves a poisoned file.
    cache = HttpCache(root=tmp_path)
    cache.get_or_fetch("https://example/a", lambda: b"A")
    cache.get_or_fetch("https://example/b", lambda: b"B")

    # Every cached file lives under a two-char bucket; no stray tmp files left over.
    entries = list(tmp_path.rglob("*"))
    files = [p for p in entries if p.is_file()]
    assert len(files) == 2
    for f in files:
        assert f.parent.parent == tmp_path  # root/<bucket>/<key>
        assert len(f.parent.name) == 2  # 2-char bucket dir


def test_cached_range_fetcher_wraps_a_base_fetcher(tmp_path: Path) -> None:
    cache = HttpCache(root=tmp_path)
    base_calls = 0

    def base(url: str, start: int, end: int) -> bytes:
        nonlocal base_calls
        base_calls += 1
        return f"{url}#{start}-{end}".encode()

    fetcher = cached_range_fetcher(cache, base)
    assert fetcher("https://x/rpm", 0, 9) == b"https://x/rpm#0-9"
    assert fetcher("https://x/rpm", 0, 9) == b"https://x/rpm#0-9"  # cache hit
    assert base_calls == 1


def test_cached_full_fetcher_wraps_a_base_fetcher(tmp_path: Path) -> None:
    cache = HttpCache(root=tmp_path)
    base_calls = 0

    def base(url: str) -> bytes:
        nonlocal base_calls
        base_calls += 1
        return f"contents-of-{url}".encode()

    fetcher = cached_full_fetcher(cache, base)
    assert fetcher("https://x/rpm") == b"contents-of-https://x/rpm"
    assert fetcher("https://x/rpm") == b"contents-of-https://x/rpm"  # cache hit
    assert base_calls == 1


def test_default_cache_root_honors_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ALBS_HTTP_CACHE", str(tmp_path / "override"))
    assert default_cache_root() == tmp_path / "override"

    monkeypatch.delenv("ALBS_HTTP_CACHE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_root() == tmp_path / "xdg" / "albs-provenance-explorer"
