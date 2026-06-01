"""On-demand CVE details (description, CVSS, references) for the GUI inspector.

A ``cve`` node in the graph carries only its id (+ a ``severity`` from errata);
this fetches a human-readable record on demand. Primary source is the **NVD**
CVE 2.0 API; when NVD has nothing usable (offline, rate-limited, or a CVE NVD
has not yet described) it falls back to **OSV** (osv.dev), which aggregates
AlmaLinux (ALSA) advisories and CVEs. Both route through the shared
``HttpCache`` and reuse the live-feed GET (macOS-safe SSL + descriptive
User-Agent). The parse functions are pure and offline-testable; the fetcher is
injectable so no test ever hits the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Callable

from albs_graph.adapters._http_cache import HttpCache, default_cache_root
from albs_graph.security.live_feeds import _default_http_get

Fetcher = Callable[[str], bytes]

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
OSV_VULN_API = "https://api.osv.dev/v1/vulns/{id}"
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{id}"
ALMALINUX_PAGE = "https://errata.almalinux.org/?cve={id}"

__all__ = ["CveDetails", "fetch_cve_details", "parse_nvd_cve", "parse_osv_vuln"]


@dataclass(frozen=True)
class CveDetails:
    id: str
    description: str = ""
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published: str | None = None
    references: tuple[str, ...] = ()
    source: str = ""  # "nvd" / "osv" / "" (nothing reachable)

    @property
    def has_content(self) -> bool:
        return bool(self.description or self.cvss_score or self.cvss_vector)


def fetch_cve_details(
    cve_id: str, *, fetcher: Fetcher | None = None, cache: HttpCache | None = None
) -> CveDetails:
    """Fetch a CVE's description/CVSS/references: NVD first, OSV fallback. Always
    returns a record (empty content if nothing was reachable) with canonical NVD
    + AlmaLinux reference links appended."""

    cve_id = cve_id.strip()
    get = _cached_getter(fetcher, cache)
    details = _try(lambda: parse_nvd_cve(_json(get(NVD_CVE_API.format(id=cve_id))), cve_id))
    if details is None or not details.has_content:
        osv = _try(lambda: parse_osv_vuln(_json(get(OSV_VULN_API.format(id=cve_id))), cve_id))
        if osv is not None and osv.has_content:
            details = osv
    if details is None:
        details = CveDetails(id=cve_id)
    return replace(details, references=_with_canonical_links(cve_id, details.references))


def parse_nvd_cve(payload: dict[str, Any], cve_id: str) -> CveDetails | None:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return None
    cve = (vulnerabilities[0] or {}).get("cve") or {}
    descriptions = cve.get("descriptions") or []
    english = [d.get("value", "") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"]
    description = english[0] if english else ""
    score, severity, vector = _nvd_cvss(cve.get("metrics") or {})
    references = tuple(
        str(ref.get("url"))
        for ref in (cve.get("references") or [])
        if isinstance(ref, dict) and ref.get("url")
    )
    return CveDetails(
        id=str(cve.get("id") or cve_id),
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        published=_opt(cve.get("published")),
        references=references,
        source="nvd",
    )


def parse_osv_vuln(payload: dict[str, Any], cve_id: str) -> CveDetails | None:
    if not payload:
        return None
    description = str(payload.get("details") or payload.get("summary") or "")
    references = tuple(
        str(ref.get("url"))
        for ref in (payload.get("references") or [])
        if isinstance(ref, dict) and ref.get("url")
    )
    vector: str | None = None
    for severity in payload.get("severity") or []:
        if isinstance(severity, dict) and str(severity.get("type", "")).startswith("CVSS"):
            vector = _opt(severity.get("score"))
            break
    if not (description or references or vector):
        return None
    return CveDetails(
        id=str(payload.get("id") or cve_id),
        description=description,
        cvss_vector=vector,
        references=references,
        source="osv",
    )


def _nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if isinstance(items, list) and items:
            entry = items[0] or {}
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            return (
                float(score) if isinstance(score, (int, float)) else None,
                str(severity) if severity else None,
                _opt(data.get("vectorString")),
            )
    return (None, None, None)


def _with_canonical_links(cve_id: str, references: tuple[str, ...]) -> tuple[str, ...]:
    links = list(references)
    for page in (NVD_PAGE.format(id=cve_id), ALMALINUX_PAGE.format(id=cve_id)):
        if page not in links:
            links.append(page)
    return tuple(links)


def _cached_getter(fetcher: Fetcher | None, cache: HttpCache | None) -> Fetcher:
    if fetcher is not None:
        return fetcher
    store = cache or HttpCache(root=default_cache_root() / "cve-details")
    return lambda url: store.get_or_fetch(url, lambda: _default_http_get(url))


def _json(body: bytes) -> dict[str, Any]:
    data = json.loads(body.decode("utf-8"))
    return data if isinstance(data, dict) else {}


def _try(builder: Callable[[], CveDetails | None]) -> CveDetails | None:
    try:
        return builder()
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _opt(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None
