"""On-demand package description for the GUI inspector (D140).

A binary RPM / SRPM / source node carries its NEVRA but no human-readable
description. This fetches one: the host ``dnf repoquery --info <name>`` when dnf
is available (no network), else the package's own RPM header range-fetched from
the public AlmaLinux mirror/vault (no dnf -- works on macOS). Both are injectable
so no test hits the network or shells out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from albs_graph.adapters.dnf import DnfUnavailable, Runner, _run, dnf_available
from albs_graph.adapters.rpm_header import RpmHeaderError
from albs_graph.adapters.rpm_remote import (
    RangeFetcher,
    RpmHeaderFetchError,
    default_range_fetcher,
    fetch_rpm_header,
    vault_candidate_urls,
)

__all__ = ["PackageInfo", "fetch_package_info", "parse_dnf_info"]


@dataclass(frozen=True)
class PackageInfo:
    name: str
    summary: str = ""
    description: str = ""
    license: str = ""
    url: str = ""
    source: str = ""  # "dnf" / "rpm header (<url>)" / "" (nothing reachable)

    @property
    def has_content(self) -> bool:
        return bool(self.summary or self.description)


def fetch_package_info(
    name: str,
    *,
    rpm_filename: str | None = None,
    dnf_runner: Runner | None = None,
    range_fetcher: RangeFetcher | None = None,
) -> PackageInfo:
    """Fetch a package's summary/description/license/url: host ``dnf`` first (no
    network), then the RPM header over HTTP Range (no dnf). Always returns a
    record (empty when nothing was reachable)."""

    name = name.strip()
    if dnf_runner is not None or dnf_available():
        info = _dnf_package_info(name, runner=dnf_runner)
        if info is not None and info.has_content:
            return info
    if rpm_filename:
        info = _header_package_info(name, rpm_filename, range_fetcher=range_fetcher)
        if info is not None and info.has_content:
            return info
    return PackageInfo(name=name)


def parse_dnf_info(text: str) -> dict[str, str]:
    """Parse the first ``dnf repoquery --info`` record into lowercase fields. Each
    record is ``Field : value`` lines; a wrapped description continues on lines
    that start with a colon. A blank line ends the first record."""

    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                break
            continue
        cont = re.match(r"^\s+:\s?(.*)$", line)
        if cont is not None and current is not None:
            fields[current] = f"{fields[current]} {cont.group(1)}".strip()
            continue
        head = re.match(r"^([A-Za-z][A-Za-z ]*?)\s*:\s?(.*)$", line)
        if head is not None:
            current = head.group(1).strip().lower()
            fields.setdefault(current, head.group(2).strip())
    return fields


def _dnf_package_info(name: str, *, runner: Runner | None) -> PackageInfo | None:
    try:
        output = _run(["dnf", "repoquery", "--quiet", "--info", name], runner)
    except DnfUnavailable:
        return None
    fields = parse_dnf_info(output)
    if not (fields.get("summary") or fields.get("description")):
        return None
    return PackageInfo(
        name=fields.get("name") or name,
        summary=fields.get("summary", ""),
        description=fields.get("description", ""),
        license=fields.get("license", ""),
        url=fields.get("url", ""),
        source="dnf",
    )


def _header_package_info(
    name: str, rpm_filename: str, *, range_fetcher: RangeFetcher | None
) -> PackageInfo | None:
    fetcher = range_fetcher or default_range_fetcher()
    for url in vault_candidate_urls(rpm_filename):
        try:
            header = fetch_rpm_header(url, fetcher)
        except (RpmHeaderFetchError, RpmHeaderError):
            continue
        return PackageInfo(
            name=header.name or name,
            summary=header.summary or "",
            description=header.description or "",
            license=header.license or "",
            url=header.url or "",
            source=f"rpm header ({url})",
        )
    return None
