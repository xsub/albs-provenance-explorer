"""RPM GPG signature verification - real provenance verification.

ALBS gives us signature *nodes* (from sign tasks), but until now nothing checked
the actual RPM's GPG signature. With Codenotary CAS gone, this is the verification
story: ``rpmkeys --checksig`` (or ``rpm -K``) validates a downloaded RPM against
the AlmaLinux GPG keys in the host keyring, moving a signature from "present" to
"cryptographically verified".

Opt-in and crash-proof, like the CAS adapter: absent ``rpmkeys`` returns a
recorded ``unavailable`` status, never raising. The command runner and the RPM
fetcher are both injectable, so the parsing and graph-mutation are fully tested
offline without the binary or the network. Only a successful verification flips
``signature_verified`` on the RPM node and ``externally_verified`` on its
signature node(s).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation

from .rpm_remote import vault_candidate_urls

Runner = Callable[[list[str]], tuple[int, str]]
FullFetcher = Callable[[str], bytes]
UrlResolver = Callable[[str], list[str]]
NodeSelector = Callable[[Node], bool]

_MAX_RPM_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class SignatureVerification:
    artifact: str
    status: str  # "verified" | "nokey" | "failed" | "unavailable"
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"artifact": self.artifact, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class SignatureReport:
    requested: bool
    available: bool
    binaries: int
    verified: int
    nokey: int
    failed: int
    unavailable: int
    results: list[SignatureVerification] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "available": self.available,
            "binaries": self.binaries,
            "verified": self.verified,
            "nokey": self.nokey,
            "failed": self.failed,
            "unavailable": self.unavailable,
            "results": [result.to_dict() for result in self.results],
        }


def rpmkeys_available() -> bool:
    return shutil.which("rpmkeys") is not None or shutil.which("rpm") is not None


def parse_checksig(returncode: int, output: str) -> str:
    """Classify ``rpmkeys --checksig`` output into a status."""

    lowered = output.lower()
    if "nokey" in lowered:
        return "nokey"
    if returncode == 0 and ("signatures ok" in lowered or lowered.rstrip().endswith("ok")):
        return "verified"
    return "failed"


def checksig_bytes(
    artifact: str, rpm_bytes: bytes, *, runner: Runner | None = None
) -> SignatureVerification:
    """Verify the GPG signature of RPM bytes via ``rpmkeys --checksig``."""

    use_real = runner is None
    if use_real and not rpmkeys_available():
        return SignatureVerification(artifact, "unavailable", "rpmkeys/rpm not found in PATH")
    tool = "rpmkeys" if shutil.which("rpmkeys") else "rpm"
    handle, path = tempfile.mkstemp(suffix=".rpm")
    try:
        with os.fdopen(handle, "wb") as tmp:
            tmp.write(rpm_bytes)
        invoke = runner or _run_rpmkeys
        try:
            returncode, output = invoke([tool, "--checksig", path])
        except FileNotFoundError:
            return SignatureVerification(artifact, "unavailable", "rpmkeys/rpm not found")
    finally:
        try:
            os.unlink(path)
        except OSError:  # pragma: no cover - best effort cleanup
            pass
    status = parse_checksig(returncode, output)
    detail = (output or "").strip()[:200] or None
    return SignatureVerification(artifact, status, detail if status != "verified" else None)


def verify_graph_signatures(
    graph: ProvenanceGraph,
    *,
    use_signatures: bool = True,
    fetch_full: FullFetcher | None = None,
    url_resolver: UrlResolver | None = None,
    runner: Runner | None = None,
    node_selector: NodeSelector | None = None,
    limit: int | None = None,
) -> SignatureReport:
    """Download each selected binary RPM and verify its GPG signature."""

    binaries = verified = nokey = failed = unavailable = 0
    results: list[SignatureVerification] = []
    if not use_signatures:
        return SignatureReport(False, False, 0, 0, 0, 0, 0, [])

    available = runner is not None or rpmkeys_available()
    if not available:
        seen = sum(
            1
            for node in graph.find_by_type(NodeType.BINARY_RPM)
            if (not node_selector or node_selector(node))
        )
        return SignatureReport(True, False, seen, 0, 0, 0, seen, [])

    resolver = url_resolver or vault_candidate_urls
    fetcher = fetch_full or _requests_full_get
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        filename = _filename(graph, node.id)
        if not filename or _is_debug(filename):
            continue
        if limit is not None and binaries >= limit:
            break
        binaries += 1
        result = _verify_one(node.id, filename, resolver(filename), fetcher, runner)
        results.append(result)
        if result.status == "verified":
            verified += 1
            node.metadata["signature_verified"] = True
            _mark_signature_nodes(graph, node.id, result)
        elif result.status == "nokey":
            nokey += 1
            node.metadata["signature_verified"] = False
        elif result.status == "failed":
            failed += 1
            node.metadata["signature_verified"] = False
        else:
            unavailable += 1
    return SignatureReport(True, True, binaries, verified, nokey, failed, unavailable, results)


def _verify_one(
    artifact: str,
    filename: str,
    candidates: list[str],
    fetcher: FullFetcher,
    runner: Runner | None,
) -> SignatureVerification:
    for url in candidates:
        try:
            return checksig_bytes(filename, fetcher(url), runner=runner)
        except (OSError, ValueError):
            continue
    return SignatureVerification(filename, "unavailable", "could not download RPM")


def _mark_signature_nodes(
    graph: ProvenanceGraph, rpm_id: str, result: SignatureVerification
) -> None:
    for edge in graph.outgoing(rpm_id, Relation.SIGNED_AS):
        node = graph.nodes[edge.target]
        if node.type == NodeType.SIGNATURE:
            node.metadata["externally_verified"] = True
            node.metadata["signature_verification"] = result.to_dict()


def _filename(graph: ProvenanceGraph, node_id: str) -> str | None:
    metadata = graph.nodes[node_id].metadata
    value = metadata.get("filename") or metadata.get("artifact_name") or graph.nodes[node_id].label
    text = str(value).strip()
    return text if text.endswith(".rpm") else None


def _is_debug(filename: str) -> bool:
    return "-debuginfo" in filename or "-debugsource" in filename


def _run_rpmkeys(args: list[str]) -> tuple[int, str]:
    process = subprocess.run(args, check=False, text=True, capture_output=True)
    return process.returncode, (process.stdout or "") + (process.stderr or "")


def _requests_full_get(url: str) -> bytes:
    import requests

    response = requests.get(url, timeout=120, allow_redirects=True, stream=True)
    if response.status_code not in (200, 206):
        raise OSError(f"HTTP {response.status_code} for {url}")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=65536):
        chunks.append(chunk)
        size += len(chunk)
        if size > _MAX_RPM_BYTES:
            raise OSError(f"RPM exceeded {_MAX_RPM_BYTES} bytes for {url}")
    return b"".join(chunks)
