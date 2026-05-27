"""Optional Codenotary CAS verification.

CAS verification is strictly opt-in (``--use-cas``) and must never break the
tool: the ``cas`` binary is frequently absent (Codenotary changed product lines
and the public installer/releases are gone), so every entry point degrades to a
recorded ``unavailable`` status instead of raising.

When ``cas`` *is* present (e.g. an AlmaLinux host that still has it), this flips
a CAS attestation node's ``externally_verified`` from the reported default
(false) to true on a successful ``cas authenticate``. That is the only place the
graph is allowed to claim CAS evidence was independently verified, per the
"reported, not verified" rule in CLAUDE.md. Mirrors AlmaLinux's own
``cas_wrapper`` (a thin Python shell over the ``cas`` binary).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

from albs_graph.model import NodeType, ProvenanceGraph

DEFAULT_SIGNER_ID = "cloud-infra@almalinux.org"

# A runner takes cas argv (without the leading "cas") and returns (rc, output).
CasRunner = Callable[[list[str]], tuple[int, str]]


@dataclass(frozen=True)
class CasVerification:
    cas_hash: str
    status: str  # "verified" | "failed" | "unavailable"
    signer_id: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cas_hash": self.cas_hash,
            "status": self.status,
            "signer_id": self.signer_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CasVerificationReport:
    requested: bool
    available: bool
    attestations: int
    verified: int
    failed: int
    unavailable: int
    results: list[CasVerification] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "available": self.available,
            "attestations": self.attestations,
            "verified": self.verified,
            "failed": self.failed,
            "unavailable": self.unavailable,
            "results": [result.to_dict() for result in self.results],
        }


def cas_available() -> bool:
    return shutil.which("cas") is not None


def verify_hash(
    cas_hash: str,
    *,
    signer_id: str | None = DEFAULT_SIGNER_ID,
    runner: CasRunner | None = None,
) -> CasVerification:
    """Verify one CAS hash. Returns ``unavailable`` (never raises) if cas is absent."""

    use_real = runner is None
    if use_real and not cas_available():
        return CasVerification(cas_hash, "unavailable", signer_id, "cas CLI not found in PATH")
    invoke = runner or _run_cas
    args = ["authenticate"]
    if signer_id:
        args += ["--signerID", signer_id]
    args += ["--hash", cas_hash]
    try:
        returncode, output = invoke(args)
    except FileNotFoundError:
        return CasVerification(cas_hash, "unavailable", signer_id, "cas CLI not found in PATH")
    if returncode == 0:
        return CasVerification(cas_hash, "verified", signer_id, None)
    return CasVerification(cas_hash, "failed", signer_id, (output or "").strip()[:200] or "cas failed")


def verify_graph_cas(
    graph: ProvenanceGraph,
    *,
    use_cas: bool = True,
    signer_id: str | None = DEFAULT_SIGNER_ID,
    runner: CasRunner | None = None,
) -> CasVerificationReport:
    """Verify every CAS attestation node carrying a hash; opt-in and crash-proof.

    With ``use_cas=False`` nothing runs and the graph is untouched. With it on
    but ``cas`` absent, every attestation is recorded ``unavailable`` and
    ``externally_verified`` stays false. Only a successful verification flips it.
    """

    nodes = [
        node
        for node in graph.find_by_type(NodeType.CAS_ATTESTATION)
        if node.metadata.get("cas_hash")
    ]
    if not use_cas:
        return CasVerificationReport(False, False, len(nodes), 0, 0, 0, [])

    available = runner is not None or cas_available()
    results: list[CasVerification] = []
    verified = failed = unavailable = 0
    for node in nodes:
        result = verify_hash(str(node.metadata["cas_hash"]), signer_id=signer_id, runner=runner)
        results.append(result)
        if result.status == "verified":
            graph.update_metadata(
                node.id, {"externally_verified": True, "cas_verification": result.to_dict()}
            )
            verified += 1
        elif result.status == "failed":
            graph.update_metadata(node.id, {"cas_verification": result.to_dict()})
            failed += 1
        else:
            unavailable += 1
    return CasVerificationReport(True, available, len(nodes), verified, failed, unavailable, results)


def _run_cas(args: list[str]) -> tuple[int, str]:
    process = subprocess.run(
        ["cas", *args], check=False, text=True, capture_output=True
    )
    return process.returncode, (process.stdout or "") + (process.stderr or "")
