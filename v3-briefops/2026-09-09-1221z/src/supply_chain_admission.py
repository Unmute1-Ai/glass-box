from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class SupplyChainComponent:
    name: str
    source_registry: str
    expected_digest: Optional[str]
    runtime_digest: Optional[str]
    publisher_verified: bool
    build_provenance_verified: bool
    generated_or_modified_by_ai: bool = False
    external_scanner_verdict: Optional[str] = None

@dataclass(frozen=True)
class AdmissionDecision:
    decision: str
    reason: str

def admit_supply_chain_component(c: SupplyChainComponent) -> AdmissionDecision:
    # External scanner verdicts are advisory evidence only and never grant authority.
    if not c.publisher_verified:
        return AdmissionDecision("DENY", "publisher_unverified")
    if not c.build_provenance_verified:
        return AdmissionDecision("DENY", "build_provenance_unverified")
    if not c.expected_digest or not c.runtime_digest:
        return AdmissionDecision("DENY", "digest_missing")
    if c.expected_digest != c.runtime_digest:
        return AdmissionDecision("DENY", "runtime_digest_mismatch")
    return AdmissionDecision("ADMIT", "verified_component")

def authority_delta_after_admission() -> int:
    # Component admission establishes identity/integrity, not principal authority.
    return 0
