from dataclasses import dataclass

@dataclass(frozen=True)
class CryptoPolicy:
    algorithm: str
    provenance_verified: bool
    policy_status: str  # allowed | migrate | disallowed
    pqc_transition_ready: bool = False
    external_quantum_claim_verified: bool = False

def admit_signature_algorithm(p: CryptoPolicy):
    # Vendor/research estimates are evidence for migration planning, not automatic deprecation.
    if not p.provenance_verified:
        return "DENY", "crypto_provenance_unverified"
    if p.policy_status == "disallowed":
        return "DENY", "algorithm_disallowed_by_policy"
    if p.policy_status == "migrate" and not p.pqc_transition_ready:
        return "DENY", "pqc_transition_required"
    if p.policy_status not in {"allowed", "migrate"}:
        return "DENY", "unknown_crypto_policy_status"
    return "ADMIT", "crypto_policy_satisfied"

def authority_delta_from_crypto_migration() -> int:
    # Changing signature algorithms must never widen the authority of the principal.
    return 0
