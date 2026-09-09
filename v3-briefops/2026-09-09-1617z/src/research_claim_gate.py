from dataclasses import dataclass

@dataclass(frozen=True)
class ResearchClaimArtifact:
    claim_id: str
    source_digest_verified: bool
    formal_artifact_present: bool
    verifier_toolchain_verified: bool
    independent_reproduction_complete: bool = False

def classify_research_claim(a: ResearchClaimArtifact):
    if not a.source_digest_verified:
        return "REJECT", "source_digest_unverified"
    if not a.formal_artifact_present:
        return "UNVERIFIED", "formal_artifact_missing"
    if not a.verifier_toolchain_verified:
        return "UNVERIFIED", "verifier_toolchain_unverified"
    if not a.independent_reproduction_complete:
        return "CANDIDATE_VERIFIED_ARTIFACT", "independent_reproduction_pending"
    return "INDEPENDENTLY_REPRODUCED", "verification_complete"

def authority_delta_from_research_claim() -> int:
    # Scientific evidence classification never changes principal authority.
    return 0
