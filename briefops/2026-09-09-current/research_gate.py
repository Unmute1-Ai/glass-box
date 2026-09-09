from dataclasses import dataclass

VALID_STATES = (
    "GENERATED",
    "FORMALIZED",
    "INDEPENDENTLY_REVIEWED",
    "PUBLISHABLE",
    "ESTABLISHED",
)

@dataclass(frozen=True)
class ResearchClaim:
    claim_id: str
    state: str
    formal_artifact_verified: bool
    independent_review_count: int
    source_conflict: bool = False
    prize_body_or_authority_accepted: bool = False

@dataclass(frozen=True)
class ResearchDecision:
    decision: str
    reason: str

def evaluate_claim(c: ResearchClaim) -> ResearchDecision:
    if c.state not in VALID_STATES:
        return ResearchDecision("DENY","invalid_research_state")
    if c.source_conflict:
        return ResearchDecision("HOLD","source_conflict_requires_resolution")
    if c.state in {"FORMALIZED","INDEPENDENTLY_REVIEWED","PUBLISHABLE","ESTABLISHED"} and not c.formal_artifact_verified:
        return ResearchDecision("DENY","formal_artifact_not_verified")
    if c.state in {"PUBLISHABLE","ESTABLISHED"} and c.independent_review_count < 2:
        return ResearchDecision("HOLD","independent_review_threshold_not_met")
    if c.state == "ESTABLISHED" and not c.prize_body_or_authority_accepted:
        return ResearchDecision("HOLD","external_authority_acceptance_missing")
    return ResearchDecision("ALLOW","research_state_supported")

def model_may_self_promote_claim() -> bool:
    return False
