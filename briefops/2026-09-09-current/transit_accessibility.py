from dataclasses import dataclass

SAFE_INTENTS = frozenset({
    "identify_vehicle",
    "announce_stop",
    "request_next_stop",
    "locate_accessible_space",
    "request_boarding_assistance",
})

@dataclass(frozen=True)
class TransitIntent:
    action: str
    confidence: float
    provenance_verified: bool
    raw_biometric_retained: bool = False

@dataclass(frozen=True)
class TransitDecision:
    decision: str
    reason: str

def validate_transit_intent(x: TransitIntent) -> TransitDecision:
    if x.raw_biometric_retained:
        return TransitDecision("DENY","raw_biometric_retention_disallowed")
    if not x.provenance_verified:
        return TransitDecision("DENY","unverified_accessibility_provenance")
    if x.confidence < 0.80:
        return TransitDecision("REQUIRE_HUMAN","low_confidence")
    if x.action not in SAFE_INTENTS:
        return TransitDecision("DENY","intent_requires_separate_domain_authority")
    return TransitDecision("ALLOW","assistive_transit_intent")
