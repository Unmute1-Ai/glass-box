from dataclasses import dataclass
from typing import FrozenSet, Optional

SENSITIVE_DOMAINS: FrozenSet[str] = frozenset({"payments", "health", "smart_home", "email"})

@dataclass(frozen=True)
class DomainTransitionRequest:
    principal_id: str
    from_domain: str
    to_domain: str
    explicit_consent: bool
    component_provenance_verified: bool
    action_digest: str
    credential_scope: Optional[str]
    credential_domain: Optional[str]
    credential_single_use: bool
    credential_consumed: bool = False
    external_safety_agent_verdict: Optional[str] = None

def decide_domain_transition(req: DomainTransitionRequest):
    if not req.component_provenance_verified:
        return "DENY", "component_provenance_unverified"
    crossing = req.from_domain != req.to_domain
    sensitive = req.from_domain in SENSITIVE_DOMAINS or req.to_domain in SENSITIVE_DOMAINS
    if crossing and sensitive and not req.explicit_consent:
        return "DENY", "explicit_cross_domain_consent_required"
    if sensitive:
        if req.credential_domain != req.to_domain:
            return "DENY", "credential_domain_mismatch"
        if req.credential_scope != req.action_digest:
            return "DENY", "credential_scope_mismatch"
        if not req.credential_single_use or req.credential_consumed:
            return "DENY", "fresh_single_use_credential_required"
    return "ALLOW", "domain_transition_authorized"

def authority_delta_from_model_or_safety_agent() -> int:
    return 0
