from dataclasses import dataclass
from typing import FrozenSet

SENSITIVE_DOMAINS = frozenset({'payments','health','smart_home','physical','emergency','identity','child_profile'})

@dataclass(frozen=True)
class PrincipalGrant:
    principal: str
    domains: FrozenSet[str]
    actions: FrozenSet[str]

@dataclass(frozen=True)
class ComponentEvidence:
    artifact_digest_verified: bool
    signed_provenance_verified: bool
    inspector_verdict: str = 'unknown'
    registry_owner: str = 'unknown'
    hardware_vendor: str = 'unknown'
    hardware_attested: bool = False

@dataclass(frozen=True)
class EffectRequest:
    principal: str
    source_domain: str
    target_domain: str
    action: str
    explicit_consent: bool = False
    credential_scope: str = ''
    credential_single_use: bool = False
    credential_consumed: bool = False


def admit_component(e: ComponentEvidence) -> bool:
    return bool(e.artifact_digest_verified and e.signed_provenance_verified)


def authorize(req: EffectRequest, grant: PrincipalGrant, component: ComponentEvidence) -> tuple[str, str]:
    if not admit_component(component):
        return 'DENY', 'unverified_component_provenance'
    if req.principal != grant.principal:
        return 'DENY', 'principal_mismatch'
    if req.target_domain not in grant.domains or req.action not in grant.actions:
        return 'DENY', 'scope_mismatch'
    if req.source_domain != req.target_domain and req.target_domain in SENSITIVE_DOMAINS and not req.explicit_consent:
        return 'REQUIRE_CONSENT', 'explicit_cross_domain_consent_required'
    expected_scope = f'{req.target_domain}:{req.action}'
    if req.target_domain in SENSITIVE_DOMAINS:
        if not req.credential_single_use or req.credential_consumed or req.credential_scope != expected_scope:
            return 'DENY', 'scoped_single_use_credential_required'
    return 'ALLOW', 'authorized'


def external_monitor_can_override(decision: str, monitor_verdict: str) -> bool:
    return False


def authority_vector_for_model(model_id: str, requests, grant, component):
    return [authorize(r, grant, component)[0] for r in requests]
