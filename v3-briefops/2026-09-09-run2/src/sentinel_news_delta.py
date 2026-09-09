from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

SENSITIVE_DOMAINS = frozenset({"payments","health","smart_home","physical","emergency","identity","external_publish"})
CONSEQUENTIAL_VERBS = frozenset({"send_payment","write_health_record","actuate","publish_official_alert","delete","publish_external","export_sensitive_data"})

@dataclass(frozen=True)
class Provenance:
    issuer_verified: bool
    artifact_digest_verified: bool
    deployment_class_allowed: bool
    supplier: str = "unknown"
    hardware_attestation: Optional[str] = None
    external_scanner_verdict: Optional[str] = None
    @property
    def admitted(self) -> bool:
        return self.issuer_verified and self.artifact_digest_verified and self.deployment_class_allowed

@dataclass(frozen=True)
class Component:
    expected_digest: str
    runtime_digest: str
    discovered_by_external_scanner: bool = False
    external_scanner_verdict: Optional[str] = None
    @property
    def admitted(self) -> bool:
        return bool(self.expected_digest) and self.expected_digest == self.runtime_digest

@dataclass(frozen=True)
class Principal:
    principal_id: str
    capabilities: FrozenSet[str]
    domains: FrozenSet[str]
    consents: FrozenSet[Tuple[str,str]] = frozenset()

@dataclass(frozen=True)
class Effect:
    source_domain: str
    target_domain: str
    capability: str
    verb: str
    action_digest: str
    credential_scope: Optional[str] = None
    credential_single_use: bool = False
    credential_consumed: bool = False
    authenticated_official_authority: bool = False
    verified_simulation: bool = False

def authority_vector(p: Principal):
    return (p.principal_id, tuple(sorted(p.capabilities)), tuple(sorted(p.domains)), tuple(sorted(p.consents)))

def decide(p: Principal, prov: Provenance, comp: Component, e: Effect):
    if not prov.admitted:
        return "DENY", "unverified_model_provenance"
    if not comp.admitted:
        return "DENY", "unverified_component_provenance"
    if e.capability not in p.capabilities or e.target_domain not in p.domains:
        return "DENY", "principal_scope_mismatch"
    if e.source_domain != e.target_domain and e.target_domain in SENSITIVE_DOMAINS and (e.source_domain, e.target_domain) not in p.consents:
        return "REQUIRE_CONSENT", "explicit_cross_domain_consent_required"
    if e.verb in CONSEQUENTIAL_VERBS:
        if e.credential_scope != e.action_digest or not e.credential_single_use or e.credential_consumed:
            return "DENY", "scoped_single_use_credential_required"
    if e.verb == "actuate" and not e.verified_simulation:
        return "DENY", "verified_simulation_required"
    if e.verb == "publish_official_alert" and not e.authenticated_official_authority:
        return "DENY", "authenticated_authority_integration_required"
    return "ALLOW", "authorized"
