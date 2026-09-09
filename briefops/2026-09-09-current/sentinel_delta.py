from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

SENSITIVE_DOMAINS = frozenset({"payments","health","smart_home","physical","emergency"})
CONSEQUENTIAL = frozenset({
    "send_payment","write_health_record","actuate",
    "publish_official_alert","delete","send_external"
})

@dataclass(frozen=True)
class ModelManifest:
    model_id: str
    issuer_verified: bool
    artifact_digest_verified: bool
    deployment_class_allowed: bool
    external_safety_report: str = "unknown"

    @property
    def admitted(self) -> bool:
        return (
            self.issuer_verified
            and self.artifact_digest_verified
            and self.deployment_class_allowed
        )

@dataclass(frozen=True)
class ComponentManifest:
    component_id: str
    expected_digest: str
    runtime_digest: str
    inspector_verdict: str = "unknown"

    @property
    def admitted(self) -> bool:
        return bool(self.expected_digest) and self.expected_digest == self.runtime_digest

@dataclass(frozen=True)
class PrincipalPolicy:
    principal_id: str
    capabilities: FrozenSet[str]
    domains: FrozenSet[str]
    consented_transitions: FrozenSet[Tuple[str,str]] = frozenset()

@dataclass(frozen=True)
class AgentLease:
    lease_id: str
    principal_id: str
    allowed_domains: FrozenSet[str]
    allowed_capabilities: FrozenSet[str]
    expires_unix: int
    revoked: bool = False

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
    official_authority_authenticated: bool = False
    physical_simulation_verified: bool = False

@dataclass(frozen=True)
class Decision:
    decision: str
    reason: str

def authority_vector(p: PrincipalPolicy) -> tuple:
    return (
        p.principal_id,
        tuple(sorted(p.capabilities)),
        tuple(sorted(p.domains)),
        tuple(sorted(p.consented_transitions)),
    )

def authorize(p, m, c, lease, effect, now_unix):
    if not m.admitted:
        return Decision("DENY","unverified_model_provenance")
    if not c.admitted:
        return Decision("DENY","component_runtime_digest_mismatch")
    if lease.revoked or lease.expires_unix <= now_unix:
        return Decision("DENY","agent_lease_expired_or_revoked")
    if lease.principal_id != p.principal_id:
        return Decision("DENY","lease_principal_mismatch")
    if effect.capability not in p.capabilities or effect.capability not in lease.allowed_capabilities:
        return Decision("DENY","capability_not_allowed")
    if effect.target_domain not in p.domains or effect.target_domain not in lease.allowed_domains:
        return Decision("DENY","domain_not_allowed")
    if (
        effect.source_domain != effect.target_domain
        and effect.target_domain in SENSITIVE_DOMAINS
        and (effect.source_domain,effect.target_domain) not in p.consented_transitions
    ):
        return Decision("REQUIRE_CONSENT","explicit_cross_domain_consent_required")
    if effect.verb in CONSEQUENTIAL:
        if effect.credential_scope != effect.action_digest:
            return Decision("DENY","scoped_single_use_credential_required")
        if not effect.credential_single_use or effect.credential_consumed:
            return Decision("DENY","credential_invalid_or_replayed")
    if effect.verb == "actuate" and not effect.physical_simulation_verified:
        return Decision("DENY","verified_simulation_required")
    if effect.verb == "publish_official_alert" and not effect.official_authority_authenticated:
        return Decision("DENY","official_alert_requires_authenticated_authority")
    return Decision("ALLOW","authorized")
