from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple
SENSITIVE=frozenset({"payments","health","physical","emergency","release","external_publish"})
CONSEQUENTIAL=frozenset({"send_payment","write_health_record","actuate","publish_official_alert","delete","publish_external","release_artifact"})
@dataclass(frozen=True)
class ModelManifest:
    model_id:str
    issuer_verified:bool
    artifact_digest_verified:bool
    deployment_class_allowed:bool
    generated_code:bool=False
    generator_model_id:Optional[str]=None
    generator_run_digest:Optional[str]=None
    external_safety_report:str="unknown"
    @property
    def admitted(self): return self.issuer_verified and self.artifact_digest_verified and self.deployment_class_allowed
@dataclass(frozen=True)
class ComponentManifest:
    component_id:str
    expected_digest:str
    runtime_digest:str
    inspector_verdict:str="unknown"
    @property
    def admitted(self): return bool(self.expected_digest) and self.expected_digest==self.runtime_digest
@dataclass(frozen=True)
class PrincipalPolicy:
    principal_id:str
    allowed_capabilities:FrozenSet[str]
    allowed_domains:FrozenSet[str]
    consented_transitions:FrozenSet[Tuple[str,str]]=frozenset()
@dataclass(frozen=True)
class Effect:
    source_domain:str
    target_domain:str
    capability:str
    verb:str
    resource:str
    action_digest:str
    credential_scope:Optional[str]=None
    credential_single_use:bool=False
    credential_consumed:bool=False
    independent_review_verified:bool=False
    official_authority_authenticated:bool=False
    physical_simulation_verified:bool=False
@dataclass(frozen=True)
class Decision:
    decision:str
    reason:str
def authority_vector(p): return (p.principal_id,tuple(sorted(p.allowed_capabilities)),tuple(sorted(p.allowed_domains)),tuple(sorted(p.consented_transitions)))
def authorize(p,m,c,e):
    if not m.admitted:return Decision("DENY","unverified_model_provenance")
    if not c.admitted:return Decision("DENY","component_runtime_digest_mismatch")
    if e.capability not in p.allowed_capabilities:return Decision("DENY","capability_not_allowed")
    if e.target_domain not in p.allowed_domains:return Decision("DENY","domain_not_allowed")
    if e.source_domain!=e.target_domain and e.target_domain in SENSITIVE and (e.source_domain,e.target_domain) not in p.consented_transitions:return Decision("REQUIRE_CONSENT","explicit_cross_domain_consent_required")
    if e.verb in CONSEQUENTIAL:
        if e.credential_scope!=e.action_digest:return Decision("DENY","scoped_single_use_credential_required")
        if not e.credential_single_use or e.credential_consumed:return Decision("DENY","credential_invalid_or_replayed")
    if e.verb=="release_artifact" and m.generated_code and not e.independent_review_verified:return Decision("DENY","independent_review_required_for_agent_generated_artifact")
    if e.verb=="actuate" and not e.physical_simulation_verified:return Decision("DENY","verified_simulation_required")
    if e.verb=="publish_official_alert" and not e.official_authority_authenticated:return Decision("DENY","official_alert_requires_authenticated_authority")
    return Decision("ALLOW","authorized")