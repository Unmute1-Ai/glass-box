from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PhysicalEffectRequest:
    action_digest: str
    mode: str  # simulation | proposal | actuation
    authenticated_hardware_authority: bool = False
    credential_scope: Optional[str] = None
    credential_single_use: bool = False
    credential_consumed: bool = False
    external_safety_agent_verdict: Optional[str] = None

def decide_physical_effect(req: PhysicalEffectRequest):
    if req.mode == "simulation":
        return "ALLOW", "simulation_only"
    if req.mode == "proposal":
        return "ALLOW", "proposal_only_no_actuation"
    if req.mode != "actuation":
        return "DENY", "unknown_effect_mode"
    if not req.authenticated_hardware_authority:
        return "DENY", "authenticated_hardware_authority_required"
    if req.credential_scope != req.action_digest:
        return "DENY", "credential_scope_mismatch"
    if not req.credential_single_use or req.credential_consumed:
        return "DENY", "fresh_single_use_credential_required"
    return "ALLOW", "authorized_actuation"

def authority_delta_from_model_or_safety_agent() -> int:
    return 0
