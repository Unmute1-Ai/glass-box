from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class FinancialEffectRequest:
    action_digest: str
    mode: str  # simulation | proposal | transaction
    authenticated_institution_authority: bool = False
    credential_scope: Optional[str] = None
    credential_single_use: bool = False
    credential_consumed: bool = False
    source_model_provenance_verified: bool = True
    external_scanner_verdict: Optional[str] = None

def decide_financial_effect(req: FinancialEffectRequest):
    # External scanners, fraud models, or safety agents provide evidence only.
    # They never authorize movement of money.
    if not req.source_model_provenance_verified:
        return "DENY", "model_provenance_unverified"

    if req.mode == "simulation":
        return "ALLOW", "simulation_only"
    if req.mode == "proposal":
        return "ALLOW", "proposal_only_no_transaction"
    if req.mode != "transaction":
        return "DENY", "unknown_financial_effect_mode"

    if not req.authenticated_institution_authority:
        return "DENY", "authenticated_institution_authority_required"
    if req.credential_scope != req.action_digest:
        return "DENY", "credential_scope_mismatch"
    if not req.credential_single_use or req.credential_consumed:
        return "DENY", "fresh_single_use_credential_required"

    return "ALLOW", "authorized_financial_transaction"

def authority_delta_from_model_scanner_or_agent() -> int:
    return 0
