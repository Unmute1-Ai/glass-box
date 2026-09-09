from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class OutboundWriteRequest:
    target: str
    target_registered: bool
    explicit_egress_authority: bool
    action_digest: str
    credential_scope: Optional[str]
    credential_single_use: bool
    credential_consumed: bool = False
    external_scanner_verdict: Optional[str] = None

def decide_outbound_write(req: OutboundWriteRequest):
    # Scanner/safety-agent verdicts are evidence only. They never authorize communication.
    if not req.target_registered:
        return "DENY", "unregistered_egress_target"
    if not req.explicit_egress_authority:
        return "DENY", "explicit_egress_authority_required"
    if req.credential_scope != req.action_digest:
        return "DENY", "credential_scope_mismatch"
    if not req.credential_single_use or req.credential_consumed:
        return "DENY", "fresh_single_use_credential_required"
    return "ALLOW", "authorized_outbound_write"

def authority_delta_from_agent_or_scanner() -> int:
    return 0
