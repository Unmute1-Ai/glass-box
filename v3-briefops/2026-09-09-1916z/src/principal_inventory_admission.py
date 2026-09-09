from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PrincipalInventoryRecord:
    principal_id: str
    principal_kind: str  # human | agent | service
    identity_verified: bool
    owner_principal_id: Optional[str]
    authority_profile_id: Optional[str]
    discovered_by_external_scanner: bool = False

def admit_principal(record: PrincipalInventoryRecord):
    # Discovery is not authorization. A scanner may find an agent, but cannot mint its authority.
    if record.principal_kind not in {"human", "agent", "service"}:
        return "DENY", "unknown_principal_kind"
    if not record.identity_verified:
        return "DENY", "principal_identity_unverified"
    if record.principal_kind in {"agent", "service"}:
        if not record.owner_principal_id:
            return "DENY", "nonhuman_owner_required"
        if not record.authority_profile_id:
            return "DENY", "authority_profile_required"
    return "ADMIT", "principal_inventory_verified"

def authority_delta_from_discovery() -> int:
    return 0
