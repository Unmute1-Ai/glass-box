from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class ContextSource:
    source_id: str
    provenance_verified: bool
    principal_scope: str
    requested_principal_scope: str
    freshness_verified: bool = True
    external_scanner_verdict: Optional[str] = None


def admit_context_source(source: ContextSource):
    # Context may improve reasoning, but it is not an authority-bearing credential.
    if not source.provenance_verified:
        return "DENY", "context_provenance_unverified"
    if not source.freshness_verified:
        return "DENY", "context_freshness_unverified"
    if source.principal_scope != source.requested_principal_scope:
        return "DENY", "context_scope_mismatch"
    return "ADMIT", "context_verified"


def authority_delta_from_context() -> int:
    return 0
