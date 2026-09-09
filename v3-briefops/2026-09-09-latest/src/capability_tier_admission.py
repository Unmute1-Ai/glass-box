from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class CapabilityTierAdmission:
    model_id: str
    issuer_verified: bool
    artifact_digest_verified: bool
    deployment_class_allowed: bool
    capability_tier: str
    enhanced_review_required: bool = False
    enhanced_review_verified: bool = False
    external_scanner_verdict: Optional[str] = None

    @property
    def admitted(self) -> bool:
        if not (self.issuer_verified and self.artifact_digest_verified and self.deployment_class_allowed):
            return False
        if self.enhanced_review_required and not self.enhanced_review_verified:
            return False
        return True

def authority_delta_after_capability_admission() -> int:
    # Higher model capability may change review requirements, never principal authority.
    return 0
