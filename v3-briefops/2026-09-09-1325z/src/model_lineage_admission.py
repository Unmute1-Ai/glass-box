from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class ModelLineageManifest:
    model_id: str
    issuer_verified: bool
    artifact_digest_verified: bool
    deployment_class_allowed: bool
    lineage_attestation_required: bool = False
    lineage_attestation_verified: bool = False
    upstream_model_family: Optional[str] = None
    training_method: Optional[str] = None
    external_scanner_verdict: Optional[str] = None

    @property
    def admitted(self) -> bool:
        if not (self.issuer_verified and self.artifact_digest_verified and self.deployment_class_allowed):
            return False
        if self.lineage_attestation_required and not self.lineage_attestation_verified:
            return False
        return True

def authority_delta_after_lineage_admission() -> int:
    # Provenance/lineage verification establishes admissibility, never principal authority.
    return 0
