from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class GenerativeAssetAdmission:
    asset_id: str
    source_model_verified: bool
    license_attestation_required: bool
    license_attestation_verified: bool
    rights_scope: Optional[str]
    requested_use_scope: Optional[str]
    external_scanner_verdict: Optional[str] = None

def admit_generated_asset(a: GenerativeAssetAdmission):
    # Scanner/inspector verdicts are evidence only and never establish content rights.
    if not a.source_model_verified:
        return "DENY", "source_model_unverified"
    if a.license_attestation_required and not a.license_attestation_verified:
        return "DENY", "license_attestation_unverified"
    if a.rights_scope and a.requested_use_scope and a.rights_scope != a.requested_use_scope:
        return "DENY", "rights_scope_mismatch"
    return "ADMIT", "rights_and_provenance_verified"

def authority_delta_from_content_rights() -> int:
    # Content-rights admission governs permitted use of an artifact, not principal authority.
    return 0
