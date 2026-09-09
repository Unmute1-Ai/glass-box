from dataclasses import dataclass

@dataclass(frozen=True)
class DeploymentRegionAdmission:
    component_id: str
    region_attestation_required: bool
    region_attestation_verified: bool
    deployed_region: str
    allowed_regions: frozenset[str]
    component_provenance_verified: bool
    external_inspector_verdict: str | None = None

def admit_deployment_region(d: DeploymentRegionAdmission):
    if not d.component_provenance_verified:
        return "DENY", "component_provenance_unverified"
    if d.region_attestation_required and not d.region_attestation_verified:
        return "DENY", "region_attestation_unverified"
    if d.allowed_regions and d.deployed_region not in d.allowed_regions:
        return "DENY", "deployment_region_not_allowed"
    return "ADMIT", "region_policy_satisfied"

def authority_delta_from_region_admission() -> int:
    # Residency/location evidence constrains deployment but never expands principal authority.
    return 0
