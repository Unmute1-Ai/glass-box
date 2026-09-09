from dataclasses import dataclass

@dataclass(frozen=True)
class GeneratedDesignArtifact:
    artifact_id: str
    generator_model_id: str
    artifact_digest_verified: bool
    independent_toolchain_verified: bool
    independent_reviewer_verified: bool
    component_runtime_digest_matches: bool

@dataclass(frozen=True)
class AdmissionDecision:
    decision: str
    reason: str

def admit_generated_design(a: GeneratedDesignArtifact) -> AdmissionDecision:
    """Model-generated hardware/software artifacts cannot self-attest into authority."""
    if not a.artifact_digest_verified:
        return AdmissionDecision("DENY", "generated_artifact_digest_unverified")
    if not a.independent_toolchain_verified:
        return AdmissionDecision("DENY", "independent_toolchain_verification_required")
    if not a.independent_reviewer_verified:
        return AdmissionDecision("DENY", "independent_reviewer_verification_required")
    if not a.component_runtime_digest_matches:
        return AdmissionDecision("DENY", "runtime_component_digest_mismatch")
    return AdmissionDecision("ADMIT", "independently_verified_generated_artifact")

def generated_artifact_authority_delta() -> int:
    return 0
