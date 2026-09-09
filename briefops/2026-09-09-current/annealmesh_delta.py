from dataclasses import dataclass

@dataclass(frozen=True)
class SovereignBackend:
    backend_id: str
    deployment_location: str
    customer_controlled: bool
    local_or_private_cloud: bool
    data_residency_assertion_verified: bool
    verified_security_certification: bool = False

def sovereign_routing_metadata(b: SovereignBackend) -> dict:
    return {
        "backend_id": b.backend_id,
        "deployment_location": b.deployment_location,
        "customer_controlled": b.customer_controlled,
        "local_or_private_cloud": b.local_or_private_cloud,
        "data_residency_assertion_verified": b.data_residency_assertion_verified,
        "verified_security_certification": b.verified_security_certification,
        "authority_delta": 0,
    }

@dataclass(frozen=True)
class QuantumBackend:
    backend_id: str
    medium: str
    isotope: str
    qubit_design: str
    predicted_error_reduction_factor: float | None
    device_built: bool
    peer_reviewed: bool
    verified_advantage: bool = False

def quantum_metadata(q: QuantumBackend) -> dict:
    return {
        "backend_id": q.backend_id,
        "medium": q.medium,
        "isotope": q.isotope,
        "qubit_design": q.qubit_design,
        "predicted_error_reduction_factor": q.predicted_error_reduction_factor,
        "device_built": q.device_built,
        "peer_reviewed": q.peer_reviewed,
        "verified_advantage": q.verified_advantage,
        "authority_delta": 0,
    }
