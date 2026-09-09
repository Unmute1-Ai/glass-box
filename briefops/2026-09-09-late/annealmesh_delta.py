from dataclasses import dataclass
@dataclass(frozen=True)
class QuantumBackendDescriptor:
    backend_id:str
    atom_species:str
    isotope:str|None
    trapping_method:str
    tunneling_speedup_claim:float|None
    maturity:str
    peer_reviewed:bool
    device_built:bool
    verified_advantage:bool=False
def quantum_metadata(q):
    return {"backend_id":q.backend_id,"atom_species":q.atom_species,"isotope":q.isotope,"trapping_method":q.trapping_method,"tunneling_speedup_claim":q.tunneling_speedup_claim,"maturity":q.maturity,"peer_reviewed":q.peer_reviewed,"device_built":q.device_built,"verified_advantage":q.verified_advantage,"authority_delta":0}
@dataclass(frozen=True)
class RoboticsCommercialEvidence:
    platform_id:str
    recurring_revenue_verified:bool
    unit_economics_verified:bool
    safety_evidence_verified:bool
    independent_certification:bool
    market_valuation_usd:float|None=None
def commercialization_scorecard(x):
    return {"platform_id":x.platform_id,"recurring_revenue_verified":x.recurring_revenue_verified,"unit_economics_verified":x.unit_economics_verified,"safety_evidence_verified":x.safety_evidence_verified,"independent_certification":x.independent_certification,"market_valuation_usd":x.market_valuation_usd,"authority_delta":0,"note":"valuation is never safety or authority evidence"}