"""PQC adapter surface. Does not claim FIPS validation by itself."""
from dataclasses import dataclass
@dataclass(frozen=True)
class PQCProviderStatus:
    provider:str; fips_203:bool; fips_204:bool; fips_205:bool; note:str

def provider_status()->PQCProviderStatus:
    return PQCProviderStatus("unconfigured",False,False,False,"Wire to a validated/approved PQC provider before making compliance claims.")
