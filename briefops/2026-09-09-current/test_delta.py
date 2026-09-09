from sentinel_delta import *
from research_gate import *
from annealmesh_delta import *
from transit_accessibility import *

NOW = 1788950000

def base():
    p=PrincipalPolicy("u",frozenset({"read","send"}),frozenset({"research","communications"}))
    m=ModelManifest("small",True,True,True)
    c=ComponentManifest("tool","x","x","safe")
    lease=AgentLease("l","u",frozenset({"research","communications"}),frozenset({"read","send"}),NOW+300)
    return p,m,c,lease

def test_model_substitution_zero_authority_lift():
    p,m,c,l=base()
    m2=ModelManifest("frontier-superagent",True,True,True,"advisory")
    e=Effect("research","research","read","read","d")
    assert authority_vector(p)==authority_vector(p)
    assert authorize(p,m,c,l,e,NOW)==authorize(p,m2,c,l,e,NOW)

def test_scanner_safe_cannot_override_digest_mismatch():
    p,m,c,l=base(); c=ComponentManifest("tool","x","tampered","safe")
    e=Effect("research","research","read","read","d")
    assert authorize(p,m,c,l,e,NOW).reason=="component_runtime_digest_mismatch"

def test_expired_background_agent_lease_denied():
    p,m,c,l=base()
    l=AgentLease("l","u",l.allowed_domains,l.allowed_capabilities,NOW-1)
    e=Effect("research","research","read","read","d")
    assert authorize(p,m,c,l,e,NOW).reason=="agent_lease_expired_or_revoked"

def test_cross_domain_sensitive_transition_requires_consent():
    p=PrincipalPolicy("u",frozenset({"read"}),frozenset({"research","health"}))
    m=ModelManifest("m",True,True,True); c=ComponentManifest("c","x","x")
    l=AgentLease("l","u",frozenset({"research","health"}),frozenset({"read"}),NOW+100)
    e=Effect("research","health","read","read","d")
    assert authorize(p,m,c,l,e,NOW).decision=="REQUIRE_CONSENT"

def test_consequential_effect_exact_scope_required():
    p,m,c,l=base()
    e=Effect("communications","communications","send","send_external","d","wrong",True,False)
    assert authorize(p,m,c,l,e,NOW).reason=="scoped_single_use_credential_required"

def test_credential_replay_denied():
    p,m,c,l=base()
    e=Effect("communications","communications","send","send_external","d","d",True,True)
    assert authorize(p,m,c,l,e,NOW).reason=="credential_invalid_or_replayed"

def test_formalized_claim_is_not_established():
    c=ResearchClaim("navier-stokes","FORMALIZED",True,0,False,False)
    assert evaluate_claim(c).decision=="ALLOW"
    assert model_may_self_promote_claim() is False

def test_established_claim_needs_independent_review_and_authority_acceptance():
    c=ResearchClaim("navier-stokes","ESTABLISHED",True,1,False,False)
    assert evaluate_claim(c).decision=="HOLD"
    c2=ResearchClaim("navier-stokes","ESTABLISHED",True,2,False,False)
    assert evaluate_claim(c2).reason=="external_authority_acceptance_missing"

def test_sovereignty_metadata_does_not_grant_authority():
    b=SovereignBackend("cylake-like","customer-dc",True,True,True,False)
    assert sovereign_routing_metadata(b)["authority_delta"]==0

def test_superfluid_qubit_concept_not_advantage():
    q=QuantumBackend("shoq","superfluid-helium","He-3","micromechanical-oscillator",100.0,False,True,False)
    d=quantum_metadata(q)
    assert d["device_built"] is False
    assert d["verified_advantage"] is False
    assert d["authority_delta"]==0

def test_transit_low_confidence_requires_human():
    assert validate_transit_intent(TransitIntent("identify_vehicle",.60,True)).decision=="REQUIRE_HUMAN"

def test_transit_unverified_provenance_denied():
    assert validate_transit_intent(TransitIntent("announce_stop",.95,False)).decision=="DENY"

def test_transit_payment_not_in_assistive_authority():
    assert validate_transit_intent(TransitIntent("pay_fare",.95,True)).decision=="DENY"

def test_raw_biometric_retention_denied():
    assert validate_transit_intent(TransitIntent("identify_vehicle",.95,True,True)).decision=="DENY"

def test_physical_action_without_simulation_denied():
    p=PrincipalPolicy("op",frozenset({"move"}),frozenset({"physical"}))
    m=ModelManifest("m",True,True,True); c=ComponentManifest("c","x","x")
    l=AgentLease("l","op",frozenset({"physical"}),frozenset({"move"}),NOW+100)
    e=Effect("physical","physical","move","actuate","d","d",True,False,False,False)
    assert authorize(p,m,c,l,e,NOW).reason=="verified_simulation_required"

def test_official_alert_without_authenticated_authority_denied():
    p=PrincipalPolicy("op",frozenset({"alert"}),frozenset({"emergency"}))
    m=ModelManifest("m",True,True,True); c=ComponentManifest("c","x","x")
    l=AgentLease("l","op",frozenset({"emergency"}),frozenset({"alert"}),NOW+100)
    e=Effect("emergency","emergency","alert","publish_official_alert","d","d",True,False,False,False)
    assert authorize(p,m,c,l,e,NOW).reason=="official_alert_requires_authenticated_authority"
