import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cross_domain_capability_gate import *

def req(**kw):
    d = dict(principal_id="human-1", from_domain="email", to_domain="payments", explicit_consent=True, component_provenance_verified=True, action_digest="pay:invoice:123", credential_scope="pay:invoice:123", credential_domain="payments", credential_single_use=True, credential_consumed=False, external_safety_agent_verdict="PASS")
    d.update(kw)
    return DomainTransitionRequest(**d)

def test_sensitive_cross_domain_requires_explicit_consent():
    assert decide_domain_transition(req(explicit_consent=False))[0] == "DENY"

def test_credential_is_destination_domain_bound():
    assert decide_domain_transition(req(credential_domain="health"))[0] == "DENY"

def test_credential_is_exact_action_bound_and_single_use():
    assert decide_domain_transition(req(credential_scope="pay:other"))[0] == "DENY"
    assert decide_domain_transition(req(credential_consumed=True))[0] == "DENY"

def test_safety_agent_pass_does_not_replace_consent():
    assert decide_domain_transition(req(explicit_consent=False, external_safety_agent_verdict="PASS"))[0] == "DENY"

def test_unverified_component_provenance_fails_closed():
    assert decide_domain_transition(req(component_provenance_verified=False))[0] == "DENY"

def test_authorized_transition_has_zero_model_authority_lift():
    assert decide_domain_transition(req())[0] == "ALLOW"
    assert authority_delta_from_model_or_safety_agent() == 0

def test_quantum_descriptor_is_blueprint_not_advantage():
    d = json.loads((ROOT / "docs" / "annealmesh_helium3.json").read_text())
    assert d["reported_evidence"]["prototype_built"] is False
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"] == "none"

def test_exactly_five_stories_and_global_safety():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    s = d["safety"]
    assert s["external_scanner_or_inspector_advisory_only"] is True
    assert s["sensitive_cross_domain_requires_explicit_consent"] is True
    assert s["unverified_model_component_provenance_fails_closed"] is True
    assert s["consequential_effect_requires_scoped_single_use_credential"] is True
    assert s["external_effects_executed"] is False
