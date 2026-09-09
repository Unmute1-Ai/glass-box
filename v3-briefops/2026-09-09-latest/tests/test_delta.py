import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from capability_tier_admission import *

def good(**kw):
    d = dict(
        model_id="gpt-6-astra",
        issuer_verified=True,
        artifact_digest_verified=True,
        deployment_class_allowed=True,
        capability_tier="critical",
        enhanced_review_required=True,
        enhanced_review_verified=True,
        external_scanner_verdict="PASS"
    )
    d.update(kw)
    return CapabilityTierAdmission(**d)

def test_critical_model_review_fails_closed_when_required_but_missing():
    assert good(enhanced_review_verified=False).admitted is False

def test_scanner_pass_cannot_override_missing_enhanced_review():
    assert good(enhanced_review_verified=False, external_scanner_verdict="PASS").admitted is False

def test_higher_capability_has_zero_authority_lift():
    assert good().admitted is True
    assert authority_delta_after_capability_admission() == 0

def test_quantum_descriptor_does_not_claim_advantage():
    d = json.loads((ROOT/"docs"/"annealmesh_prxq_nanophotonic.json").read_text())
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"] == "none"

def test_exactly_five_story_dispositions():
    d = json.loads((ROOT/"docs"/"delta_manifest.json").read_text())
    assert len(d["stories"]) == 5

def test_global_safety_invariants():
    d = json.loads((ROOT/"docs"/"delta_manifest.json").read_text())
    s = d["safety"]
    assert s["scanner_or_inspector_is_authority_grant"] is False
    assert s["cross_domain_sensitive_transition_requires_explicit_consent"] is True
    assert s["unverified_model_component_provenance_fails_closed"] is True
    assert s["consequential_effect_requires_scoped_single_use_credential"] is True
    assert s["external_effects_executed"] is False
