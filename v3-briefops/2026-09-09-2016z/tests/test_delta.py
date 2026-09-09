import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from context_source_admission import ContextSource, admit_context_source, authority_delta_from_context
from primer_school_ai_policy import SchoolAIRequest, decide_school_ai_request, authority_delta_from_school_policy


def test_context_provenance_fails_closed_even_with_scanner_pass():
    c = ContextSource("ctx", False, "student-1", "student-1", True, "PASS")
    assert admit_context_source(c)[0] == "DENY"


def test_context_scope_mismatch_fails_closed():
    c = ContextSource("ctx", True, "student-1", "student-2", True, None)
    assert admit_context_source(c)[0] == "DENY"


def test_context_has_zero_authority_lift():
    c = ContextSource("ctx", True, "student-1", "student-1", True, None)
    assert admit_context_source(c)[0] == "ADMIT"
    assert authority_delta_from_context() == 0


def test_school_data_cannot_train_model():
    r = SchoolAIRequest("student", True, False, False, True, False, True)
    assert decide_school_ai_request(r) == ("DENY", "school_data_training_use_disallowed")


def test_school_tracking_and_social_companion_are_denied():
    tracking = SchoolAIRequest("student", False, True, False, True, False, True)
    companion = SchoolAIRequest("student", False, False, False, True, True, True)
    assert decide_school_ai_request(tracking)[0] == "DENY"
    assert decide_school_ai_request(companion)[0] == "DENY"


def test_high_impact_school_decision_requires_human_oversight():
    r = SchoolAIRequest("student", False, False, True, False, False, True)
    assert decide_school_ai_request(r) == ("DENY", "human_oversight_required")


def test_school_policy_has_zero_authority_lift():
    r = SchoolAIRequest("educator", False, False, False, True, False, True)
    assert decide_school_ai_request(r)[0] == "ALLOW"
    assert authority_delta_from_school_policy() == 0


def test_quantum_security_descriptor_is_evidence_not_authority():
    d = json.loads((ROOT / "docs" / "annealmesh_ionq_quantum_safe_deployment.json").read_text())
    assert d["automatic_crypto_policy_change"] is False
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"] == "none"


def test_exactly_five_stories_and_global_invariants():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    assert d["invariant"] == "model capability can change without changing principal authority"
    s = d["safety"]
    assert s["external_scanner_or_inspector_advisory_only"] is True
    assert s["sensitive_cross_domain_requires_explicit_consent"] is True
    assert s["unverified_model_component_provenance_fails_closed"] is True
    assert s["consequential_effect_requires_scoped_single_use_credential"] is True
    assert s["destructive_or_external_effects_executed"] is False
