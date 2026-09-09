import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from financial_effect_gate import *

def req(**kw):
    d = dict(
        action_digest="txn:123",
        mode="transaction",
        authenticated_institution_authority=True,
        credential_scope="txn:123",
        credential_single_use=True,
        credential_consumed=False,
        source_model_provenance_verified=True,
        external_scanner_verdict="PASS",
    )
    d.update(kw)
    return FinancialEffectRequest(**d)

def test_financial_simulation_does_not_need_transaction_authority():
    r = FinancialEffectRequest(action_digest="x", mode="simulation")
    assert decide_financial_effect(r) == ("ALLOW", "simulation_only")

def test_scanner_pass_cannot_authorize_bank_transaction():
    r = req(authenticated_institution_authority=False, external_scanner_verdict="PASS")
    assert decide_financial_effect(r)[0] == "DENY"

def test_transaction_requires_action_bound_scope():
    assert decide_financial_effect(req(credential_scope="txn:other"))[0] == "DENY"

def test_transaction_requires_fresh_single_use_credential():
    assert decide_financial_effect(req(credential_single_use=False))[0] == "DENY"
    assert decide_financial_effect(req(credential_consumed=True))[0] == "DENY"

def test_unverified_model_provenance_fails_closed():
    assert decide_financial_effect(req(source_model_provenance_verified=False))[0] == "DENY"

def test_model_scanner_agent_authority_delta_is_zero():
    assert authority_delta_from_model_scanner_or_agent() == 0

def test_quantum_descriptor_does_not_claim_advantage():
    d = json.loads((ROOT / "docs" / "annealmesh_fujitsu_diamond_spin.json").read_text())
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"] == "none"

def test_exactly_five_story_dispositions_and_global_safety():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    s = d["safety"]
    assert s["external_scanner_or_inspector_advisory_only"] is True
    assert s["sensitive_cross_domain_requires_explicit_consent"] is True
    assert s["unverified_model_component_provenance_fails_closed"] is True
    assert s["consequential_effect_requires_scoped_single_use_credential"] is True
    assert s["financial_transactions_executed"] is False
    assert s["health_system_writes_executed"] is False
    assert s["physical_actuation_executed"] is False
    assert s["official_emergency_alerts_issued"] is False
    assert s["external_effects_executed"] is False
