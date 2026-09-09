import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from principal_inventory_admission import *

def test_scanner_discovery_cannot_authorize_agent():
    r = PrincipalInventoryRecord("agent-1", "agent", True, None, None, True)
    assert admit_principal(r)[0] == "DENY"
    assert authority_delta_from_discovery() == 0

def test_nonhuman_principal_requires_owner_and_authority_profile():
    r1 = PrincipalInventoryRecord("agent-1", "agent", True, None, "profile-a", False)
    r2 = PrincipalInventoryRecord("agent-1", "agent", True, "human-1", None, False)
    assert admit_principal(r1)[0] == "DENY"
    assert admit_principal(r2)[0] == "DENY"

def test_verified_nonhuman_principal_is_inventory_admitted_only():
    r = PrincipalInventoryRecord("agent-1", "agent", True, "human-1", "profile-a", False)
    assert admit_principal(r)[0] == "ADMIT"
    assert authority_delta_from_discovery() == 0

def test_quantum_descriptor_does_not_claim_advantage():
    d = json.loads((ROOT / "docs" / "annealmesh_xanadu_asml.json").read_text())
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
