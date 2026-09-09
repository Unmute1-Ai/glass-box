import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from crypto_horizon_policy import *

def test_unverified_crypto_provenance_fails_closed():
    p = CryptoPolicy("ecdsa", False, "allowed")
    assert admit_signature_algorithm(p)[0] == "DENY"

def test_vendor_quantum_claim_does_not_auto_ban_algorithm():
    p = CryptoPolicy("secp256k1", True, "allowed", False, True)
    assert admit_signature_algorithm(p)[0] == "ADMIT"

def test_policy_migrate_requires_pqc_transition_readiness():
    p = CryptoPolicy("legacy-ecc", True, "migrate", False, True)
    assert admit_signature_algorithm(p)[0] == "DENY"

def test_ready_migration_preserves_authority():
    p = CryptoPolicy("legacy-ecc", True, "migrate", True, True)
    assert admit_signature_algorithm(p)[0] == "ADMIT"
    assert authority_delta_from_crypto_migration() == 0

def test_exactly_five_stories_and_safety_invariants():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    s = d["safety"]
    assert s["external_scanner_or_inspector_advisory_only"] is True
    assert s["official_emergency_alert_requires_authenticated_authority_integration"] is True
    assert s["destructive_or_external_effects_executed"] is False
