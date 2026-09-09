import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_exactly_five_stories():
    d = json.loads((ROOT / 'docs' / 'delta_manifest.json').read_text())
    assert len(d['stories']) == 5

def test_authority_invariant():
    d = json.loads((ROOT / 'docs' / 'delta_manifest.json').read_text())
    assert d['invariant'] == 'model capability can change without changing principal authority'

def test_global_safety_boundaries():
    s = json.loads((ROOT / 'docs' / 'delta_manifest.json').read_text())['safety']
    assert s['external_scanner_or_inspector_advisory_only'] is True
    assert s['sensitive_cross_domain_requires_explicit_consent'] is True
    assert s['unverified_model_component_provenance_fails_closed'] is True
    assert s['consequential_effect_requires_scoped_single_use_credential'] is True
    assert s['health_system_writes_executed'] is False
    assert s['physical_actuation_executed'] is False
    assert s['financial_transactions_executed'] is False
    assert s['official_emergency_alerts_issued'] is False
    assert s['external_effects_executed'] is False

def test_who_artifact_does_not_claim_regulatory_approval():
    t = (ROOT / 'partners' / 'WHO-GI-AI4H-2026.md').read_text()
    assert 'not regulatory approval' in t
    assert 'does not submit a model' in t

def test_moldova_artifact_preserves_health_and_physical_boundaries():
    t = (ROOT / 'partners' / 'UNDP-MOLDOVA-ASSISTIVE-TECH-2026.md').read_text()
    assert 'no physical or health-system effect' in t
