import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())

def test_exactly_five_stories():
    assert len(data['stories']) == 5

def test_all_dispositions_are_no_change():
    assert all(x['disposition'] == 'no change' for x in data['stories'])

def test_authority_invariant():
    assert data['invariant'] == 'model capability can change without changing principal authority'

def test_safety_invariants():
    s = data['safety']
    assert s['external_scanner_results_advisory_only'] is True
    assert s['unverified_model_component_provenance_fails_closed'] is True
    assert s['sensitive_cross_domain_transition_requires_explicit_consent'] is True
    assert s['consequential_effect_requires_scoped_single_use_credential'] is True
    assert s['destructive_or_external_effects_executed'] is False
