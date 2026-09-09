import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from supply_chain_admission import *

def good(**overrides):
    data = dict(name='pkg', source_registry='pypi', expected_digest='abc', runtime_digest='abc', publisher_verified=True, build_provenance_verified=True, generated_or_modified_by_ai=True, external_scanner_verdict='PASS')
    data.update(overrides)
    return SupplyChainComponent(**data)

def test_scanner_pass_cannot_override_unverified_publisher():
    assert admit_supply_chain_component(good(publisher_verified=False)).decision == 'DENY'

def test_scanner_pass_cannot_override_missing_build_provenance():
    assert admit_supply_chain_component(good(build_provenance_verified=False)).decision == 'DENY'

def test_runtime_digest_mismatch_fails_closed():
    assert admit_supply_chain_component(good(runtime_digest='tampered')).reason == 'runtime_digest_mismatch'

def test_verified_ai_modified_component_has_zero_authority_lift():
    assert admit_supply_chain_component(good()).decision == 'ADMIT'
    assert authority_delta_after_admission() == 0

def test_neutral_atom_descriptor_does_not_claim_advantage():
    d = json.loads((ROOT/'docs'/'annealmesh_neutral_atom.json').read_text())
    assert d['verified_quantum_advantage'] is False
    assert d['authority_effect'] == 'none'

def test_exactly_five_story_dispositions():
    d = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    assert len(d['stories']) == 5
    assert d['external_effects_executed'] is False
