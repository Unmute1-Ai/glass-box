import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_manifest_preserves_authority_invariant():
    data = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    assert data['invariant'] == 'Model capability can change without changing principal authority.'

def test_no_invented_changes_for_covered_stories():
    data = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    changes = {x['story']: x['change'] for x in data['stories']}
    assert changes['Meta Muse cross-app autonomous agent'] == 'no change'
    assert changes['Quantinuum $100M CHIPS trapped-ion award'] == 'no change'

def test_external_effects_disabled():
    data = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    assert data['external_effects_executed'] is False

def test_funding_artifact_has_safety_boundary():
    text = (ROOT/'partners'/'FTA-ICAM-2026-U1-PARTNER-BRIEF.md').read_text()
    assert 'does not authorize submission, spending' in text
    assert 'physical actuation' in text
