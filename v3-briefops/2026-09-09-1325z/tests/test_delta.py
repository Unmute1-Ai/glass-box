import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from model_lineage_admission import ModelLineageManifest, authority_delta_after_lineage_admission

def base(**kw):
    d = dict(
        model_id='m', issuer_verified=True, artifact_digest_verified=True,
        deployment_class_allowed=True, lineage_attestation_required=True,
        lineage_attestation_verified=True, upstream_model_family='frontier-family',
        training_method='distillation', external_scanner_verdict='PASS')
    d.update(kw)
    return ModelLineageManifest(**d)

def test_required_unverified_lineage_fails_closed():
    assert base(lineage_attestation_verified=False).admitted is False

def test_scanner_pass_does_not_override_lineage_failure():
    assert base(lineage_attestation_verified=False, external_scanner_verdict='PASS').admitted is False

def test_verified_lineage_has_zero_authority_lift():
    assert base().admitted is True
    assert authority_delta_after_lineage_admission() == 0

def test_exactly_five_story_dispositions():
    d = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    assert len(d['stories']) == 5

def test_no_external_effects():
    d = json.loads((ROOT/'docs'/'delta_manifest.json').read_text())
    assert d['safety']['external_effects_executed'] is False
