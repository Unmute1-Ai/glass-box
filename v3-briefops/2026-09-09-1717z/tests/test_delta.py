import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from generated_asset_rights_gate import *
from deployment_region_admission import *

def test_required_license_attestation_fails_closed():
    a = GenerativeAssetAdmission("x", True, True, False, "educational", "educational", "PASS")
    assert admit_generated_asset(a)[0] == "DENY"

def test_scanner_cannot_substitute_for_rights_attestation():
    a = GenerativeAssetAdmission("x", True, True, False, "educational", "educational", "PASS")
    assert admit_generated_asset(a)[1] == "license_attestation_unverified"

def test_rights_scope_mismatch_fails_closed():
    a = GenerativeAssetAdmission("x", True, True, True, "personal", "commercial", None)
    assert admit_generated_asset(a)[0] == "DENY"

def test_content_rights_do_not_expand_authority():
    assert authority_delta_from_content_rights() == 0

def test_region_attestation_fails_closed_when_required():
    d = DeploymentRegionAdmission("model", True, False, "my-kul", frozenset({"my-kul"}), True, "PASS")
    assert admit_deployment_region(d)[0] == "DENY"

def test_unapproved_region_is_denied():
    d = DeploymentRegionAdmission("model", True, True, "my-kul", frozenset({"us-east"}), True, None)
    assert admit_deployment_region(d)[0] == "DENY"

def test_region_admission_has_zero_authority_lift():
    d = DeploymentRegionAdmission("model", True, True, "my-kul", frozenset({"my-kul"}), True, None)
    assert admit_deployment_region(d)[0] == "ADMIT"
    assert authority_delta_from_region_admission() == 0

def test_exactly_five_story_dispositions_and_no_external_effects():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    assert d["safety"]["destructive_or_external_effects_executed"] is False
