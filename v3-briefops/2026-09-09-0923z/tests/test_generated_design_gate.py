import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from generated_design_gate import *

def good():
    return GeneratedDesignArtifact("jalapeno-design-sim","frontier-model-sim",True,True,True,True)

def test_model_generated_design_cannot_self_attest():
    a = GeneratedDesignArtifact("x","model",True,False,False,True)
    assert admit_generated_design(a).decision == "DENY"

def test_independent_review_is_mandatory():
    a = GeneratedDesignArtifact("x","model",True,True,False,True)
    assert admit_generated_design(a).reason == "independent_reviewer_verification_required"

def test_runtime_digest_still_fails_closed():
    a = GeneratedDesignArtifact("x","model",True,True,True,False)
    assert admit_generated_design(a).decision == "DENY"

def test_verified_generated_design_has_zero_authority_lift():
    assert admit_generated_design(good()).decision == "ADMIT"
    assert generated_artifact_authority_delta() == 0
