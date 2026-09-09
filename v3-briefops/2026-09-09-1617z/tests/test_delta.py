import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from egress_authority_gate import *
from research_claim_gate import *

def request(**kw):
    d = dict(
        target="https://approved.example/write",
        target_registered=True,
        explicit_egress_authority=True,
        action_digest="A",
        credential_scope="A",
        credential_single_use=True,
        credential_consumed=False,
        external_scanner_verdict="PASS",
    )
    d.update(kw)
    return OutboundWriteRequest(**d)

def test_scanner_pass_cannot_authorize_unregistered_egress():
    assert decide_outbound_write(request(target_registered=False))[0] == "DENY"

def test_outbound_write_requires_explicit_authority():
    assert decide_outbound_write(request(explicit_egress_authority=False))[0] == "DENY"

def test_outbound_write_requires_fresh_action_bound_credential():
    assert decide_outbound_write(request(credential_scope="B"))[0] == "DENY"
    assert decide_outbound_write(request(credential_consumed=True))[0] == "DENY"

def test_agent_or_scanner_has_zero_authority_delta():
    assert authority_delta_from_agent_or_scanner() == 0

def test_formal_research_artifact_is_not_claimed_independently_reproduced():
    a = ResearchClaimArtifact("ns", True, True, True, False)
    assert classify_research_claim(a)[0] == "CANDIDATE_VERIFIED_ARTIFACT"

def test_research_claim_authority_delta_zero():
    assert authority_delta_from_research_claim() == 0

def test_edge_hardware_candidate_requires_benchmark():
    d = json.loads((ROOT / "docs" / "edge_hardware_analog_alif.json").read_text())
    assert d["benchmark_required"] is True
    assert d["authority_effect"] == "none"

def test_quantum_descriptor_does_not_claim_advantage():
    d = json.loads((ROOT / "docs" / "annealmesh_ionq_superion.json").read_text())
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"] == "none"

def test_exactly_five_stories_and_no_external_effects():
    d = json.loads((ROOT / "docs" / "delta_manifest.json").read_text())
    assert len(d["stories"]) == 5
    assert d["safety"]["destructive_or_external_effects_executed"] is False
