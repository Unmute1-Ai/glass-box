import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from physical_effect_gate import *
from wearable_accessibility_adapter import *

def test_external_safety_agent_cannot_authorize_actuation():
    r=PhysicalEffectRequest("A","actuation",False,"A",True,False,"PASS")
    assert decide_physical_effect(r)[0]=="DENY"

def test_actuation_requires_action_bound_fresh_single_use_credential():
    r=PhysicalEffectRequest("A","actuation",True,"B",True,False)
    assert decide_physical_effect(r)[0]=="DENY"
    r2=PhysicalEffectRequest("A","actuation",True,"A",True,True)
    assert decide_physical_effect(r2)[0]=="DENY"

def test_simulation_is_allowed_without_actuation_authority():
    r=PhysicalEffectRequest("A","simulation")
    assert decide_physical_effect(r)==("ALLOW","simulation_only")

def test_model_or_safety_agent_has_zero_authority_delta():
    assert authority_delta_from_model_or_safety_agent()==0

def test_wearable_accessibility_skill_is_authority_neutral():
    s=WearableSkill("describe-scene",True,frozenset({"speech","haptic"}),False,False)
    assert admit_wearable_skill(s)[0]=="ADMIT"

def test_wearable_raw_sensor_retention_fails_closed():
    s=WearableSkill("describe-scene",True,frozenset({"speech"}),True,False)
    assert admit_wearable_skill(s)[0]=="DENY"

def test_quantum_descriptor_does_not_claim_advantage():
    d=json.loads((ROOT/"docs"/"annealmesh_ibm_protein.json").read_text())
    assert d["verified_quantum_advantage"] is False
    assert d["authority_effect"]=="none"

def test_exactly_five_story_dispositions_and_no_external_effects():
    d=json.loads((ROOT/"docs"/"delta_manifest.json").read_text())
    assert len(d["stories"])==5
    assert d["safety"]["external_physical_effects_executed"] is False
