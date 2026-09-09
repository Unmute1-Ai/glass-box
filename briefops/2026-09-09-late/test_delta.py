from sentinel_delta import *
from media_delta import *
from annealmesh_delta import *

def base():
    return PrincipalPolicy('u',frozenset({'read','release'}),frozenset({'research','release'})),ModelManifest('m',True,True,True),ComponentManifest('c','x','x','safe')

def test_model_substitution_zero_authority_lift():
    p,m,c=base(); stronger=ModelManifest('agent',True,True,True,True,'agent','run'); e=Effect('research','research','read','read','x','d'); assert authority_vector(p)==authority_vector(p) and authorize(p,m,c,e)==authorize(p,stronger,c,e)

def test_scanner_safe_is_advisory():
    p,m,c=base(); c=ComponentManifest('c','x','tampered','safe'); assert authorize(p,m,c,Effect('research','research','read','read','x','d')).decision=='DENY'

def test_generated_artifact_requires_review():
    p=PrincipalPolicy('u',frozenset({'release'}),frozenset({'research','release'}),frozenset({('research','release')})); m=ModelManifest('agent',True,True,True,True,'agent','run'); c=ComponentManifest('c','x','x'); e=Effect('research','release','release','release_artifact','a','d','d',True,False); assert authorize(p,m,c,e).reason=='independent_review_required_for_agent_generated_artifact'

def test_accessible_media_contract():
    assert admit_accessible_media(AccessibleMediaArtifact('a',True,True,'description','captions',True)).decision=='ALLOW'
    assert admit_accessible_media(AccessibleMediaArtifact('a',True,True,None,'captions',True)).decision=='DENY'

def test_helium3_does_not_imply_advantage():
    d=quantum_metadata(QuantumBackendDescriptor('he3','helium','He-3','optical_tweezers',3.0,'concept',True,False,False)); assert not d['verified_advantage'] and d['authority_delta']==0

def test_valuation_is_not_safety_evidence():
    d=commercialization_scorecard(RoboticsCommercialEvidence('humanoid',False,False,False,False,1e10)); assert not d['safety_evidence_verified'] and d['authority_delta']==0
