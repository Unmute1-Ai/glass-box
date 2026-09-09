from u1_briefops.delta_policy import *

GOOD = ComponentEvidence(True, True, inspector_verdict='allow', registry_owner='nvidia/huggingface', hardware_vendor='samsung', hardware_attested=True)
GRANT = PrincipalGrant('user:matt', frozenset({'email','payments','child_profile'}), frozenset({'read','send','purchase','adapt'}))

def test_unverified_provenance_fails_closed_even_with_inspector_allow():
    bad = ComponentEvidence(False, True, inspector_verdict='allow')
    r = EffectRequest('user:matt','email','email','read')
    assert authorize(r, GRANT, bad)[0] == 'DENY'

def test_advisory_monitor_cannot_override_deny():
    assert external_monitor_can_override('DENY','allow') is False

def test_cross_domain_sensitive_requires_consent():
    r = EffectRequest('user:matt','email','payments','purchase',False,'payments:purchase',True,False)
    assert authorize(r, GRANT, GOOD)[0] == 'REQUIRE_CONSENT'

def test_sensitive_effect_requires_single_use_exact_scope():
    r = EffectRequest('user:matt','email','payments','purchase',True,'payments:read',True,False)
    assert authorize(r, GRANT, GOOD)[0] == 'DENY'

def test_single_use_credential_replay_denied():
    r = EffectRequest('user:matt','email','payments','purchase',True,'payments:purchase',True,True)
    assert authorize(r, GRANT, GOOD)[0] == 'DENY'

def test_child_profile_transition_requires_guardian_style_explicit_consent():
    r = EffectRequest('user:matt','email','child_profile','adapt',False,'child_profile:adapt',True,False)
    assert authorize(r, GRANT, GOOD)[0] == 'REQUIRE_CONSENT'

def test_registry_ownership_and_hardware_vendor_do_not_create_authority():
    no_scope = PrincipalGrant('user:matt', frozenset({'email'}), frozenset({'read'}))
    r = EffectRequest('user:matt','email','payments','purchase',True,'payments:purchase',True,False)
    assert authorize(r, no_scope, GOOD)[0] == 'DENY'

def test_model_substitution_does_not_change_authority_vector():
    reqs = [EffectRequest('user:matt','email','email','read'), EffectRequest('user:matt','email','payments','purchase',False,'payments:purchase',True,False), EffectRequest('user:matt','email','payments','purchase',True,'payments:purchase',True,False)]
    assert authority_vector_for_model('local-edge', reqs, GRANT, GOOD) == authority_vector_for_model('frontier-next', reqs, GRANT, GOOD)
