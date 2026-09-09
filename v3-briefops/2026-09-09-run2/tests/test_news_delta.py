import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from sentinel_news_delta import *
from accessibility_adapters import normalize

def P(consents=frozenset()): return Principal('u1',frozenset({'read','export','alert'}),frozenset({'email','health','external_publish','emergency'}),consents)
def V(**kw):
    x=dict(issuer_verified=True,artifact_digest_verified=True,deployment_class_allowed=True); x.update(kw); return Provenance(**x)
def C(**kw):
    x=dict(expected_digest='abc',runtime_digest='abc'); x.update(kw); return Component(**x)
def E(**kw):
    x=dict(source_domain='email',target_domain='email',capability='read',verb='read',action_digest='D'); x.update(kw); return Effect(**x)

def test_external_scanner_is_advisory_only(): assert decide(P(),V(issuer_verified=False,external_scanner_verdict='PASS'),C(external_scanner_verdict='PASS'),E())[0]=='DENY'
def test_supplier_identity_does_not_grant(): assert decide(P(),V(issuer_verified=False,supplier='Samsung',hardware_attestation='valid'),C(),E())[0]=='DENY'
def test_cross_domain_health_requires_consent(): assert decide(P(),V(),C(),E(target_domain='health'))[0]=='REQUIRE_CONSENT'
def test_credential_replay_fails():
    p=P(frozenset({('email','external_publish')})); e=E(target_domain='external_publish',capability='export',verb='export_sensitive_data',credential_scope='D',credential_single_use=True,credential_consumed=True); assert decide(p,V(),C(),e)[0]=='DENY'
def test_official_alert_requires_authenticated_authority():
    p=Principal('u1',frozenset({'alert'}),frozenset({'emergency'}),frozenset({('email','emergency')})); e=Effect('email','emergency','alert','publish_official_alert','A','A',True,False,False,False); assert decide(p,V(),C(),e)[0]=='DENY'
def test_model_supplier_swap_preserves_authority_vector():
    p=P(); a=V(supplier='OpenAI/Samsung'); b=V(supplier='Mistral/other'); assert a.admitted and b.admitted and authority_vector(p)==authority_vector(p)
def test_accessibility_visual_description_is_authority_neutral():
    x=normalize('visual_description','identify_object'); assert x['raw_sensor_retained'] is False and x['authority_granted'] is False

def test_unverified_component_fails_closed(): assert decide(P(),V(),C(runtime_digest='tampered'),E())[0]=='DENY'
