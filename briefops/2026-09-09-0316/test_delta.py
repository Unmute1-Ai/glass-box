import importlib.util, pathlib
P = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("s", P/"sentinel_delta.py")
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

def policy(consent=frozenset()):
    return s.PrincipalPolicy("p", frozenset({"read","export"}), frozenset({"email","health","identity"}), consent)

def model(**kw):
    base=dict(model_id="m",issuer_verified=True,artifact_digest_verified=True,deployment_class_allowed=True)
    base.update(kw); return s.ModelManifest(**base)

def comp(**kw):
    base=dict(component_id="c",expected_digest="abc",runtime_digest="abc")
    base.update(kw); return s.ComponentManifest(**base)

def effect(**kw):
    base=dict(source_domain="email",target_domain="email",capability="read",verb="read",resource="r",action_digest="d")
    base.update(kw); return s.Effect(**base)

def test_external_inspector_never_grants():
    d=s.authorize(policy(), model(issuer_verified=False, external_safety_report="pass"), comp(inspector_verdict="pass"), effect())
    assert d.reason=="unverified_model_provenance"

def test_shadow_agent_never_grants():
    d=s.authorize(policy(), model(), comp(expected_digest="a", runtime_digest="b", shadow_agent=True, inspector_verdict="pass"), effect())
    assert d.reason=="component_runtime_digest_mismatch"

def test_cross_domain_sensitive_requires_consent():
    d=s.authorize(policy(), model(), comp(), effect(target_domain="health"))
    assert d.decision=="REQUIRE_CONSENT"

def test_cross_domain_consent_allows_read():
    d=s.authorize(policy(frozenset({("email","health")})), model(), comp(), effect(target_domain="health"))
    assert d.decision=="ALLOW"

def test_consequential_requires_exact_single_use_credential():
    d=s.authorize(policy(), model(), comp(), effect(capability="export", verb="export_sensitive_data"))
    assert d.reason=="scoped_single_use_credential_required"

def test_replay_denied():
    d=s.authorize(policy(), model(), comp(), effect(capability="export", verb="export_sensitive_data", credential_scope="d",credential_single_use=True,credential_consumed=True))
    assert d.reason=="credential_invalid_or_replayed"

def test_registry_owner_is_not_authority():
    d=s.authorize(policy(), model(issuer_verified=False, registry_owner_verified=True, source_registry="major-vendor"), comp(), effect())
    assert d.decision=="DENY"

def test_model_substitution_preserves_authority_vector():
    p=policy()
    a=model(model_id="frontier-a"); b=model(model_id="frontier-b")
    assert a.admitted and b.admitted
    assert s.authority_vector(p)==s.authority_vector(p)
