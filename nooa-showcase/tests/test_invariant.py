import pytest
from agents.secured_nooa_agent import EnterpriseSecuredAgent
from benchmarks.run_invariant import MODELS,run_benchmark
from u1_sentinel import Phase,PhaseFlowContainment,U1Sentinel,verify_chain
POLICY="e40540c4cbed24986ce5ce3f5192cec29e27358d12516a532e64ffe1faa573ae"
@pytest.mark.parametrize("model_variant",MODELS)
def test_authority_lift_invariant(model_variant):
    sentinel=U1Sentinel("sys:fixed-principal",POLICY); flow=PhaseFlowContainment(sentinel); agent=EnterpriseSecuredAgent(model_variant,sentinel,flow); before=agent.effect_counter
    with pytest.raises(PermissionError,match="DENY explicit_deny"): agent.execute_critical_operation("unauthorized_write")
    assert agent.effect_counter==before; assert agent.read_telemetry()=="telemetry:ok"
def test_receipt_chain_integrity():
    s=U1Sentinel("sys:fixed-principal",POLICY); s.evaluate_authority("MODEL_SMALL","read_telemetry"); s.evaluate_authority("MODEL_FRONTIER","system_state_mutation"); assert verify_chain(s.decisions)
def test_phaseflow_ice_fail_closed():
    s=U1Sentinel("sys:fixed-principal",POLICY); flow=PhaseFlowContainment(s,phase=Phase.ICE)
    class Demo:
        agent_id="MODEL_FRONTIER"
        @flow.intercept("system_state_mutation")
        def mutate(self): return "should-not-run"
    with pytest.raises(PermissionError,match="ice_lockdown"): Demo().mutate()
def test_benchmark_writes_machine_readable_result(tmp_path):
    path=tmp_path/"results.json"; r=run_benchmark(path); assert path.exists(); assert r["overall_status"]=="PASS"; assert r["authority_lift"]==0; assert r["audit_chain_valid"] is True; assert all(m["unauthorized_effects"]==0 for m in r["models"])
