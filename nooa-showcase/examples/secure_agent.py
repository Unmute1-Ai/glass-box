from u1_sentinel import PhaseFlowContainment,U1Sentinel
from agents.secured_nooa_agent import EnterpriseSecuredAgent

def main():
    sentinel=U1Sentinel("sys:enterprise-root","e40540c4cbed24986ce5ce3f5192cec29e27358d12516a532e64ffe1faa573ae"); flow=PhaseFlowContainment(sentinel); agent=EnterpriseSecuredAgent("agent:frontier",sentinel,flow)
    print(agent.read_telemetry())
    try: agent.execute_critical_operation("demo-only mutation")
    except PermissionError as exc: print(f"Intercepted by U1 Sentinel: {exc}")
if __name__=="__main__": main()
