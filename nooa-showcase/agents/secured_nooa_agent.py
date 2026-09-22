from __future__ import annotations
try:
    from nooa import Agent
except ImportError:
    class Agent:
        def __init__(self,**_:object)->None: pass
from u1_sentinel import PhaseFlowContainment,U1Sentinel

class EnterpriseSecuredAgent(Agent):
    def __init__(self,agent_id:str,sentinel:U1Sentinel,phaseflow:PhaseFlowContainment,**kwargs):
        super().__init__(**kwargs); self.agent_id=agent_id; self._sentinel=sentinel; self._phaseflow=phaseflow; self.effect_counter=0
    def execute_critical_operation(self,payload:str,**kwargs)->str:
        d=self._sentinel.evaluate_authority(self.agent_id,"system_state_mutation")
        if not d.allowed: raise PermissionError(f"DENY {d.reason} [Receipt: {d.receipt_digest[:12]}]: Agent '{self.agent_id}' blocked under Principal '{d.principal}'.")
        self.effect_counter+=1; return f"Executed: {payload}"
    def read_telemetry(self)->str:
        d=self._sentinel.evaluate_authority(self.agent_id,"read_telemetry")
        if not d.allowed: raise PermissionError(f"DENY {d.reason}")
        return "telemetry:ok"
