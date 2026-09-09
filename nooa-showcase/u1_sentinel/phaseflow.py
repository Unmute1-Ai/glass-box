from __future__ import annotations
from enum import Enum
from functools import wraps
from .engine import U1Sentinel

class Phase(str,Enum):
    WATER="WATER"; STEAM="STEAM"; ICE="ICE"

class PhaseFlowContainment:
    def __init__(self,sentinel:U1Sentinel,phase:Phase=Phase.WATER): self.sentinel=sentinel; self.phase=phase
    def set_phase(self,phase:Phase)->None: self.phase=phase
    def intercept(self,action_name:str):
        def decorator(func):
            @wraps(func)
            def wrapper(self_agent,*args,**kwargs):
                agent_identity=getattr(self_agent,"agent_id","agent:unknown")
                if self.phase is Phase.ICE and action_name != "read_telemetry":
                    d=self.sentinel._record(False,"ice_lockdown",agent_identity,action_name); raise PermissionError(f"DENY {d.reason} [Receipt: {d.receipt_digest[:12]}]")
                if self.phase is Phase.STEAM and action_name == "system_state_mutation" and not kwargs.pop("dual_custody",False):
                    d=self.sentinel._record(False,"dual_custody_required",agent_identity,action_name); raise PermissionError(f"DENY {d.reason} [Receipt: {d.receipt_digest[:12]}]")
                d=self.sentinel.evaluate_authority(agent_identity,action_name)
                if not d.allowed: raise PermissionError(f"DENY {d.reason} [Receipt: {d.receipt_digest[:12]}]")
                return func(self_agent,*args,**kwargs)
            return wrapper
        return decorator
