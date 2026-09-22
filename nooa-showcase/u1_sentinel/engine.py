from __future__ import annotations
from dataclasses import dataclass
import hashlib, json
from threading import Lock
from typing import Iterable
from .decision import Decision

@dataclass(frozen=True)
class SecurityContext:
    principal: str
    policy_digest: str
    environment: str = "production"
    tenant: str = "default"

def deterministic_policy_digest(policy: dict) -> str:
    payload=json.dumps(policy,sort_keys=True,separators=(",",":")).encode("utf-8")
    return hashlib.sha3_256(payload).hexdigest()

class U1Sentinel:
    def __init__(self, principal:str, policy_digest:str, *, environment:str="production", tenant:str="default", denied_actions:Iterable[str]|None=None):
        self.context=SecurityContext(principal,policy_digest,environment,tenant)
        self._denied_actions=frozenset(denied_actions or {"system_state_mutation"})
        self._decisions:list[Decision]=[]
        self._lock=Lock()
    @property
    def decisions(self)->tuple[Decision,...]: return tuple(self._decisions)
    def evaluate_authority(self, agent_id:str, requested_action:str)->Decision:
        if not agent_id or not requested_action: return self._record(False,"invalid_request",agent_id or "agent:unknown",requested_action or "unknown")
        denied=requested_action in self._denied_actions
        return self._record(not denied,"explicit_deny" if denied else "authorized",agent_id,requested_action)
    def _record(self, allowed:bool, reason:str, agent_id:str, action:str)->Decision:
        with self._lock:
            previous=self._decisions[-1].receipt_digest if self._decisions else "0"*64
            decision=Decision.create(allowed=allowed,reason=reason,principal=self.context.principal,action=action,policy_digest=self.context.policy_digest,agent_id=agent_id,sequence=len(self._decisions),previous_receipt_digest=previous)
            self._decisions.append(decision); return decision
