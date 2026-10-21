"""U1 Agent Watchtower: deterministic pre-effect policy gate and hash-chained audit."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class ActionRequest:
    agent_id: str
    session_id: str
    action: str
    resource: str
    requested_scope: tuple[str, ...] = ()
    data_classification: str = "public"
    requires_human_approval: bool = False
    human_approval_token: str | None = None
    correlation_id: str = ""

@dataclass(frozen=True)
class WatchtowerPolicy:
    version: str
    allowed_actions: frozenset[str]
    allowed_resources: frozenset[str]
    allowed_scope: frozenset[str]
    blocked_classifications: frozenset[str] = frozenset({"restricted", "secret"})
    max_actions_per_session: int = 100
    human_approval_actions: frozenset[str] = frozenset()
    require_correlation_id: bool = True

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy_version: str
    event_hash: str
    audit_sequence: int

class AgentWatchtower:
    """In-memory reference gate. Production needs shared transactional state and signed checkpoints."""
    def __init__(self, policy: WatchtowerPolicy):
        if not policy.version.strip(): raise ValueError("policy_version_required")
        if policy.max_actions_per_session < 1: raise ValueError("max_actions_per_session_must_be_positive")
        self.policy = policy
        self._kill_switch = False
        self._session_counts: dict[str, int] = {}
        self._audit: list[dict[str, Any]] = []
        self._last_hash = "0" * 64

    @property
    def kill_switch_engaged(self) -> bool:
        return self._kill_switch

    def engage_kill_switch(self, *, actor: str, reason: str) -> None:
        if not actor.strip() or not reason.strip(): raise ValueError("kill_switch_actor_and_reason_required")
        self._kill_switch = True
        self._append({"type":"kill_switch","engaged":True,"actor":actor,"reason":reason,"timestamp":now_utc()})

    def reset_kill_switch(self, *, actor: str, reason: str, explicit_admin_authorized: bool) -> None:
        if not explicit_admin_authorized: raise PermissionError("explicit_admin_authorization_required")
        if not actor.strip() or not reason.strip(): raise ValueError("kill_switch_reset_actor_and_reason_required")
        self._kill_switch = False
        self._append({"type":"kill_switch","engaged":False,"actor":actor,"reason":reason,"timestamp":now_utc()})

    def authorize(self, request: ActionRequest) -> Decision:
        count = self._session_counts.get(request.session_id, 0)
        reason = self._deny_reason(request, count)
        allowed = reason == "allowed"
        if allowed: self._session_counts[request.session_id] = count + 1
        record = {"type":"action_decision","timestamp":now_utc(),"agent_id":request.agent_id,
          "session_id":request.session_id,"action":request.action,"resource":request.resource,
          "requested_scope":sorted(request.requested_scope),"data_classification":request.data_classification,
          "correlation_id":request.correlation_id,"allowed":allowed,"reason":reason,
          "policy_version":self.policy.version,"authority_source":"deterministic_policy"}
        digest = self._append(record)
        return Decision(allowed, reason, self.policy.version, digest, len(self._audit))

    def execute_if_permitted(self, request: ActionRequest, effect: Callable[[], Any]) -> tuple[Decision, Any | None]:
        decision = self.authorize(request)
        if not decision.allowed: return decision, None
        try: result = effect()
        except Exception as exc:
            self._append({"type":"effect_error","timestamp":now_utc(),"correlation_id":request.correlation_id,
                          "error_type":type(exc).__name__,"message":"effect_failed"})
            raise
        self._append({"type":"effect_completed","timestamp":now_utc(),"correlation_id":request.correlation_id,
                      "decision_hash":decision.event_hash})
        return decision, result

    def _deny_reason(self, r: ActionRequest, count: int) -> str:
        if self._kill_switch: return "kill_switch_engaged"
        if not r.agent_id.strip() or not r.session_id.strip(): return "missing_agent_or_session"
        if self.policy.require_correlation_id and not r.correlation_id.strip(): return "correlation_id_required"
        if r.action not in self.policy.allowed_actions: return "action_not_allowlisted"
        if r.resource not in self.policy.allowed_resources: return "resource_not_allowlisted"
        if not set(r.requested_scope).issubset(self.policy.allowed_scope): return "scope_exceeds_policy"
        if r.data_classification in self.policy.blocked_classifications: return "data_classification_blocked"
        if (r.action in self.policy.human_approval_actions or r.requires_human_approval) and not r.human_approval_token:
            return "human_approval_required"
        if count >= self.policy.max_actions_per_session: return "session_action_limit_exceeded"
        return "allowed"

    def _append(self, record: Mapping[str, Any]) -> str:
        body = dict(record)
        body["sequence"] = len(self._audit) + 1
        body["previous_hash"] = self._last_hash
        digest = hashlib.sha256(canonical(body)).hexdigest()
        body["hash"] = digest
        self._audit.append(body)
        self._last_hash = digest
        return digest

    def audit_records(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._audit]

    def verify_audit_chain(self) -> bool:
        previous = "0" * 64
        for sequence, stored in enumerate(self._audit, 1):
            row = dict(stored); digest = row.pop("hash", None)
            if row.get("sequence") != sequence or row.get("previous_hash") != previous: return False
            if hashlib.sha256(canonical(row)).hexdigest() != digest: return False
            previous = digest
        return previous == self._last_hash

    def export_audit_jsonl(self) -> str:
        return "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in self._audit)

def policy_from_mapping(raw: Mapping[str, Any]) -> WatchtowerPolicy:
    allowed = {"version","allowed_actions","allowed_resources","allowed_scope","blocked_classifications",
               "max_actions_per_session","human_approval_actions","require_correlation_id"}
    if set(raw) - allowed: raise ValueError("unknown_policy_fields")
    if not {"version","allowed_actions","allowed_resources","allowed_scope"}.issubset(raw):
        raise ValueError("missing_policy_fields")
    for key in ("allowed_actions","allowed_resources","allowed_scope"):
        if not isinstance(raw[key], list) or not all(isinstance(v,str) and v for v in raw[key]):
            raise ValueError(f"invalid_{key}")
    return WatchtowerPolicy(version=str(raw["version"]),allowed_actions=frozenset(raw["allowed_actions"]),
      allowed_resources=frozenset(raw["allowed_resources"]),allowed_scope=frozenset(raw["allowed_scope"]),
      blocked_classifications=frozenset(raw.get("blocked_classifications",["restricted","secret"])),
      max_actions_per_session=int(raw.get("max_actions_per_session",100)),
      human_approval_actions=frozenset(raw.get("human_approval_actions",[])),
      require_correlation_id=bool(raw.get("require_correlation_id",True)))
