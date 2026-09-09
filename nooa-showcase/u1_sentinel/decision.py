from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    principal: str
    action: str
    policy_digest: str
    agent_id: str
    receipt_digest: str

    @classmethod
    def create(cls, *, allowed: bool, reason: str, principal: str, action: str, policy_digest: str, agent_id: str) -> "Decision":
        payload = {
            "action": action,
            "agent_id": agent_id,
            "allowed": allowed,
            "policy_digest": policy_digest,
            "principal": principal,
            "reason": reason,
        }
        receipt = hashlib.sha3_256(canonical_json(payload)).hexdigest()
        return cls(receipt_digest=receipt, **payload)

    def to_dict(self) -> dict:
        return asdict(self)
