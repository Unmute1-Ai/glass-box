from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    principal: str
    action: str
    policy_digest: str
    agent_id: str
    sequence: int
    previous_receipt_digest: str
    receipt_digest: str

    @classmethod
    def create(cls, *, allowed: bool, reason: str, principal: str, action: str, policy_digest: str, agent_id: str, sequence: int, previous_receipt_digest: str) -> "Decision":
        unsigned = {"allowed": allowed, "reason": reason, "principal": principal, "action": action, "policy_digest": policy_digest, "agent_id": agent_id, "sequence": sequence, "previous_receipt_digest": previous_receipt_digest}
        receipt_digest = hashlib.sha3_256(canonical_json(unsigned)).hexdigest()
        return cls(**unsigned, receipt_digest=receipt_digest)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
