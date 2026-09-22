from __future__ import annotations
from typing import Iterable
from .decision import Decision

def verify_chain(decisions: Iterable[Decision]) -> bool:
    previous="0"*64
    for expected_sequence, decision in enumerate(decisions):
        if decision.sequence != expected_sequence or decision.previous_receipt_digest != previous: return False
        rebuilt=Decision.create(allowed=decision.allowed,reason=decision.reason,principal=decision.principal,action=decision.action,policy_digest=decision.policy_digest,agent_id=decision.agent_id,sequence=decision.sequence,previous_receipt_digest=decision.previous_receipt_digest)
        if rebuilt.receipt_digest != decision.receipt_digest: return False
        previous=decision.receipt_digest
    return True
