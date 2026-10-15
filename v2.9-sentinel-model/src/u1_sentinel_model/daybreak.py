from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .schema import Evaluation


Outcome = Literal["allow", "deny", "manual_review"]


@dataclass(frozen=True)
class ContinuitySnapshot:
    """Verified Daybreak recovery facts supplied by the trusted control plane.

    These flags are inputs, not proof by themselves. The caller must derive them
    from authenticated, current control-plane state and verified receipts.
    """

    deterministic_policy: str
    authority_graph_frozen: bool
    capability_grant_valid: bool
    clean_checkpoint_verified: bool
    receipt_chain_valid: bool
    continuity_plane_promoted: bool


@dataclass(frozen=True)
class DaybreakDecision:
    outcome: Outcome
    reasons: tuple[str, ...]
    authority: str = "deterministic control plane only; model output is advisory"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "u1/daybreak-pre-effect-decision/v1",
            "outcome": self.outcome,
            "reasons": list(self.reasons),
            "authority": self.authority,
        }


def evaluate_pre_effect(
    snapshot: ContinuitySnapshot,
    model_evaluation: Evaluation,
) -> DaybreakDecision:
    """Combine continuity invariants with a model advisory without granting authority.

    The model can veto with deny/manual_review, but cannot override deterministic
    denial or make an unhealthy continuity plane eligible for effects. This
    function does not execute tools, issue capabilities, or consume confirmations.
    """
    flags = (
        snapshot.authority_graph_frozen,
        snapshot.capability_grant_valid,
        snapshot.clean_checkpoint_verified,
        snapshot.receipt_chain_valid,
        snapshot.continuity_plane_promoted,
    )
    if any(type(flag) is not bool for flag in flags):
        return DaybreakDecision("deny", ("Continuity state contains a non-boolean flag.",))

    if snapshot.deterministic_policy == "deny":
        return DaybreakDecision("deny", ("Deterministic policy denied; model output cannot lift denial.",))
    if snapshot.deterministic_policy != "allow":
        return DaybreakDecision("deny", ("Deterministic policy state is missing or invalid.",))

    blocked: list[str] = []
    if snapshot.authority_graph_frozen:
        blocked.append("Authority graph is frozen.")
    if not snapshot.capability_grant_valid:
        blocked.append("Capability grant is absent, stale, or invalid.")
    if not snapshot.clean_checkpoint_verified:
        blocked.append("Clean recovery checkpoint is not verified.")
    if not snapshot.receipt_chain_valid:
        blocked.append("Evidence receipt chain is not valid.")
    if not snapshot.continuity_plane_promoted:
        blocked.append("Continuity plane has not been promoted.")
    if blocked:
        return DaybreakDecision("manual_review", tuple(blocked))

    if model_evaluation.verdict == "deny":
        return DaybreakDecision("deny", ("Model advisory veto: " + "; ".join(model_evaluation.findings),))
    if model_evaluation.verdict == "manual_review":
        return DaybreakDecision("manual_review", ("Model advisory requests review: " + "; ".join(model_evaluation.findings),))
    if model_evaluation.risk != "low":
        return DaybreakDecision("manual_review", ("Model allow is not low-risk; manual review required.",))

    return DaybreakDecision(
        "allow",
        ("Continuity invariants and deterministic policy passed; model advisory did not veto.",),
    )
