from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence


class Denied(RuntimeError):
    def __init__(self, reason: str, details: Sequence[str] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.details = tuple(details or ())


class ManualReviewRequired(RuntimeError):
    def __init__(self, findings: Sequence[str]):
        super().__init__("manual_review_required")
        self.findings = tuple(findings)


@dataclass(frozen=True)
class Principal:
    principal_id: str


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    principal_id: str
    kind: str
    resources: tuple[str, ...]
    diff_digest: str
    scope: tuple[str, ...]

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "principal_id": self.principal_id,
            "kind": self.kind,
            "resources": list(self.resources),
            "diff_digest": self.diff_digest,
            "scope": list(self.scope),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def canonical_digest(self) -> str:
        raw = self.canonical_json().encode("utf-8")
        return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Confirmation:
    principal_id: str
    proposal_digest: str
    nonce: str
    expires_at: datetime


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: tuple[str, ...]
    effective_permissions: tuple[str, ...]
    resource_classification: Mapping[str, str]
    version: str


@dataclass(frozen=True)
class EvaluationResult:
    verdict: str
    risk: str
    findings: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvaluationResult":
        required = {"verdict", "risk", "findings"}
        if set(value.keys()) != required:
            raise ValueError("evaluator_schema_mismatch")

        verdict = value["verdict"]
        risk = value["risk"]
        findings = value["findings"]

        if verdict not in {"allow", "deny", "manual_review"}:
            raise ValueError("unknown_evaluator_verdict")
        if risk not in {"low", "medium", "high", "critical"}:
            raise ValueError("unknown_evaluator_risk")
        if not isinstance(findings, list) or not all(
            isinstance(item, str) and item.strip() for item in findings
        ):
            raise ValueError("invalid_evaluator_findings")

        return cls(
            verdict=verdict,
            risk=risk,
            findings=tuple(findings),
        )


@dataclass(frozen=True)
class ExecutionReceipt:
    proposal_id: str
    proposal_digest: str
    principal_id: str
    policy_version: str
    evaluator_verdict: str
    evaluator_risk: str
    evaluator_findings: tuple[str, ...]
    evaluator_authority_effect: str
    result: Any


class ProposalStore(Protocol):
    async def load_immutable(self, proposal_id: str) -> Proposal | None:
        ...


class PolicyEngine(Protocol):
    def evaluate(self, *, principal: Principal, proposal: Proposal) -> PolicyDecision:
        ...


class Evaluator(Protocol):
    async def review(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class NonceStore(Protocol):
    async def consume_once(
        self,
        nonce: str,
        *,
        principal_id: str,
        proposal_digest: str,
        expires_at: datetime,
    ) -> bool:
        ...


class Executor(Protocol):
    async def execute(self, proposal: Proposal) -> Any:
        ...


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _verify_confirmation(
    confirmation: Confirmation,
    *,
    principal_id: str,
    proposal_digest: str,
    now: datetime,
) -> None:
    if confirmation.principal_id != principal_id:
        raise Denied("confirmation_principal_mismatch")
    if confirmation.proposal_digest != proposal_digest:
        raise Denied("confirmation_digest_mismatch")

    expiry = confirmation.expires_at
    if expiry.tzinfo is None:
        raise Denied("confirmation_expiry_not_timezone_aware")
    if expiry <= now:
        raise Denied("confirmation_expired")


async def authorize_execution(
    *,
    principal: Principal,
    proposal_id: str,
    confirmation: Confirmation,
    proposal_store: ProposalStore,
    policy_engine: PolicyEngine,
    evaluator: Evaluator,
    nonce_store: NonceStore,
    executor: Executor,
    now: datetime | None = None,
) -> ExecutionReceipt:
    """
    Hardened pre-effect authorization path.

    The caller supplies only an opaque proposal_id and a confirmation bound to
    the exact proposal digest. The action itself is loaded server-side.

    The evaluator is advisory. Its ALLOW can never lift deterministic DENY.
    """
    now = now or _utcnow()

    # 1. Load the server-side proposal. Caller-selected action bodies are absent.
    proposal = await proposal_store.load_immutable(proposal_id)
    if proposal is None:
        raise Denied("unknown_proposal")

    # 2. Bind the proposal to the authenticated principal.
    if proposal.principal_id != principal.principal_id:
        raise Denied("principal_mismatch")

    proposal_digest = proposal.canonical_digest()

    # 3. Deterministic policy is the first authority gate.
    policy = policy_engine.evaluate(principal=principal, proposal=proposal)
    if not policy.allowed:
        raise Denied("deterministic_policy_denied", policy.reasons)

    # 4. Advisory evaluator receives authoritative context, not authority.
    context = {
        "proposal": proposal.canonical_dict(),
        "proposal_digest": proposal_digest,
        "effective_permissions": list(policy.effective_permissions),
        "resource_classification": dict(policy.resource_classification),
        "policy_version": policy.version,
        "authority_effect": "none",
    }

    try:
        raw_review = await evaluator.review(context)
        review = EvaluationResult.from_mapping(raw_review)
    except ManualReviewRequired:
        raise
    except Exception as exc:
        raise Denied("evaluator_failure") from exc

    if review.verdict == "deny":
        raise Denied("independent_review_denied", review.findings)
    if review.verdict == "manual_review":
        raise ManualReviewRequired(review.findings)

    # 5. Confirmation must bind the authenticated principal and exact proposal.
    _verify_confirmation(
        confirmation,
        principal_id=principal.principal_id,
        proposal_digest=proposal_digest,
        now=now,
    )

    # 6. Consume the nonce atomically before any external effect.
    consumed = await nonce_store.consume_once(
        confirmation.nonce,
        principal_id=principal.principal_id,
        proposal_digest=proposal_digest,
        expires_at=confirmation.expires_at,
    )
    if not consumed:
        raise Denied("nonce_invalid_or_replayed")

    # 7. Reload to detect any proposal mutation between review and execution.
    final_proposal = await proposal_store.load_immutable(proposal_id)
    if final_proposal is None:
        raise Denied("proposal_disappeared_before_execution")
    if final_proposal.canonical_digest() != proposal_digest:
        raise Denied("proposal_changed_before_execution")

    # 8. Re-run deterministic policy immediately before effect.
    final_policy = policy_engine.evaluate(
        principal=principal,
        proposal=final_proposal,
    )
    if not final_policy.allowed:
        raise Denied("policy_changed_before_execution", final_policy.reasons)

    # 9. Only the immutable stored proposal reaches the executor.
    result = await executor.execute(final_proposal)

    return ExecutionReceipt(
        proposal_id=proposal_id,
        proposal_digest=proposal_digest,
        principal_id=principal.principal_id,
        policy_version=final_policy.version,
        evaluator_verdict=review.verdict,
        evaluator_risk=review.risk,
        evaluator_findings=review.findings,
        evaluator_authority_effect="none",
        result=result,
    )
