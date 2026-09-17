from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from sentinel_control import (
    Confirmation,
    Denied,
    ManualReviewRequired,
    PolicyDecision,
    Principal,
    Proposal,
    authorize_execution,
)


class MutableProposalStore:
    def __init__(self, proposal: Proposal):
        self.proposal = proposal

    async def load_immutable(self, proposal_id: str):
        if self.proposal.proposal_id != proposal_id:
            return None
        return self.proposal


class StaticPolicy:
    def __init__(self, allowed: bool = True):
        self.allowed = allowed
        self.calls = 0

    def evaluate(self, *, principal, proposal):
        self.calls += 1
        return PolicyDecision(
            allowed=self.allowed,
            reasons=() if self.allowed else ("scope_denied",),
            effective_permissions=("write:/srv/u1-sandbox/**",),
            resource_classification={
                resource: "sandbox" for resource in proposal.resources
            },
            version="sentinel-test-v1",
        )


class FlipPolicy(StaticPolicy):
    def evaluate(self, *, principal, proposal):
        self.calls += 1
        allowed = self.calls == 1
        return PolicyDecision(
            allowed=allowed,
            reasons=() if allowed else ("state_changed",),
            effective_permissions=("write:/srv/u1-sandbox/**",),
            resource_classification={
                resource: "sandbox" for resource in proposal.resources
            },
            version="sentinel-test-v1",
        )


class StaticEvaluator:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    async def review(self, context):
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class MutatingEvaluator(StaticEvaluator):
    def __init__(self, store, replacement):
        super().__init__(
            {"verdict": "allow", "risk": "low", "findings": ["no hidden hazard"]}
        )
        self.store = store
        self.replacement = replacement

    async def review(self, context):
        self.store.proposal = self.replacement
        return await super().review(context)


class AtomicNonceStore:
    def __init__(self):
        self._used = set()
        self._lock = asyncio.Lock()

    async def consume_once(
        self,
        nonce,
        *,
        principal_id,
        proposal_digest,
        expires_at,
    ):
        key = (nonce, principal_id, proposal_digest)
        async with self._lock:
            if key in self._used:
                return False
            self._used.add(key)
            return True


class RecordingExecutor:
    def __init__(self):
        self.effects = []

    async def execute(self, proposal):
        self.effects.append(proposal.canonical_dict())
        return {"status": "executed"}


def make_proposal():
    return Proposal(
        proposal_id="prop_123",
        principal_id="user:abc",
        kind="write",
        resources=("/srv/u1-sandbox/out.txt",),
        diff_digest="sha256:deadbeef",
        scope=("/srv/u1-sandbox/**",),
    )


def confirmation_for(proposal, *, nonce="nonce-1", offset_seconds=60):
    return Confirmation(
        principal_id=proposal.principal_id,
        proposal_digest=proposal.canonical_digest(),
        nonce=nonce,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=offset_seconds),
    )


class SentinelControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_model_allow_cannot_override_deterministic_deny(self):
        proposal = make_proposal()
        evaluator = StaticEvaluator(
            {"verdict": "allow", "risk": "low", "findings": ["model allows"]}
        )
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(False),
                evaluator=evaluator,
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "deterministic_policy_denied")
        self.assertEqual(evaluator.calls, 0)
        self.assertEqual(executor.effects, [])

    async def test_cross_principal_access_is_denied(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:attacker"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(True),
                evaluator=StaticEvaluator(
                    {"verdict": "allow", "risk": "low", "findings": ["ok"]}
                ),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "principal_mismatch")
        self.assertEqual(executor.effects, [])

    async def test_malformed_evaluator_output_fails_closed(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(True),
                evaluator=StaticEvaluator({"verdict": "allow"}),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "evaluator_failure")
        self.assertEqual(executor.effects, [])

    async def test_manual_review_never_executes(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        with self.assertRaises(ManualReviewRequired):
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(True),
                evaluator=StaticEvaluator(
                    {
                        "verdict": "manual_review",
                        "risk": "high",
                        "findings": ["human decision required"],
                    }
                ),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(executor.effects, [])

    async def test_expired_confirmation_is_denied(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal, offset_seconds=-1),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(True),
                evaluator=StaticEvaluator(
                    {"verdict": "allow", "risk": "low", "findings": ["ok"]}
                ),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "confirmation_expired")
        self.assertEqual(executor.effects, [])

    async def test_confirmation_digest_mismatch_is_denied(self):
        proposal = make_proposal()
        executor = RecordingExecutor()
        bad = Confirmation(
            principal_id=proposal.principal_id,
            proposal_digest="sha256:mutated",
            nonce="nonce-1",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
        )

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=bad,
                proposal_store=MutableProposalStore(proposal),
                policy_engine=StaticPolicy(True),
                evaluator=StaticEvaluator(
                    {"verdict": "allow", "risk": "low", "findings": ["ok"]}
                ),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "confirmation_digest_mismatch")
        self.assertEqual(executor.effects, [])

    async def test_proposal_mutation_after_review_is_denied(self):
        proposal = make_proposal()
        replacement = Proposal(
            proposal_id=proposal.proposal_id,
            principal_id=proposal.principal_id,
            kind="deploy",
            resources=("production",),
            diff_digest="sha256:mutated",
            scope=("/srv/u1-sandbox/**",),
        )
        store = MutableProposalStore(proposal)
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=store,
                policy_engine=StaticPolicy(True),
                evaluator=MutatingEvaluator(store, replacement),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "proposal_changed_before_execution")
        self.assertEqual(executor.effects, [])

    async def test_policy_change_before_effect_is_denied(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        with self.assertRaises(Denied) as ctx:
            await authorize_execution(
                principal=Principal("user:abc"),
                proposal_id=proposal.proposal_id,
                confirmation=confirmation_for(proposal),
                proposal_store=MutableProposalStore(proposal),
                policy_engine=FlipPolicy(),
                evaluator=StaticEvaluator(
                    {"verdict": "allow", "risk": "low", "findings": ["ok"]}
                ),
                nonce_store=AtomicNonceStore(),
                executor=executor,
            )

        self.assertEqual(ctx.exception.reason, "policy_changed_before_execution")
        self.assertEqual(executor.effects, [])

    async def test_concurrent_nonce_replay_allows_at_most_one_effect(self):
        proposal = make_proposal()
        store = MutableProposalStore(proposal)
        policy = StaticPolicy(True)
        evaluator = StaticEvaluator(
            {"verdict": "allow", "risk": "low", "findings": ["ok"]}
        )
        nonce_store = AtomicNonceStore()
        executor = RecordingExecutor()
        confirmation = confirmation_for(proposal, nonce="same-nonce")

        async def run_once():
            try:
                return await authorize_execution(
                    principal=Principal("user:abc"),
                    proposal_id=proposal.proposal_id,
                    confirmation=confirmation,
                    proposal_store=store,
                    policy_engine=policy,
                    evaluator=evaluator,
                    nonce_store=nonce_store,
                    executor=executor,
                )
            except Denied as exc:
                return exc

        results = await asyncio.gather(run_once(), run_once())

        self.assertEqual(len(executor.effects), 1)
        reasons = [
            result.reason for result in results if isinstance(result, Denied)
        ]
        self.assertEqual(reasons, ["nonce_invalid_or_replayed"])

    async def test_success_receipt_preserves_no_model_authority(self):
        proposal = make_proposal()
        executor = RecordingExecutor()

        receipt = await authorize_execution(
            principal=Principal("user:abc"),
            proposal_id=proposal.proposal_id,
            confirmation=confirmation_for(proposal),
            proposal_store=MutableProposalStore(proposal),
            policy_engine=StaticPolicy(True),
            evaluator=StaticEvaluator(
                {
                    "verdict": "allow",
                    "risk": "medium",
                    "findings": ["bounded action"],
                }
            ),
            nonce_store=AtomicNonceStore(),
            executor=executor,
        )

        self.assertEqual(receipt.evaluator_authority_effect, "none")
        self.assertEqual(len(executor.effects), 1)


if __name__ == "__main__":
    unittest.main()
