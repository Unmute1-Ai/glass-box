import asyncio
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from approval_store import SQLiteApprovalStore
from sentinel_control import Denied, Principal, authorize_execution
from test_sentinel_control import (AtomicNonceStore, MutableProposalStore,
    RecordingExecutor, StaticEvaluator, StaticPolicy, confirmation_for, make_proposal)


class HardeningTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'approvals.db'
        self.store = SQLiteApprovalStore(self.path)
        self.proposal = make_proposal()
        self.executor = RecordingExecutor()

    def issue(self):
        return self.store.issue(principal_id=self.proposal.principal_id,
                                proposal_digest=self.proposal.canonical_digest())

    async def consume(self, store, confirmation):
        return await store.consume_once(confirmation.nonce,
            principal_id=confirmation.principal_id,
            proposal_digest=confirmation.proposal_digest,
            expires_at=confirmation.expires_at)

    async def run_action(self, confirmation, *, evaluator=None, proposal_store=None,
                         nonce_store=None, **kwargs):
        return await authorize_execution(principal=Principal(self.proposal.principal_id),
            proposal_id=self.proposal.proposal_id, confirmation=confirmation,
            proposal_store=proposal_store or MutableProposalStore(self.proposal),
            policy_engine=StaticPolicy(), evaluator=evaluator or StaticEvaluator(
                {'verdict':'allow','risk':'low','findings':['reviewed']}),
            nonce_store=nonce_store or self.store, executor=self.executor, **kwargs)

    async def test_expiry_during_review_blocks_effect(self):
        start=datetime.now(timezone.utc)
        confirmation=replace(confirmation_for(self.proposal),expires_at=start+timedelta(seconds=1))
        class DelayedEvaluator:
            async def review(self, context):
                clock.return_value=start+timedelta(seconds=2)
                return {'verdict':'allow','risk':'low','findings':['reviewed']}
        with patch('sentinel_control._utcnow',return_value=start) as clock:
            with self.assertRaises(Denied) as error:
                await self.run_action(confirmation,evaluator=DelayedEvaluator(),nonce_store=AtomicNonceStore())
        self.assertEqual(error.exception.reason,'confirmation_expired')
        self.assertEqual(self.executor.effects,[])

    async def test_expiry_during_final_reload_blocks_effect(self):
        start=datetime.now(timezone.utc)
        confirmation=replace(confirmation_for(self.proposal),expires_at=start+timedelta(seconds=1))
        class SlowStore(MutableProposalStore):
            calls=0
            async def load_immutable(self, proposal_id):
                self.calls+=1
                if self.calls==2: clock.return_value=start+timedelta(seconds=2)
                return await super().load_immutable(proposal_id)
        with patch('sentinel_control._utcnow',return_value=start) as clock:
            with self.assertRaises(Denied) as error:
                await self.run_action(confirmation,proposal_store=SlowStore(self.proposal),nonce_store=AtomicNonceStore())
        self.assertEqual(error.exception.reason,'confirmation_expired')
        self.assertEqual(self.executor.effects,[])

    async def test_hung_evaluator_times_out_without_effect(self):
        class HungEvaluator:
            async def review(self, context): await asyncio.Event().wait()
        with self.assertRaises(Denied) as error:
            await asyncio.wait_for(self.run_action(self.issue(),evaluator=HungEvaluator(),
                                  review_timeout_seconds=0.01),timeout=1)
        self.assertEqual(error.exception.reason,'evaluator_timeout')
        self.assertEqual(self.executor.effects,[])

    async def test_unissued_confirmation_denied_end_to_end(self):
        with self.assertRaises(Denied) as error:
            await self.run_action(confirmation_for(self.proposal,nonce='unissued-'+'a'*40))
        self.assertEqual(error.exception.reason,'nonce_invalid_or_replayed')
        self.assertEqual(self.executor.effects,[])

    async def test_binding_tampering_does_not_consume_original(self):
        confirmation=self.issue()
        for changed in (replace(confirmation,principal_id='other'),
                        replace(confirmation,proposal_digest='sha256:'+'0'*64),
                        replace(confirmation,expires_at=confirmation.expires_at+timedelta(seconds=1))):
            self.assertFalse(await self.consume(self.store,changed))
        self.assertTrue(await self.consume(self.store,confirmation))

    async def test_concurrent_workers_and_restart_reject_replay(self):
        confirmation=self.issue()
        workers=[SQLiteApprovalStore(self.path) for _ in range(8)]
        results=await asyncio.gather(*(self.consume(worker,confirmation) for worker in workers))
        self.assertEqual(sum(results),1)
        self.assertFalse(await self.consume(SQLiteApprovalStore(self.path),confirmation))

    async def test_store_rechecks_expiry(self):
        confirmation=self.issue()
        with patch('approval_store.utcnow',return_value=confirmation.expires_at):
            self.assertFalse(await self.consume(self.store,confirmation))

    async def test_database_failure_denies_effect(self):
        confirmation=self.issue()
        with patch.object(self.store,'_connect',side_effect=__import__('sqlite3').OperationalError('offline')):
            with self.assertRaises(Denied): await self.run_action(confirmation)
        self.assertEqual(self.executor.effects,[])

    async def test_issued_approval_executes_once(self):
        confirmation=self.issue()
        await self.run_action(confirmation)
        with self.assertRaises(Denied): await self.run_action(confirmation)
        self.assertEqual(len(self.executor.effects),1)


if __name__=='__main__': unittest.main()
