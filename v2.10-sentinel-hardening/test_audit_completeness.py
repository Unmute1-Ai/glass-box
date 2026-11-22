from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from audit_completeness import (
    VerificationError,
    merkle_root,
    validate_agent_oauth_grant,
    verify_completeness_statement,
)


def record(record_id, stamp, prev_hash, *, agent="agent:u1", session="session:1"):
    return {
        "record_id": record_id,
        "timestamp": stamp,
        "prev_hash": prev_hash,
        "agent_id": agent,
        "session_id": session,
        "action_type": "tool_call",
        "action_detail": {"tool_name": "synthetic", "parameters_hash": record_id},
    }


class CompletenessTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            record("r1", "2026-11-22T10:00:00Z", "0" * 64),
            record("r2", "2026-11-22T10:00:01Z", "1" * 64),
            record("r3", "2026-11-22T10:00:02Z", "2" * 64, agent="agent:other"),
        ]
        scoped = self.records[:2]
        self.statement = {
            "action_type": "lifecycle",
            "action_detail": {
                "event": "completeness_statement",
                "scope": {"agent_ids": ["agent:u1"], "session_ids": ["session:1"]},
                "as_of": "2026-11-22T10:01:00Z",
                "record_count": 2,
                "set_digest": merkle_root(scoped),
            },
        }

    def test_valid_scoped_statement(self):
        result = verify_completeness_statement(
            self.records, self.statement, verify_signature=lambda _: True
        )
        self.assertEqual(result["record_count"], 2)
        self.assertTrue(result["scope_count_verified"])

    def test_missing_record_is_detected_by_count(self):
        with self.assertRaisesRegex(VerificationError, "record_count_mismatch"):
            verify_completeness_statement(
                [self.records[0]], self.statement, verify_signature=lambda _: True
            )

    def test_changed_record_is_detected_by_digest(self):
        changed = [dict(self.records[0]), self.records[1]]
        changed[0]["action_detail"] = {"tool_name": "changed"}
        with self.assertRaisesRegex(VerificationError, "set_digest_mismatch"):
            verify_completeness_statement(
                changed, self.statement, verify_signature=lambda _: True
            )

    def test_out_of_scope_record_does_not_change_claim(self):
        result = verify_completeness_statement(
            [self.records[0], self.records[1], self.records[2]],
            self.statement,
            verify_signature=lambda _: True,
        )
        self.assertEqual(result["record_count"], 2)

    def test_record_after_as_of_is_out_of_scope(self):
        later = record("r4", "2026-11-22T10:02:00Z", "3" * 64)
        result = verify_completeness_statement(
            self.records + [later], self.statement, verify_signature=lambda _: True
        )
        self.assertEqual(result["record_count"], 2)

    def test_invalid_signature_fails_closed(self):
        with self.assertRaisesRegex(VerificationError, "statement_signature_invalid"):
            verify_completeness_statement(
                self.records, self.statement, verify_signature=lambda _: False
            )

    def test_merkle_root_changes_when_record_changes(self):
        altered = [dict(r) for r in self.records[:2]]
        altered[1]["action_detail"] = {"tool_name": "different"}
        self.assertNotEqual(merkle_root(self.records[:2]), merkle_root(altered))


class OAuthAgentGrantTests(unittest.TestCase):
    def setUp(self):
        self.grant = {
            "issuer": "https://github.com",
            "client_id": "u1-test-client",
            "principal_id": "user:tester",
            "scopes": ["repo:read"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
            "remote_session": False,
        }
        self.expected = dict(
            expected_issuer="https://github.com",
            expected_client_id="u1-test-client",
            principal_id="user:tester",
            allowed_scopes={"repo:read"},
        )

    def test_expected_grant_passes(self):
        validate_agent_oauth_grant(self.grant, **self.expected)

    def test_unexpected_client_fails(self):
        grant = dict(self.grant, client_id="attacker-client")
        with self.assertRaisesRegex(VerificationError, "oauth_client_mismatch"):
            validate_agent_oauth_grant(grant, **self.expected)

    def test_scope_escalation_fails(self):
        grant = dict(self.grant, scopes=["repo:read", "repo:write"])
        with self.assertRaisesRegex(VerificationError, "oauth_scope_escalation"):
            validate_agent_oauth_grant(grant, **self.expected)

    def test_principal_mismatch_fails(self):
        grant = dict(self.grant, principal_id="user:other")
        with self.assertRaisesRegex(VerificationError, "oauth_principal_mismatch"):
            validate_agent_oauth_grant(grant, **self.expected)

    def test_remote_session_requires_separate_approval(self):
        grant = dict(self.grant, remote_session=True)
        with self.assertRaisesRegex(VerificationError, "remote_session_not_separately_approved"):
            validate_agent_oauth_grant(grant, **self.expected)
        validate_agent_oauth_grant(
            grant, **self.expected, remote_session_approved=True
        )

    def test_wrong_issuer_fails(self):
        grant = dict(self.grant, issuer="https://attacker.example")
        with self.assertRaisesRegex(VerificationError, "oauth_issuer_mismatch"):
            validate_agent_oauth_grant(grant, **self.expected)


if __name__ == "__main__":
    unittest.main()
