"""Synthetic regression tests for delegated-identity and supply-chain abuse.
These tests exercise the reference policy gate only. No cloud, credentials, or production monitoring are contacted.
"""
import unittest
from agent_watchtower import ActionRequest, AgentWatchtower, WatchtowerPolicy

def gate():
    return AgentWatchtower(WatchtowerPolicy(
        version="delegated-identity-regression-1",
        allowed_actions=frozenset({"read", "send_message"}),
        allowed_resources=frozenset({"tenant-a:notes", "tenant-a:approved_contacts"}),
        allowed_scope=frozenset({"read:notes", "send:message"}),
        blocked_classifications=frozenset({"restricted", "secret"}),
        max_actions_per_session=10,
        human_approval_actions=frozenset({"send_message"}),
        require_correlation_id=True,
    ))

def request(**overrides):
    values = dict(agent_id="synthetic-agent", session_id="synthetic-session",
        action="read", resource="tenant-a:notes", requested_scope=("read:notes",),
        data_classification="internal", correlation_id="delegated-identity-test-001")
    values.update(overrides)
    return ActionRequest(**values)

class DelegatedIdentityTests(unittest.TestCase):
    def test_cross_tenant_resource_is_denied_before_effect(self):
        calls = []
        decision, result = gate().execute_if_permitted(request(resource="tenant-b:notes"),
            lambda: calls.append("cross-tenant-read"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "resource_not_allowlisted")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_privilege_escalation_is_denied_before_effect(self):
        calls = []
        decision, result = gate().execute_if_permitted(
            request(action="grant_admin_role", requested_scope=("admin:tenant",)),
            lambda: calls.append("grant-admin"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "action_not_allowlisted")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_credential_mutation_is_denied_before_effect(self):
        calls = []
        decision, result = gate().execute_if_permitted(
            request(action="rotate_or_export_credentials", requested_scope=("secrets:read",)),
            lambda: calls.append("credential-operation"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "action_not_allowlisted")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_monitor_disable_request_is_denied_before_effect(self):
        calls = []
        decision, result = gate().execute_if_permitted(request(action="disable_monitoring"),
            lambda: calls.append("disable-monitor"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "action_not_allowlisted")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_out_of_scope_attempts_are_audited(self):
        watchtower = gate()
        watchtower.authorize(request(resource="tenant-b:notes"))
        watchtower.authorize(request(action="change_service_principal",
            correlation_id="delegated-identity-test-002"))
        decisions = [r for r in watchtower.audit_records() if r.get("type") == "action_decision"]
        self.assertEqual(len(decisions), 2)
        self.assertTrue(all(not r["allowed"] for r in decisions))
        self.assertTrue(watchtower.verify_audit_chain())

    def test_denial_does_not_consume_authorized_action_budget(self):
        watchtower = gate()
        denied = watchtower.authorize(request(resource="tenant-b:notes"))
        allowed = watchtower.authorize(request(correlation_id="delegated-identity-test-003"))
        self.assertFalse(denied.allowed)
        self.assertTrue(allowed.allowed)

if __name__ == "__main__":
    unittest.main(verbosity=2)
