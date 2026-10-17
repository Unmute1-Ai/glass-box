import unittest
from agent_watchtower import ActionRequest, AgentWatchtower, WatchtowerPolicy, policy_from_mapping

def setup_watchtower(**overrides):
    data = dict(version="test-1", allowed_actions=frozenset({"read","send_message"}),
      allowed_resources=frozenset({"local_notes","approved_contacts"}),
      allowed_scope=frozenset({"read:notes","send:message"}),
      blocked_classifications=frozenset({"restricted","secret"}), max_actions_per_session=2,
      human_approval_actions=frozenset({"send_message"}), require_correlation_id=True)
    data.update(overrides)
    return AgentWatchtower(WatchtowerPolicy(**data))

def req(**overrides):
    data = dict(agent_id="test-agent",session_id="s1",action="read",resource="local_notes",
      requested_scope=("read:notes",),data_classification="internal",correlation_id="trace-1")
    data.update(overrides)
    return ActionRequest(**data)

class WatchtowerTests(unittest.TestCase):
    def test_allowlist(self):
        self.assertTrue(setup_watchtower().authorize(req()).allowed)
    def test_unknown_action_denied(self):
        self.assertEqual(setup_watchtower().authorize(req(action="delete_all")).reason,"action_not_allowlisted")
    def test_scope_escalation_denied(self):
        self.assertEqual(setup_watchtower().authorize(req(requested_scope=("read:notes","admin:all"))).reason,"scope_exceeds_policy")
    def test_restricted_data_denied(self):
        self.assertEqual(setup_watchtower().authorize(req(data_classification="restricted")).reason,"data_classification_blocked")
    def test_human_approval_required(self):
        self.assertEqual(setup_watchtower().authorize(req(action="send_message",resource="approved_contacts",requested_scope=("send:message",))).reason,"human_approval_required")
    def test_kill_switch_blocks_effect(self):
        w=setup_watchtower(); w.engage_kill_switch(actor="operator",reason="unexpected behavior"); calls=[]
        decision,result=w.execute_if_permitted(req(),lambda:calls.append("effect"))
        self.assertFalse(decision.allowed); self.assertIsNone(result); self.assertEqual(calls,[])
    def test_effect_only_runs_after_permit(self):
        calls=[]; d,result=setup_watchtower().execute_if_permitted(req(),lambda:calls.append(1) or 7)
        self.assertTrue(d.allowed); self.assertEqual(result,7); self.assertEqual(calls,[1])
    def test_denied_effect_never_runs(self):
        calls=[]; d,result=setup_watchtower().execute_if_permitted(req(action="erase"),lambda:calls.append(1))
        self.assertFalse(d.allowed); self.assertIsNone(result); self.assertEqual(calls,[])
    def test_session_budget(self):
        w=setup_watchtower(); self.assertTrue(w.authorize(req()).allowed)
        self.assertTrue(w.authorize(req(correlation_id="trace-2")).allowed)
        self.assertEqual(w.authorize(req(correlation_id="trace-3")).reason,"session_action_limit_exceeded")
    def test_correlation_required(self):
        self.assertEqual(setup_watchtower().authorize(req(correlation_id="")).reason,"correlation_id_required")
    def test_audit_chain_tamper_detection(self):
        w=setup_watchtower(); w.authorize(req()); w.authorize(req(action="bad"))
        self.assertTrue(w.verify_audit_chain()); w._audit[0]["reason"]="rewritten"
        self.assertFalse(w.verify_audit_chain())
    def test_reset_requires_admin_authorization(self):
        w=setup_watchtower(); w.engage_kill_switch(actor="op",reason="test")
        with self.assertRaises(PermissionError): w.reset_kill_switch(actor="op",reason="reset",explicit_admin_authorized=False)
        w.reset_kill_switch(actor="admin",reason="reviewed",explicit_admin_authorized=True)
        self.assertFalse(w.kill_switch_engaged)
    def test_policy_rejects_unknown_fields(self):
        with self.assertRaises(ValueError):
            policy_from_mapping({"version":"p","allowed_actions":[],"allowed_resources":[],"allowed_scope":[],"authority_override":True})

if __name__ == "__main__": unittest.main(verbosity=2)
