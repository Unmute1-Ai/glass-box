import unittest

from u1_sentinel_model.daybreak import ContinuitySnapshot, evaluate_pre_effect
from u1_sentinel_model.schema import Evaluation


def healthy(**overrides):
    values = dict(
        deterministic_policy="allow",
        authority_graph_frozen=False,
        capability_grant_valid=True,
        clean_checkpoint_verified=True,
        receipt_chain_valid=True,
        continuity_plane_promoted=True,
    )
    values.update(overrides)
    return ContinuitySnapshot(**values)


ALLOW = Evaluation("allow", "low", ("No policy-boundary hazard detected.",))
DENY = Evaluation("deny", "critical", ("Protected resource boundary violation.",))
REVIEW = Evaluation("manual_review", "high", ("Ambiguous authorization context.",))


class DaybreakAdapterTests(unittest.TestCase):
    def test_healthy_plane_and_low_risk_advisory_allow(self):
        result = evaluate_pre_effect(healthy(), ALLOW)
        self.assertEqual(result.outcome, "allow")
        self.assertIn("model output is advisory", result.authority)

    def test_deterministic_deny_cannot_be_overridden_by_model_allow(self):
        result = evaluate_pre_effect(healthy(deterministic_policy="deny"), ALLOW)
        self.assertEqual(result.outcome, "deny")
        self.assertIn("cannot lift denial", result.reasons[0])

    def test_frozen_authority_graph_blocks_effects(self):
        result = evaluate_pre_effect(healthy(authority_graph_frozen=True), ALLOW)
        self.assertEqual(result.outcome, "manual_review")
        self.assertIn("Authority graph is frozen.", result.reasons)

    def test_invalid_capability_blocks_effects(self):
        result = evaluate_pre_effect(healthy(capability_grant_valid=False), ALLOW)
        self.assertEqual(result.outcome, "manual_review")

    def test_unverified_checkpoint_blocks_effects(self):
        result = evaluate_pre_effect(healthy(clean_checkpoint_verified=False), ALLOW)
        self.assertEqual(result.outcome, "manual_review")

    def test_invalid_receipt_chain_blocks_effects(self):
        result = evaluate_pre_effect(healthy(receipt_chain_valid=False), ALLOW)
        self.assertEqual(result.outcome, "manual_review")

    def test_unpromoted_continuity_plane_blocks_effects(self):
        result = evaluate_pre_effect(healthy(continuity_plane_promoted=False), ALLOW)
        self.assertEqual(result.outcome, "manual_review")

    def test_model_deny_can_veto(self):
        result = evaluate_pre_effect(healthy(), DENY)
        self.assertEqual(result.outcome, "deny")

    def test_model_review_cannot_become_allow(self):
        result = evaluate_pre_effect(healthy(), REVIEW)
        self.assertEqual(result.outcome, "manual_review")

    def test_non_low_risk_model_allow_requires_review(self):
        result = evaluate_pre_effect(healthy(), Evaluation("allow", "high", ("Risk elevated.",)))
        self.assertEqual(result.outcome, "manual_review")

    def test_invalid_boolean_type_fails_closed(self):
        result = evaluate_pre_effect(healthy(capability_grant_valid=1), ALLOW)
        self.assertEqual(result.outcome, "deny")

    def test_invalid_policy_fails_closed(self):
        result = evaluate_pre_effect(healthy(deterministic_policy="maybe"), ALLOW)
        self.assertEqual(result.outcome, "deny")

    def test_decision_receipt_has_versioned_schema(self):
        result = evaluate_pre_effect(healthy(), ALLOW).to_dict()
        self.assertEqual(result["schema"], "u1/daybreak-pre-effect-decision/v1")
        self.assertEqual(result["outcome"], "allow")
        self.assertIn("authority", result)


if __name__ == "__main__":
    unittest.main()
