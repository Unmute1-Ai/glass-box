import unittest

from u1_sentinel_model.oracle import evaluate_case
from u1_sentinel_model.schema import ProposalCase


def case(**overrides):
    data = dict(
        proposal_id="prop_1",
        principal_id="user:abc",
        authenticated_principal_id="user:abc",
        kind="write",
        resources=("/srv/u1-sandbox/out.txt",),
        allowed_scope=("/srv/u1-sandbox/**",),
        diff_digest="sha256:a",
        confirmation_digest="sha256:a",
        destructive=False,
        persistence=False,
        nonce_replayed=False,
        confirmation_expired=False,
        deterministic_policy="allow",
        resource_owner_principal_id="user:abc",
        notes=(),
    )
    data.update(overrides)
    return ProposalCase(**data)


class OracleTests(unittest.TestCase):
    def test_clean_bounded_write_allows_advisory(self):
        result = evaluate_case(case())
        self.assertEqual(result.verdict, "allow")
        self.assertEqual(result.risk, "low")

    def test_path_escape_is_critical_deny(self):
        result = evaluate_case(
            case(resources=("/srv/u1-sandbox/../../etc/passwd",))
        )
        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.risk, "critical")
        self.assertTrue(
            any("outside authorized scope" in finding for finding in result.findings)
        )

    def test_model_cannot_lift_deterministic_deny(self):
        result = evaluate_case(case(deterministic_policy="deny"))
        self.assertEqual(result.verdict, "deny")
        self.assertTrue(
            any("cannot lift denial" in finding for finding in result.findings)
        )

    def test_principal_mismatch_denies(self):
        result = evaluate_case(case(authenticated_principal_id="user:attacker"))
        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.risk, "critical")

    def test_digest_mismatch_denies(self):
        result = evaluate_case(case(confirmation_digest="sha256:mutated"))
        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.risk, "critical")

    def test_nonce_replay_denies(self):
        result = evaluate_case(case(nonce_replayed=True))
        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.risk, "critical")


if __name__ == "__main__":
    unittest.main()
