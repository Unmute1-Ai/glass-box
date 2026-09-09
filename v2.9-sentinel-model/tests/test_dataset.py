import json
import unittest

from u1_sentinel_model.dataset import generate_records


class DatasetTests(unittest.TestCase):
    def test_generation_is_deterministic(self):
        a = list(generate_records(20, 7))
        b = list(generate_records(20, 7))
        self.assertEqual(a, b)

    def test_records_have_strict_training_shape(self):
        records = list(generate_records(100, 9))
        self.assertEqual(len(records), 100)

        for record in records:
            self.assertEqual(len(record["messages"]), 3)
            self.assertEqual(
                [m["role"] for m in record["messages"]],
                ["system", "user", "assistant"],
            )
            target = json.loads(record["messages"][-1]["content"])
            self.assertEqual(set(target), {"verdict", "risk", "findings"})
            self.assertIn(
                target["verdict"],
                {"allow", "deny", "manual_review"},
            )
            self.assertIn(
                target["risk"],
                {"low", "medium", "high", "critical"},
            )

    def test_dataset_contains_both_allow_and_deny(self):
        records = list(generate_records(500, 7))
        verdicts = {
            json.loads(r["messages"][-1]["content"])["verdict"] for r in records
        }
        self.assertIn("allow", verdicts)
        self.assertIn("deny", verdicts)


if __name__ == "__main__":
    unittest.main()
