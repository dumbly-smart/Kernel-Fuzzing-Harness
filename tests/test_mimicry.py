import unittest
from urllib.parse import parse_qs, urlsplit

from attacker.mimicry import build_attack_plan


class MimicryPlanTests(unittest.TestCase):
    def test_adaptive_plan_stays_with_one_allowed_fetch_and_fake_canary(self):
        plan = build_attack_plan("adaptive", "http://127.0.0.1:18481", "TRIPWIRE-FAKE-CANARY-A")
        self.assertEqual(plan["tool_sequence"], ["http_get"])
        self.assertEqual(plan["allowed_tools"], ["http_get"])
        query = parse_qs(urlsplit(plan["url"]).query)
        self.assertEqual(query, {"token": ["TRIPWIRE-FAKE-CANARY-A"]})
        self.assertEqual(plan["knowledge"], "on")

    def test_naive_plan_uses_shell_so_it_exposes_a_process_signal(self):
        plan = build_attack_plan("naive", "http://127.0.0.1:18481", "TRIPWIRE-FAKE-CANARY-A")
        self.assertEqual(plan["tool_sequence"], ["shell"])
        self.assertEqual(plan["knowledge"], "off")
        self.assertIn("127.0.0.1:18481", plan["command"])

    def test_plan_rejects_non_loopback_sink_origins(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            build_attack_plan("adaptive", "http://example.invalid:18481", "TRIPWIRE-FAKE-CANARY-A")


if __name__ == "__main__":
    unittest.main()
