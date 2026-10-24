import unittest

from tripwire.egress import configure_loopback_only_egress


class EgressLockdownTests(unittest.TestCase):
    def test_resets_guest_firewall_and_allows_only_loopback(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            if args == ["ufw", "status", "verbose"]:
                return type("Result", (), {
                    "stdout": "Status: active\nDefault: deny (incoming), deny (routed), deny (outgoing)\n"
                              "Anywhere on lo ALLOW IN Anywhere\nAnywhere ALLOW OUT Anywhere on lo\n"
                })()
            return type("Result", (), {"stdout": ""})()

        configure_loopback_only_egress(runner)
        self.assertIn(["ufw", "--force", "reset"], calls)
        self.assertIn(["ufw", "default", "deny", "outgoing"], calls)
        self.assertIn(["ufw", "allow", "in", "on", "lo"], calls)
        self.assertIn(["ufw", "allow", "out", "on", "lo"], calls)
        self.assertEqual(calls[-1], ["ufw", "status", "verbose"])

    def test_rejects_status_that_does_not_block_outbound(self):
        def runner(args, **kwargs):
            if args == ["ufw", "status", "verbose"]:
                return type("Result", (), {"stdout": "Status: inactive\n"})()
            return type("Result", (), {"stdout": ""})()

        with self.assertRaisesRegex(RuntimeError, "loopback-only egress"):
            configure_loopback_only_egress(runner)


if __name__ == "__main__":
    unittest.main()
