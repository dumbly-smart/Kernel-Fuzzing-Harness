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
            if args == ["sysctl", "-n", "net.ipv4.ip_forward",
                        "net.ipv6.conf.all.forwarding"]:
                return type("Result", (), {"stdout": "0\n0\n"})()
            return type("Result", (), {"stdout": ""})()

        configure_loopback_only_egress(runner)
        self.assertIn(["ufw", "--force", "reset"], calls)
        self.assertIn(["ufw", "default", "deny", "outgoing"], calls)
        self.assertIn(["ufw", "allow", "in", "on", "lo"], calls)
        self.assertIn(["ufw", "allow", "out", "on", "lo"], calls)
        self.assertEqual(calls[-2:], [
            ["ufw", "status", "verbose"],
            ["sysctl", "-n", "net.ipv4.ip_forward",
             "net.ipv6.conf.all.forwarding"],
        ])

    def test_rejects_status_that_does_not_block_outbound(self):
        status = "Status: active\nDefault: allow (outgoing)\n"

        def runner(args, **kwargs):
            if args == ["ufw", "status", "verbose"]:
                return type("Result", (), {"stdout": status})()
            if args == ["sysctl", "-n", "net.ipv4.ip_forward",
                        "net.ipv6.conf.all.forwarding"]:
                return type("Result", (), {"stdout": "0\n0\n"})()
            return type("Result", (), {"stdout": ""})()

        with self.assertRaisesRegex(RuntimeError, "loopback-only egress") as caught:
            configure_loopback_only_egress(runner)
        self.assertIn(status.rstrip(), str(caught.exception))

    def test_accepts_disabled_routing_when_kernel_forwarding_is_off(self):
        status = ("Status: active\nDefault: deny (incoming), deny (outgoing), "
                  "disabled (routed)\n"
                  "Anywhere on lo ALLOW IN Anywhere\n"
                  "Anywhere ALLOW OUT Anywhere on lo\n")

        def runner(args, **kwargs):
            if args == ["ufw", "status", "verbose"]:
                return type("Result", (), {"stdout": status})()
            if args == ["sysctl", "-n", "net.ipv4.ip_forward",
                        "net.ipv6.conf.all.forwarding"]:
                return type("Result", (), {"stdout": "0\n0\n"})()
            return type("Result", (), {"stdout": ""})()

        self.assertEqual(configure_loopback_only_egress(runner), status)

    def test_refuses_disabled_routing_if_kernel_forwarding_is_enabled(self):
        status = ("Status: active\nDefault: deny (incoming), deny (outgoing), "
                  "disabled (routed)\nAnywhere on lo ALLOW IN Anywhere\n"
                  "Anywhere ALLOW OUT Anywhere on lo\n")

        def runner(args, **kwargs):
            if args == ["ufw", "status", "verbose"]:
                return type("Result", (), {"stdout": status})()
            if args == ["sysctl", "-n", "net.ipv4.ip_forward",
                        "net.ipv6.conf.all.forwarding"]:
                return type("Result", (), {"stdout": "1\n0\n"})()
            return type("Result", (), {"stdout": ""})()

        with self.assertRaisesRegex(RuntimeError, "forwarding values"):
            configure_loopback_only_egress(runner)


if __name__ == "__main__":
    unittest.main()
