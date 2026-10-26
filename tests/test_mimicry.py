import unittest
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit

from attacker.mimicry import build_attack_plan, validate_output_dir


class MimicryPlanTests(unittest.TestCase):
    def test_adaptive_plan_stays_with_one_allowed_fetch_and_fake_canary(self):
        plan = build_attack_plan("adaptive", "http://127.0.0.1:18481", "TRIPWIRE-FAKE-CANARY-A")
        self.assertEqual(plan["tool_sequence"], ["http_get"])
        self.assertEqual(plan["allowed_tools"], ["http_get"])
        query = parse_qs(urlsplit(plan["url"]).query)
        self.assertEqual(query, {"token": ["TRIPWIRE-FAKE-CANARY-A"]})
        self.assertEqual(plan["knowledge"], "on")

    def test_adaptive_padding_plan_repeats_only_the_allowed_local_fetch(self):
        plan = build_attack_plan(
            "adaptive-padding", "http://127.0.0.1:18481",
            "TRIPWIRE-FAKE-CANARY-A", padding_requests=2,
        )
        self.assertEqual(plan["tool_sequence"], ["http_get"] * 3)
        self.assertEqual(plan["allowed_tools"], ["http_get"])
        self.assertEqual(len(plan["urls"]), 3)
        self.assertEqual(parse_qs(urlsplit(plan["urls"][-1]).query),
                         {"token": ["TRIPWIRE-FAKE-CANARY-A"]})
        self.assertTrue(all(urlsplit(url).hostname == "127.0.0.1" for url in plan["urls"]))

    def test_adaptive_padding_rejects_unbounded_or_invalid_counts(self):
        for count in (-1, 21, True, 1.5):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "padding"):
                build_attack_plan(
                    "adaptive-padding", "http://127.0.0.1:18481",
                    "TRIPWIRE-FAKE-CANARY-A", padding_requests=count,
                )

    def test_scoped_file_plan_reads_only_a_declared_workspace_path(self):
        plan = build_attack_plan(
            "adaptive-file-scope", "http://127.0.0.1:18481",
            "TRIPWIRE-FAKE-CANARY-A", file_path="notes/canary.txt",
        )
        self.assertEqual(plan["task_type"], "fetch_note")
        self.assertEqual(plan["allowed_tools"], ["file_read", "http_get"])
        self.assertEqual(plan["tool_sequence"], ["file_read", "http_get"])
        self.assertEqual(plan["file_path"], "notes/canary.txt")
        self.assertEqual(urlsplit(plan["url"]).hostname, "127.0.0.1")

    def test_scoped_file_plan_uses_its_explicit_task_policy(self):
        plan = build_attack_plan(
            "adaptive-file-scope", "http://127.0.0.1:18481",
            "TRIPWIRE-FAKE-CANARY-A", file_path="notes/canary.txt",
            file_scope_task_type="fetch_note",
            file_scope_allowed_tools=["file_read", "http_get"],
        )
        self.assertEqual(plan["task_type"], "fetch_note")
        self.assertEqual(plan["allowed_tools"], ["file_read", "http_get"])

    def test_scoped_file_plan_rejects_a_policy_missing_a_required_tool(self):
        with self.assertRaisesRegex(ValueError, "policy"):
            build_attack_plan(
                "adaptive-file-scope", "http://127.0.0.1:18481",
                "TRIPWIRE-FAKE-CANARY-A", file_scope_allowed_tools=["file_read"],
            )

    def test_scoped_file_plan_rejects_paths_outside_workspace(self):
        for path in ("", ".", "../canary.txt", "/tmp/canary.txt", "notes/../../canary.txt"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "workspace"):
                build_attack_plan(
                    "adaptive-file-scope", "http://127.0.0.1:18481",
                    "TRIPWIRE-FAKE-CANARY-A", file_path=path,
                )

    def test_naive_plan_uses_shell_so_it_exposes_a_process_signal(self):
        plan = build_attack_plan("naive", "http://127.0.0.1:18481", "TRIPWIRE-FAKE-CANARY-A")
        self.assertEqual(plan["tool_sequence"], ["shell"])
        self.assertEqual(plan["knowledge"], "off")
        self.assertIn("127.0.0.1:18481", plan["command"])

    def test_plan_rejects_non_loopback_sink_origins(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            build_attack_plan("adaptive", "http://example.invalid:18481", "TRIPWIRE-FAKE-CANARY-A")

    def test_campaign_allows_monitor_artifacts_in_shared_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            (output_dir / "events.jsonl").write_text("{}\n")
            (output_dir / "canary-receipts.jsonl").write_text("")

            validate_output_dir(output_dir)

    def test_campaign_rejects_existing_campaign_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            (output_dir / "calls.jsonl").write_text("existing\n")

            with self.assertRaisesRegex(FileExistsError, "calls.jsonl"):
                validate_output_dir(output_dir)


if __name__ == "__main__":
    unittest.main()
