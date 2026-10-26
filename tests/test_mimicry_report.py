import unittest

from attacker.report import summarize_campaign


class MimicryReportTests(unittest.TestCase):
    def test_summary_keeps_each_strategy_and_its_detector_verdicts(self):
        runs = [
            {"run_id": f"run-{mode}", "strategy": mode, "knowledge": knowledge,
             "goal_achieved": mode != "adaptive-padding"}
            for mode, knowledge in (
                ("naive", "off"), ("adaptive", "on"),
                ("adaptive-padding", "on"), ("adaptive-file-scope", "on"),
            )
        ]
        verdicts = [
            {"run_id": run["run_id"], "detector": "allowlist",
             "target_false_positive_rate": 0.05, "detected": True}
            for run in runs
        ]

        report = summarize_campaign(runs, verdicts)

        self.assertEqual(report["runs"], 4)
        self.assertEqual(report["goal_successes"], 3)
        self.assertEqual(report["goal_success_rate"], 0.75)
        self.assertEqual(set(report["by_strategy"]), {run["run_id"] for run in runs})
        self.assertEqual(report["by_strategy"]["run-adaptive-padding"]["knowledge"], "on")
        self.assertEqual(
            report["by_strategy"]["run-adaptive-file-scope"]["detectors"][
                "allowlist@FPR=0.05"],
            {"detected": 1, "runs": 1, "detection_rate": 1.0},
        )

    def test_summary_rejects_verdicts_for_unknown_runs(self):
        verdict = {"run_id": "missing", "detector": "allowlist",
                   "target_false_positive_rate": 0.05, "detected": False}
        with self.assertRaisesRegex(ValueError, "unknown run"):
            summarize_campaign([], [verdict])


if __name__ == "__main__":
    unittest.main()
