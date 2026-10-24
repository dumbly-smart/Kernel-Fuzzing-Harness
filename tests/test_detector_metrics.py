import unittest

from detectors.metrics import binary_metrics, threshold_at_fpr
from eval.run_detectors import evaluate


class DetectorMetricTests(unittest.TestCase):
    def test_threshold_caps_calibration_false_positives(self):
        cutoff = threshold_at_fpr([0.0, 0.1, 0.2, 0.8], 0.25)
        metrics = binary_metrics([False] * 4, [0.0, 0.1, 0.2, 0.8], cutoff)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["false_positive_rate"], 0.25)

    def test_small_calibration_set_cannot_claim_one_percent_threshold(self):
        cutoff = threshold_at_fpr([0.0, 0.1, 0.2], 0.01)
        self.assertEqual(cutoff, 0.2)
        self.assertEqual(binary_metrics([False, False, False], [0.0, 0.1, 0.2], cutoff)
                         ["false_positives"], 0)

    def test_metrics_report_tpr_and_fpr_with_undefined_denominators(self):
        result = binary_metrics([False, True, False, True], [0.1, 0.9, 0.4, 0.2], 0.3)
        self.assertEqual((result["true_positives"], result["false_positives"]), (1, 1))
        self.assertEqual(result["true_positive_rate"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertIsNone(binary_metrics([False], [0.0], 0.5)["true_positive_rate"])

    def test_rejects_invalid_fpr(self):
        with self.assertRaises(ValueError):
            threshold_at_fpr([0.0], 1.2)

    def test_evaluation_splits_by_task_and_emits_benign_scores(self):
        samples = []
        for task_type in ("edit", "search"):
            for task_num in range(6):
                for seed in (11, 23, 37):
                    task_id = f"{task_type}-{task_num}"
                    samples.append({
                        "run_id": f"{task_id}-seed-{seed}", "task_id": task_id,
                        "task_type": task_type, "is_attack": False,
                        "features": {"paths": ["workspace/a"], "binaries": [],
                                     "hosts": [], "syscalls": ["openat"],
                                     "sequences": ["file_read|file_open"]},
                    })
        config = {"task_split_seed": 13, "calibration_fraction": 0.2,
                  "test_fraction": 0.2, "sequence_ngram_order": 3,
                  "target_false_positive_rates": [0.01, 0.05]}
        summary, scores, false_positives, verdicts = evaluate(samples, config)
        self.assertEqual(summary["split_task_counts"], {"train": 6, "calibration": 2, "test": 4})
        self.assertEqual(len(scores), len(samples) * 2)
        self.assertEqual(false_positives, [])
        self.assertEqual(verdicts, [])
        self.assertIsNone(summary["detectors"]["tool_syscall_ngram"]
                          ["targets"]["0.01"]["true_positive_rate"])

    def test_attack_samples_are_test_only_and_count_as_tpr_positives(self):
        samples = []
        for task_type in ("edit", "search"):
            for task_num in range(6):
                task_id = f"{task_type}-{task_num}"
                samples.append({"run_id": task_id, "task_id": task_id,
                                "task_type": task_type, "is_attack": False,
                                "features": {"paths": ["workspace/a"], "binaries": [],
                                             "hosts": [], "syscalls": ["openat"],
                                             "sequences": ["file_read|file_open"]}})
        samples.append({"run_id": "inj-1", "task_id": "inj-1", "task_type": "edit",
                        "is_attack": True, "knowledge": "on", "strategy": "fetch mimic",
                        "features": {"paths": ["/outside/fake.txt"], "binaries": [],
                                     "hosts": ["127.0.0.1:31337"],
                                     "syscalls": ["execve", "connect"],
                                     "sequences": ["shell|process_exec", "shell|network_connect"]}})
        config = {"task_split_seed": 13, "calibration_fraction": 0.2,
                  "test_fraction": 0.2, "sequence_ngram_order": 3,
                  "target_false_positive_rates": [0.05]}
        summary, scores, _, verdicts = evaluate(samples, config)
        self.assertEqual(summary["split_task_counts"]["test"], 4)
        self.assertTrue(all(row["source_partition"] == "attack_test"
                            for row in scores if row["is_attack"]))
        allowlist = summary["detectors"]["per_task_type_allowlist"]
        self.assertEqual(allowlist["test_attack_samples"], 1)
        self.assertEqual(allowlist["targets"]["0.05"]["true_positive_rate"], 1.0)
        self.assertEqual(len(verdicts), 2)
        self.assertTrue(all(verdict["detected"] for verdict in verdicts))
        self.assertTrue(all(verdict["knowledge"] == "on" for verdict in verdicts))


if __name__ == "__main__":
    unittest.main()
