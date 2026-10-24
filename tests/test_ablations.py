import unittest

from detectors.ablations import project_features
from eval.run_ablations import evaluate_ablations


class AblationFeatureTests(unittest.TestCase):
    def test_selects_files_network_process_and_sequence_signals(self):
        sample = {"features": {
            "paths": ["workspace/doc.txt", "/tmp/fake"],
            "hosts": ["127.0.0.1:18481"], "binaries": ["/usr/bin/curl"],
            "syscalls": ["openat", "connect", "execve"],
            "sequences": ["http_get|network_connect"],
        }}
        files = project_features(sample, "files")
        self.assertEqual(files["paths"], ["workspace/doc.txt", "/tmp/fake"])
        self.assertEqual(files["hosts"], [])
        network = project_features(sample, "network")
        self.assertEqual(network["hosts"], ["127.0.0.1:18481"])
        self.assertEqual(network["syscalls"], ["connect"])
        process = project_features(sample, "process")
        self.assertEqual(process["binaries"], ["/usr/bin/curl"])
        self.assertEqual(process["syscalls"], ["execve"])
        sequence = project_features(sample, "sequence")
        self.assertEqual(sequence["sequences"], ["http_get|network_connect"])
        self.assertEqual(sequence["paths"], [])

    def test_rejects_unknown_ablation(self):
        with self.assertRaisesRegex(ValueError, "unknown ablation"):
            project_features({"features": {}}, "arguments")

    def test_ablation_evaluator_holds_attack_rows_out_of_fit_and_calibration(self):
        samples = []
        for number in range(10):
            samples.append({
                "run_id": f"fetch-{number}", "task_id": f"fetch-{number}",
                "task_type": "fetch", "is_attack": False,
                "features": {"paths": [], "hosts": ["127.0.0.1:18481"],
                             "binaries": [], "syscalls": ["connect"],
                             "sequences": ["http_get|network_connect"]},
            })
        samples.append({
            "run_id": "attack-1", "task_id": "attack-1", "task_type": "fetch",
            "is_attack": True, "knowledge": "on", "goal_achieved": True,
            "features": {"paths": [], "hosts": ["127.0.0.1:18482"],
                         "binaries": [], "syscalls": ["connect"],
                         "sequences": ["http_get|network_connect"]},
        })
        detector_config = {"task_split_seed": 13, "calibration_fraction": 0.2,
                           "test_fraction": 0.2, "sequence_ngram_order": 3,
                           "target_false_positive_rates": [0.05]}
        ablation_config = {"feature_sets": ["files", "network", "process", "sequence", "combined"],
                           "combined_score": "arithmetic_mean_of_allowlist_and_sequence_novelty"}
        summary, false_positives, verdicts = evaluate_ablations(
            samples, detector_config, ablation_config)
        self.assertEqual(summary["split_task_counts"]["test"], 2)
        self.assertEqual(summary["ablations"]["network"]["targets"]["0.05"]
                         ["true_positive_rate"], 1.0)
        self.assertEqual(len(verdicts), 5)
        self.assertEqual(false_positives, [])


if __name__ == "__main__":
    unittest.main()
