import json
import tempfile
import unittest
from pathlib import Path

from eval.run_ablations import run as run_ablations
from eval.run_detectors import run as run_detectors


class EvaluationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.benign = self.root / "benign"
        self.attack = self.root / "attack"
        self.benign.mkdir()
        self.attack.mkdir()
        benign_run = {"run_id": "same-run", "task_id": "benign-task",
                      "task_type": "edit", "is_attack": False}
        attack_run = {"run_id": "same-run", "task_id": "attack-task",
                      "task_type": "edit", "is_attack": True}
        for directory, record in ((self.benign, benign_run), (self.attack, attack_run)):
            (directory / "runs.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8")
            (directory / "joined.jsonl").write_text("", encoding="utf-8")

        detector_config = {
            "task_split_seed": 13, "calibration_fraction": 0.2,
            "test_fraction": 0.2, "sequence_ngram_order": 3,
            "target_false_positive_rates": [0.05],
        }
        ablation_config = {
            "feature_sets": ["files"],
            "combined_score": "arithmetic_mean_of_allowlist_and_sequence_novelty",
        }
        self.detector_config = self.root / "detectors.json"
        self.ablation_config = self.root / "ablations.json"
        self.detector_config.write_text(json.dumps(detector_config), encoding="utf-8")
        self.ablation_config.write_text(json.dumps(ablation_config), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_detector_run_rejects_run_id_collision_between_benign_and_attack(self):
        with self.assertRaisesRegex(ValueError, "duplicate run_id"):
            run_detectors(self.benign, self.root / "detector-output",
                          self.detector_config, self.attack)

    def test_ablation_run_rejects_run_id_collision_between_benign_and_attack(self):
        with self.assertRaisesRegex(ValueError, "duplicate run_id"):
            run_ablations(self.benign, self.root / "ablation-output",
                          self.detector_config, self.ablation_config, self.attack)


if __name__ == "__main__":
    unittest.main()
