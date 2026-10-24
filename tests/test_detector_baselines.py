import unittest

from detectors.allowlist import score as score_allowlist, train as train_allowlist
from detectors.ngram import fit as fit_ngrams, score as score_ngrams


def sample(task_type, *, paths=(), syscalls=(), sequence=()):
    return {"task_type": task_type, "features": {
        "paths": list(paths), "binaries": [], "hosts": [],
        "syscalls": list(syscalls), "sequences": list(sequence),
    }}


class DetectorBaselineTests(unittest.TestCase):
    def test_allowlist_is_per_task_type_and_explains_unknowns(self):
        trained = train_allowlist([
            sample("edit", paths=("workspace/a.txt",), syscalls=("openat",)),
            sample("search", paths=("workspace/index.txt",), syscalls=("openat",)),
        ])
        known_score, known_causes = score_allowlist(
            sample("edit", paths=("workspace/a.txt",), syscalls=("openat",)), trained)
        new_score, causes = score_allowlist(
            sample("edit", paths=("workspace/secret.txt",), syscalls=("openat",)), trained)
        self.assertEqual((known_score, known_causes), (0.0, {}))
        self.assertEqual(new_score, 0.5)
        self.assertEqual(causes, {"paths": ["workspace/secret.txt"]})

    def test_ngram_baseline_scores_unseen_ordered_grams(self):
        trained = fit_ngrams([
            sample("fetch", sequence=("http_get|network_connect", "http_get|network_read")),
        ], n=2)
        known, known_causes = score_ngrams(
            sample("fetch", sequence=("http_get|network_connect", "http_get|network_read")),
            trained, n=2)
        novel, causes = score_ngrams(
            sample("fetch", sequence=("shell|process_create", "shell|process_exec")),
            trained, n=2)
        self.assertEqual((known, known_causes), (0.0, []))
        self.assertGreater(novel, 0.0)
        self.assertTrue(causes)

    def test_empty_sample_has_no_ngram_anomaly(self):
        trained = fit_ngrams([sample("edit")], n=3)
        self.assertEqual(score_ngrams(sample("edit"), trained, n=3), (0.0, []))


if __name__ == "__main__":
    unittest.main()
