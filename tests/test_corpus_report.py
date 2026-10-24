import unittest

from tripwire.corpus_report import summarize_behavior


class CorpusReportTests(unittest.TestCase):
    def test_reports_utility_and_stable_vs_noisy_features_per_type(self):
        runs = [
            {"run_id": "edit-01-seed-1", "task_type": "edit", "success": True},
            {"run_id": "edit-01-seed-2", "task_type": "edit", "success": False},
        ]
        calls = [
            {"call_id": "edit-01-seed-1:0001", "events": [
                {"type": "syscall", "syscall": "openat", "path": "answer.txt", "comm": "python3"},
                {"type": "syscall", "syscall": "execve", "path": "/usr/bin/python3", "comm": "python3"},
            ]},
            {"call_id": "edit-01-seed-2:0001", "events": [
                {"type": "syscall", "syscall": "openat", "path": "answer.txt", "comm": "python3"},
            ]},
        ]
        report = summarize_behavior(runs, calls)
        edit = report["task_types"]["edit"]
        self.assertEqual((edit["attempts"], edit["successes"]), (2, 1))
        self.assertEqual(edit["sequence_lengths"], [2, 1])
        self.assertIn("answer.txt", edit["stable_features"]["paths"])
        self.assertIn("/usr/bin/python3", edit["noisy_features"]["binaries"])


if __name__ == "__main__":
    unittest.main()
