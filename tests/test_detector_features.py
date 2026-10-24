import unittest

from detectors.features import extract_sample_features, group_run_samples, syscall_class


def syscall(name, *, path=None, address=None, seq=1, monotonic_ns=10):
    event = {"type": "syscall", "syscall": name, "sequence": seq,
             "monotonic_ns": monotonic_ns}
    if path is not None:
        event["path"] = path
    if address is not None:
        event["address"] = address
    return event


class DetectorFeatureTests(unittest.TestCase):
    def test_syscall_classes_cover_tracer_event_types(self):
        self.assertEqual(syscall_class({"type": "process_fork"}), "process_fork")
        self.assertEqual(syscall_class(syscall("openat")), "file_open")
        self.assertEqual(syscall_class(syscall("connect")), "network_connect")
        self.assertEqual(syscall_class(syscall("write")), "network_write")
        self.assertEqual(syscall_class(syscall("renameat2")), "file_rename")
        self.assertIsNone(syscall_class({"type": "stats"}))

    def test_paths_inside_run_workspace_are_stable_across_seeds(self):
        first = {"call_id": "task-a-seed-11:0001", "tool": "file_read", "events": [
            syscall("openat", path="/vm/data/workspaces/task-a-seed-11/notes/a.txt")
        ]}
        second = {"call_id": "task-a-seed-23:0001", "tool": "file_read", "events": [
            syscall("openat", path="/vm/data/workspaces/task-a-seed-23/notes/a.txt")
        ]}
        a = extract_sample_features("task-a-seed-11", "summarize", [first])
        b = extract_sample_features("task-a-seed-23", "summarize", [second])
        self.assertEqual(a["paths"], ["workspace/notes/a.txt"])
        self.assertEqual(a["paths"], b["paths"])
        self.assertEqual(a["sequences"], ["file_read|file_open"])

    def test_group_run_samples_includes_zero_call_model_failure(self):
        runs = [
            {"run_id": "task-a-seed-11", "task_id": "task-a", "task_type": "search"},
            {"run_id": "task-b-seed-11", "task_id": "task-b", "task_type": "edit"},
        ]
        calls = [{"call_id": "task-a-seed-11:0001", "tool": "shell", "events": []}]
        samples = group_run_samples(runs, calls)
        self.assertEqual([sample["run_id"] for sample in samples],
                         ["task-a-seed-11", "task-b-seed-11"])
        self.assertEqual(samples[1]["features"]["sequences"], [])


if __name__ == "__main__":
    unittest.main()
