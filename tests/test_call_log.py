import json
import os
from pathlib import Path
import tempfile
import unittest

from agent.call_log import ToolCallLogger


class ToolCallLoggerTests(unittest.TestCase):
    def test_logs_call_timing_process_and_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            logger = ToolCallLogger(path, run_id="task01", cgroup_id=700)

            result = logger.invoke(
                "shell", {"command": "true"},
                lambda context: (context.set_process(101, tgid=101), "ok")[1],
            )

            record = json.loads(path.read_text().strip())
            self.assertEqual(result, "ok")
            self.assertEqual(record["call_id"], "task01:0001")
            self.assertEqual(record["tool"], "shell")
            self.assertEqual(record["args"], {"command": "true"})
            self.assertLessEqual(record["start_monotonic_ns"], record["end_monotonic_ns"])
            self.assertEqual(record["pid"], os.getpid())
            self.assertEqual(record["tool_pid"], 101)
            self.assertEqual(record["cgroup_id"], 700)
            self.assertTrue(record["ok"])

    def test_records_failed_call_without_losing_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            logger = ToolCallLogger(path, run_id="task02", cgroup_id=700)

            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                logger.invoke("shell", {"command": "false"},
                              lambda context: (_ for _ in ()).throw(RuntimeError("synthetic failure")))

            record = json.loads(path.read_text().strip())
            self.assertFalse(record["ok"])
            self.assertEqual(record["error_type"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
