import json
from pathlib import Path
import tempfile
import unittest

from agent.call_log import ToolCallLogger
from agent.run import execute_task
from agent.tools import AgentTools


class ExecuteTaskTests(unittest.TestCase):
    def test_action_plan_returns_outputs_and_logs_each_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            calls = root / "calls.jsonl"
            task = {
                "id": "unit-task",
                "actions": [
                    {"tool": "file_write", "args": {"path": "note.txt", "content": "local only"}},
                    {"tool": "file_read", "args": {"path": "note.txt"}},
                ],
            }

            results = execute_task(task, AgentTools(
                workspace, ToolCallLogger(calls, run_id="unit-task", cgroup_id=900)))

            self.assertEqual(results[1]["result"], "local only")
            records = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual([record["tool"] for record in records], ["file_write", "file_read"])
            self.assertEqual([record["call_id"] for record in records],
                             ["unit-task:0001", "unit-task:0002"])


if __name__ == "__main__":
    unittest.main()
