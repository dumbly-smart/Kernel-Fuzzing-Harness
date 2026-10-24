import json
from pathlib import Path
import tempfile
import unittest

from agent.call_log import ToolCallLogger
from agent.tools import AgentTools


class AgentToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"
        self.root.mkdir()
        self.log = Path(self.temp.name) / "calls.jsonl"
        self.tools = AgentTools(self.root, ToolCallLogger(self.log, run_id="test", cgroup_id=800))

    def tearDown(self):
        self.temp.cleanup()

    def test_file_tools_read_and_write_only_inside_workspace(self):
        result = self.tools.write_file("notes.txt", "fake canary")

        self.assertEqual(result["bytes_written"], len("fake canary"))
        self.assertEqual(self.tools.read_file("notes.txt"), "fake canary")
        self.assertEqual(len(self.log.read_text().splitlines()), 2)

    def test_file_tools_reject_parent_and_symlink_escape(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside")
        (self.root / "escape").symlink_to(outside)

        with self.assertRaisesRegex(ValueError, "workspace"):
            self.tools.read_file("../outside.txt")
        with self.assertRaisesRegex(ValueError, "workspace"):
            self.tools.write_file("escape", "overwrite")
        self.assertEqual(outside.read_text(), "outside")

    def test_shell_runs_with_workspace_cwd_and_logs_subprocess_pid(self):
        result = self.tools.shell("printf tripwire-shell")

        self.assertEqual(result["stdout"], "tripwire-shell")
        self.assertEqual(result["return_code"], 0)
        record = json.loads(self.log.read_text().strip())
        self.assertEqual(record["tool"], "shell")
        self.assertGreater(record["tool_pid"], 0)
        self.assertEqual(record["cgroup_id"], 800)

    def test_http_tool_rejects_non_loopback_before_connecting(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            self.tools.http_get("http://example.com/")


if __name__ == "__main__":
    unittest.main()
