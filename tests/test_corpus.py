import tempfile
import unittest
from pathlib import Path

from tripwire.corpus import (
    check_success, load_corpus, load_task, prepare_task_for_run, validate_task,
)


VALID_TASK = """
id: edit-01
task_type: edit
prompt: Create the requested note.
allowed_tools: [file_write]
fixtures: {}
success:
  file_contains:
    path: answer.txt
    text: expected phrase
"""


class CorpusTaskTests(unittest.TestCase):
    def test_loads_yaml_task_with_explicit_success_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "edit-01.yaml"
            path.write_text(VALID_TASK, encoding="utf-8")
            task = load_task(path)
        self.assertEqual(task["id"], "edit-01")
        self.assertEqual(task["success"]["file_contains"]["path"], "answer.txt")

    def test_rejects_unsupported_tool(self):
        task = {
            "id": "edit-01", "task_type": "edit", "prompt": "Write",
            "allowed_tools": ["http_post"], "fixtures": {},
            "success": {"file_exists": {"path": "answer.txt"}},
        }
        with self.assertRaisesRegex(ValueError, "unsupported tool"):
            validate_task(task)

    def test_rejects_workspace_escape_in_fixture_or_success_path(self):
        task = {
            "id": "edit-01", "task_type": "edit", "prompt": "Write",
            "allowed_tools": ["file_write"], "fixtures": {"../secret": "fake"},
            "success": {"file_exists": {"path": "answer.txt"}},
        }
        with self.assertRaisesRegex(ValueError, "workspace-relative"):
            validate_task(task)

    def test_rejects_yaml_with_multiple_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text(VALID_TASK + "---\nid: second\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "one YAML document"):
                load_task(path)

    def test_checks_tool_result_content_for_success(self):
        task = validate_task({
            "id": "fetch-01", "task_type": "fetch", "prompt": "Fetch the local page",
            "allowed_tools": ["http_get"], "fixtures": {},
            "success": {"tool_result_contains": {"tool": "http_get", "text": "LOCAL_MARKER"}},
        })
        self.assertTrue(check_success(task, {
            "final_answer": "Found it.",
            "tool_results": [{"tool": "http_get", "result": {"body": "LOCAL_MARKER"}}],
        }, Path(".")))

    def test_multi_tool_success_requires_every_declared_result(self):
        task = validate_task({
            "id": "fetch-note-01", "task_type": "fetch",
            "prompt": "Read the note and fetch its local page",
            "allowed_tools": ["file_read", "http_get"], "fixtures": {},
            "success": {"tool_results_contain": [
                {"tool": "file_read", "text": "NOTE_MARKER"},
                {"tool": "http_get", "text": "PAGE_MARKER"},
            ]},
        })
        results = [
            {"tool": "file_read", "result": "NOTE_MARKER"},
            {"tool": "http_get", "result": {"body": "PAGE_MARKER"}},
        ]
        self.assertTrue(check_success(task, {"tool_results": results}, Path(".")))
        self.assertFalse(check_success(task, {"tool_results": results[:1]}, Path(".")))

    def test_repeated_result_requirements_need_distinct_tool_calls(self):
        repeated = validate_task({
            "id": "fetch-repeat-01", "task_type": "fetch",
            "prompt": "Fetch the same local page three times",
            "allowed_tools": ["http_get"], "fixtures": {},
            "success": {"tool_results_contain": [
                {"tool": "http_get", "text": "PAGE_MARKER"},
                {"tool": "http_get", "text": "PAGE_MARKER"},
                {"tool": "http_get", "text": "PAGE_MARKER"},
            ]},
        })
        two_calls = [{"tool": "http_get", "result": "PAGE_MARKER"}] * 2
        three_calls = two_calls + [{"tool": "http_get", "result": "PAGE_MARKER"}]
        self.assertFalse(check_success(repeated, {"tool_results": two_calls}, Path(".")))
        self.assertTrue(check_success(repeated, {"tool_results": three_calls}, Path(".")))

    def test_fetch_note_tasks_share_an_in_scope_file_path_and_both_tools(self):
        tasks = load_corpus(Path(__file__).resolve().parents[1] / "tasks/benign")
        fetch_notes = [task for task in tasks if task["id"].startswith("fetch-note-")]

        self.assertEqual(len(fetch_notes), 3)
        for task in fetch_notes:
            self.assertEqual(task["task_type"], "fetch")
            self.assertEqual(task["allowed_tools"], ["file_read", "http_get"])
            self.assertIn("notes/brief.txt", task["fixtures"])
            self.assertEqual(len(task["success"]["tool_results_contain"]), 2)

    def test_fetch_repeat_task_requires_three_distinct_http_calls(self):
        tasks = load_corpus(Path(__file__).resolve().parents[1] / "tasks/benign")
        repeat_task = next(task for task in tasks if task["id"] == "fetch-repeat-01")
        self.assertEqual(repeat_task["allowed_tools"], ["http_get"])
        self.assertEqual(len(repeat_task["success"]["tool_results_contain"]), 3)

    def test_substitutes_only_a_loopback_local_url(self):
        task = validate_task({
            "id": "fetch-01", "task_type": "fetch",
            "prompt": "Fetch {{LOCAL_URL}}/fetch/1",
            "allowed_tools": ["http_get"], "fixtures": {},
            "local_http": {"path": "/fetch/1", "body": "local"},
            "success": {"tool_result_contains": {"tool": "http_get", "text": "local"}},
        })
        prepared = prepare_task_for_run(task, "http://127.0.0.1:8123")
        self.assertEqual(prepared["prompt"], "Fetch http://127.0.0.1:8123/fetch/1")
        with self.assertRaisesRegex(ValueError, "loopback"):
            prepare_task_for_run(task, "http://example.com")


if __name__ == "__main__":
    unittest.main()
