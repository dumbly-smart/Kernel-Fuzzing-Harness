import json
from pathlib import Path
import tempfile
import unittest

from agent.call_log import ToolCallLogger
from agent.react import OllamaClient, ReActAgent, ReActPolicyError
from agent.tools import AgentTools


def assistant(content="", tool_calls=None):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"message": message}


def tool_call(name, arguments):
    return {"type": "function", "function": {"name": name, "arguments": arguments}}


class ReActAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.call_log = self.root / "calls.jsonl"
        self.tools = AgentTools(
            self.workspace,
            ToolCallLogger(self.call_log, run_id="react-test", cgroup_id=999),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_uses_allowed_tool_and_passes_seed_and_local_chat_payload(self):
        responses = [
            assistant(tool_calls=[tool_call("file_write", {"path": "answer.txt", "content": "local"})]),
            assistant("Wrote the answer."),
        ]
        requests = []

        def transport(url, payload, timeout):
            requests.append((url, payload, timeout))
            return responses.pop(0)

        client = OllamaClient(transport=transport, model="test-model", seed=123)
        result = ReActAgent(client, self.tools).run({
            "id": "react-task",
            "prompt": "Write the answer file.",
            "allowed_tools": ["file_write"],
        })

        self.assertEqual(result["final_answer"], "Wrote the answer.")
        self.assertEqual(result["tool_results"][0]["tool"], "file_write")
        self.assertEqual(result["tool_results"][0]["result"]["bytes_written"], 5)
        self.assertEqual(self.workspace.joinpath("answer.txt").read_text(), "local")
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(url == "http://127.0.0.1:11434/api/chat" for url, _, _ in requests))
        self.assertEqual(requests[0][1]["options"]["seed"], 123)
        self.assertEqual(requests[0][1]["stream"], False)
        self.assertEqual(json.loads(self.call_log.read_text().splitlines()[0])["tool"], "file_write")

    def test_passes_configured_model_keep_alive_to_ollama_chat(self):
        requests = []
        client = OllamaClient(
            transport=lambda url, payload, timeout: requests.append(payload) or assistant("ok"),
            keep_alive_seconds=0,
        )

        client.chat([], [])

        self.assertEqual(requests[0]["keep_alive"], 0)

    def test_rejects_invalid_model_keep_alive(self):
        for value in (-1, True, 1.5, "0"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "keep_alive_seconds"):
                OllamaClient(keep_alive_seconds=value)

    def test_rejects_external_ollama_endpoint(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            OllamaClient(base_url="http://example.com:11434")

    def test_rejects_tool_not_in_task_allowlist(self):
        client = OllamaClient(
            transport=lambda *_: assistant(tool_calls=[
                tool_call("file_write", {"path": "escape.txt", "content": "no"})
            ]),
            model="test-model",
        )

        with self.assertRaisesRegex(ReActPolicyError, "not allowed"):
            ReActAgent(client, self.tools).run({
                "id": "restricted-task",
                "prompt": "Read the note only.",
                "allowed_tools": ["file_read"],
            })
        self.assertFalse(self.workspace.joinpath("escape.txt").exists())
        self.assertFalse(self.call_log.exists())

    def test_rejects_malformed_model_tool_arguments(self):
        client = OllamaClient(
            transport=lambda *_: assistant(tool_calls=[{
                "type": "function", "function": {"name": "file_write", "arguments": "not-json"}
            }]),
            model="test-model",
        )
        with self.assertRaisesRegex(ValueError, "arguments must be an object"):
            ReActAgent(client, self.tools).run({
                "id": "malformed-task", "prompt": "Write.", "allowed_tools": ["file_write"]
            })

    def test_enforces_turn_limit(self):
        client = OllamaClient(
            transport=lambda *_: assistant(tool_calls=[tool_call(
                "file_read", {"path": "missing.txt"}
            )]),
            model="test-model",
        )
        with self.assertRaisesRegex(RuntimeError, "maximum turn count"):
            ReActAgent(client, self.tools, max_turns=1).run({
                "id": "turn-limit", "prompt": "Read a file.", "allowed_tools": ["file_read"]
            })


if __name__ == "__main__":
    unittest.main()
