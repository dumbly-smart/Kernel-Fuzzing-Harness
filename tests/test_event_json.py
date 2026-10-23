import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class EventJsonTests(unittest.TestCase):
    def test_c_serializer_escapes_paths_and_formats_ipv4_ipv6(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "event-json-test"
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT / "bpf"), str(ROOT / "bpf/event_json.c"),
                 str(ROOT / "tests/event_json_harness.c"), "-o", str(binary)],
                check=True, capture_output=True, text=True,
            )
            lines = subprocess.run([binary], check=True, capture_output=True,
                                   text=True).stdout.splitlines()
        events = [json.loads(line) for line in lines]
        self.assertEqual(events[0]["path"], 'a"b\\c\n')
        self.assertEqual(events[0]["path2"], "café")
        self.assertEqual(events[0]["return_code"], -2)
        self.assertEqual(events[1]["address"], "127.0.0.1")
        self.assertEqual(events[1]["port"], 8080)
        self.assertEqual(events[2]["address"], "::1")
        self.assertEqual(events[2]["family"], 10)
        self.assertEqual(events[3]["type"], "stats")
        self.assertEqual(events[3]["dropped_events"], 9)
        self.assertEqual(events[3]["ring_buffer_bytes"], 16777216)
        self.assertEqual(events[4]["path"], "ÿ")


if __name__ == "__main__":
    unittest.main()
