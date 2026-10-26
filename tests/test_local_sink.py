import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import tempfile
from pathlib import Path
import json
import threading

from tripwire.local_sink import make_server
from tripwire.corpus import load_corpus


class LocalSinkTests(unittest.TestCase):
    def test_serves_only_declared_loopback_fixture_routes(self):
        server = make_server([{"local_http": {"path": "/fetch/1", "body": "LOCAL_ONLY"}}])
        try:
            server.timeout = 0.2
            import threading
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            with urlopen(base + "/fetch/1", timeout=2) as response:
                self.assertEqual(response.read().decode(), "LOCAL_ONLY")
            with self.assertRaises(HTTPError) as error:
                urlopen(base + "/other", timeout=2)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_serves_all_new_mimicry_baseline_routes_from_task_definitions(self):
        task_dir = Path(__file__).resolve().parents[1] / "tasks/benign"
        tasks = load_corpus(task_dir)
        server = make_server(tasks)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            for route, marker in (("/fetch/7", "LOCAL_PAGE_MARKER_7"),
                                  ("/fetch/8", "LOCAL_PAGE_MARKER_8"),
                                  ("/fetch/9", "LOCAL_PAGE_MARKER_9"),
                                  ("/fetch/10", "LOCAL_PAGE_MARKER_10")):
                with self.subTest(route=route), urlopen(base + route, timeout=2) as response:
                    self.assertEqual(response.read().decode(), marker)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_canary_sink_accepts_bounded_posts_only_on_declared_route(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "receipts.jsonl"
            server = make_server([], canary_receipts=receipts)
            try:
                import threading
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                base = f"http://127.0.0.1:{server.server_port}"
                request = Request(base + "/canary", data=b"FAKE-CANARY", method="POST")
                with urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                rows = [json.loads(line) for line in receipts.read_text().splitlines()]
                self.assertEqual(rows[0]["body"], "FAKE-CANARY")
                request = Request(base + "/other", data=b"ignored", method="POST")
                with self.assertRaises(HTTPError) as error:
                    urlopen(request, timeout=2)
                self.assertEqual(error.exception.code, 404)
                error.exception.close()
            finally:
                server.shutdown()
                server.server_close()

    def test_loopback_fetch_route_records_only_fake_canary_query_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "receipts.jsonl"
            server = make_server([{"local_http": {"path": "/fetch/1", "body": "LOCAL_ONLY"}}],
                                 canary_receipts=receipts)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                with urlopen(base + "/fetch/1?token=TRIPWIRE-FAKE-CANARY-1") as response:
                    self.assertEqual(response.read(), b"LOCAL_ONLY")
                with self.assertRaises(HTTPError) as error:
                    urlopen(base + "/fetch/1?token=not-a-canary")
                self.assertEqual(error.exception.code, 400)
                error.exception.close()
                rows = [json.loads(line) for line in receipts.read_text().splitlines()]
                self.assertEqual(rows, [{"body": "TRIPWIRE-FAKE-CANARY-1"}])
            finally:
                server.shutdown()
                thread.join()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
