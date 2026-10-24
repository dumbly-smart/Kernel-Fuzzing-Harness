import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import tempfile
from pathlib import Path
import json

from tripwire.local_sink import make_server


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


if __name__ == "__main__":
    unittest.main()
