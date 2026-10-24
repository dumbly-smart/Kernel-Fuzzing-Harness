import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

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


if __name__ == "__main__":
    unittest.main()
