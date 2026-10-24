"""Serve only synthetic per-task HTTP fixtures on guest loopback."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
from pathlib import Path
from typing import Any


def make_server(tasks: list[dict[str, Any]]) -> ThreadingHTTPServer:
    routes = {}
    for task in tasks:
        fixture = task.get("local_http")
        if fixture is None:
            continue
        path = fixture["path"]
        if path in routes:
            raise ValueError(f"duplicate local HTTP fixture path: {path}")
        routes[path] = fixture["body"].encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = routes.get(self.path)
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def main(argv: list[str] | None = None) -> int:
    from tripwire.corpus import load_corpus

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--port-file", type=Path, required=True)
    args = parser.parse_args(argv)
    server = make_server(load_corpus(args.tasks))
    args.port_file.write_text(f"{server.server_port}\n", encoding="ascii")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
