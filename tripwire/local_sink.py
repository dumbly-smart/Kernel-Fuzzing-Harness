"""Serve only synthetic per-task HTTP fixtures on guest loopback."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
from pathlib import Path
import threading
from typing import Any


MAX_CANARY_BYTES = 4096


def make_server(tasks: list[dict[str, Any]], *, canary_receipts: Path | None = None
                ) -> ThreadingHTTPServer:
    routes = {}
    for task in tasks:
        fixture = task.get("local_http")
        if fixture is None:
            continue
        path = fixture["path"]
        if path in routes:
            raise ValueError(f"duplicate local HTTP fixture path: {path}")
        routes[path] = fixture["body"].encode("utf-8")
    receipt_lock = threading.Lock()

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

        def do_POST(self):
            if self.path != "/canary" or canary_receipts is None:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                self.send_error(400)
                return
            if length < 0:
                self.send_error(400)
                return
            if length > MAX_CANARY_BYTES:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
            try:
                decoded = body.decode("utf-8")
            except UnicodeDecodeError:
                self.send_error(400)
                return
            record = json.dumps({"body": decoded}, ensure_ascii=False, sort_keys=True) + "\n"
            with receipt_lock, canary_receipts.open("a", encoding="utf-8") as stream:
                stream.write(record)
                stream.flush()
            response = b"received"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def main(argv: list[str] | None = None) -> int:
    from tripwire.corpus import load_corpus

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--injections", type=Path, default=None,
                        help="also serve declared web-page payloads from this injection suite")
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--canary-receipts", type=Path, default=None,
                        help="enable the bounded local-only POST /canary recorder")
    args = parser.parse_args(argv)
    tasks = load_corpus(args.tasks)
    if args.injections is not None:
        from tripwire.injections import load_injections
        tasks.extend(case["task"] for case in load_injections(args.injections))
    if args.canary_receipts is not None:
        args.canary_receipts.parent.mkdir(parents=True, exist_ok=True)
        args.canary_receipts.touch(exist_ok=True)
    server = make_server(tasks, canary_receipts=args.canary_receipts)
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
