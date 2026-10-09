"""Run AstraSec's demo endpoint as its own process.

You usually don't need this: AstraSec serves the same endpoint itself at
``http://localhost:8000/demo/v1/chat/completions``, and the Probe page's
"Use the built-in demo endpoint" button fills it in.

Run this only if you want the target on a separate port — for instance to
show the probe attacking a different process:

    python scripts/mock_target.py --port 8770

Then probe ``http://127.0.0.1:8770/v1/chat/completions`` (OpenAI-compatible,
no key). A browser visit shows a status page; the probe sends POSTs.
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from astrasec.demo_target import STATUS_PAGE, completion  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        raw = STATUS_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}
        raw = json.dumps(completion(body)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[demo-target] {fmt % args}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    print(f"Demo endpoint listening on http://{args.host}:{args.port}/v1/chat/completions")
    print("Protocol: OpenAI-compatible · no API key required")
    print("Deliberately insecure, for probe demonstrations only.")
    HTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
