#!/usr/bin/env python3
"""Tiny webhook capture server for tests.

Appends every POSTed request body as one JSON line to OUT_PATH, so the test
suite can assert what the honeypot actually sent to Discord/Slack/relays.

    python3 webhook_capture.py /tmp/wh.jsonl [port]
"""

import http.server
import json
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        try:
            rec = json.loads(body.decode("utf-8"))
        except Exception:
            rec = {"_raw": body.decode("utf-8", "replace")}
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    OUT_PATH = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 19849
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
