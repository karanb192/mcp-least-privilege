#!/usr/bin/env python3
"""The attacker's collection endpoint, running on your own laptop.

Every demo that "exfiltrates" sends to this process and nowhere else. It logs
each request (method, path, decoded query, body) to stdout and to a log file,
and answers 200 so a fetching agent sees success.

Usage: sink.py [--port 8787] [--log traces/live/sink.log]
"""
import argparse
import datetime as dt
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    log_path = None

    def _record(self, body):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        entry = {
            "ts": dt.datetime.now().isoformat(timespec="seconds"),
            "method": self.command,
            "path": parsed.path,
            "query": {k: v if len(v) > 1 else v[0] for k, v in query.items()},
            "body": body[:2000],
        }
        line = json.dumps(entry)
        print(f"\033[1;31m[sink] RECEIVED\033[0m {line}", flush=True)
        if self.log_path:
            with open(self.log_path, "a") as fh:
                fh.write(line + "\n")

    def do_GET(self):
        self._record("")
        self._ok()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self._record(body)
        self._ok()

    def _ok(self):
        payload = b"<html><body><h1>sink</h1><p>received, thanks</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--log", default="traces/live/sink.log")
    args = parser.parse_args()
    if args.log:
        os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
        Handler.log_path = args.log
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[sink] listening on http://127.0.0.1:{args.port}  (log: {args.log}). Ctrl-C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[sink] stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
