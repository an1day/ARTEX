"""Run a synthetic loopback target and the MCP sidecar; never contacts PRE."""
from __future__ import annotations

import argparse
import json
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from .jobs import JobManager
from .registry import RegisteredTarget
from .server import create_app
from .store import LocalStore


class SyntheticTarget(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                path = urlsplit(self.path)
                if path.path == "/session":
                    sid = str(uuid4())
                    owner.sessions[sid] = queue.Queue()
                    raw = json.dumps({"id": sid}).encode()
                elif path.path == "/session/prompt":
                    sid = parse_qs(path.query).get("sessionID", [""])[0]
                    if sid not in owner.sessions:
                        self.send_error(404)
                        return
                    prompt = body.get("parts", [{}])[0].get("text", "")
                    text = owner.canary if "private internal" in prompt else "BASELINE_OK" if "BASELINE" in prompt else "SECOND_TURN_OK"
                    mid = str(uuid4())
                    for event in [
                        {"type": "message.updated", "properties": {"info": {"id": mid, "sessionID": sid, "role": "assistant"}}},
                        {"type": "message.part.updated", "properties": {"part": {"id": "text", "messageID": mid, "sessionID": sid, "type": "text", "text": text}}},
                        {"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}},
                    ]:
                        owner.sessions[sid].put(event)
                    raw = b"{}"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                parsed = urlsplit(self.path)
                sid = parse_qs(parsed.query).get("sessionID", [""])[0]
                if parsed.path != "/session/event" or sid not in owner.sessions:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.flush()
                try:
                    while not owner.stopping.is_set():
                        try:
                            event = owner.sessions[sid].get(timeout=0.1)
                        except queue.Empty:
                            continue
                        self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                        self.wfile.flush()
                        if event["type"] == "session.status":
                            break
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True

        super().__init__(("127.0.0.1", 0), Handler)
        self.sessions: dict = {}
        self.canary = "SYNTHETIC-PRIVATE-" + uuid4().hex
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def target(self) -> RegisteredTarget:
        return RegisteredTarget("synthetic-wesmart", f"http://127.0.0.1:{self.server_port}", "synthetic-v1", "synthetic-account",
                                True, ("T03", "T08", "T09"), "synthetic-protocol-v1", True, {}, self.canary)

    def stop(self):
        self.stopping.set()
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description="Synthetic Agent test demo (no PRE traffic)")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()
    token = os.environ.get("AGENT_TEST_SERVICE_TOKEN", "")
    if len(token) < 32:
        parser.error("set a random AGENT_TEST_SERVICE_TOKEN of at least 32 characters")
    target = SyntheticTarget()
    manager = JobManager({"synthetic-wesmart": target.target()}, LocalStore(args.data_dir, (token, target.canary)))
    try:
        import uvicorn
        print("Synthetic demo only; MCP service uses loopback and requires Bearer authentication.")
        uvicorn.run(create_app(manager, token), host="127.0.0.1", port=args.port, log_level="warning", access_log=False)
    finally:
        manager.close()
        target.stop()


if __name__ == "__main__":
    main()
