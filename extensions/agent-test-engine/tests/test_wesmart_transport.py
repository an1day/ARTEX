from __future__ import annotations

import json
import asyncio
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from ai_protocol_fuzzer.models.config import EndpointConfig
from ai_protocol_fuzzer.models.session import SessionState
from ai_protocol_fuzzer.transports.vesmart import MessageAssembler, VesmartTransport


@pytest.fixture
def wesmart_fixture():
    class Server(ThreadingHTTPServer):
        daemon_threads = True
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def json_response(self, code, value):
            raw = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            path = urlsplit(self.path)
            if path.path == "/session":
                with server.lock:
                    sid = "ses" + str(len(server.sessions) + 1)
                    server.sessions[sid] = queue.Queue()
                self.json_response(200, {"id": sid})
                return
            if path.path != "/session/prompt":
                self.json_response(404, {})
                return
            sid = parse_qs(path.query)["sessionID"][0]
            server.prompts.append((sid, body))
            self.json_response(server.prompt_status, {})
            if server.hold or server.prompt_status != 200:
                return
            mid = "msg" + str(len(server.prompts))
            text = body["parts"][0]["text"]
            output = server.canary if server.canary and "private internal" in text else "BASELINE_OK" if "BASELINE" in text else "SECOND_TURN_OK"
            events = [{"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}},
                      {"type": "message.updated", "properties": {"info": {"id": mid, "sessionID": sid, "role": "assistant"}}}]
            for i in range(server.extra_events):
                events.append({"type": "trace", "properties": {"index": i}})
            events.extend([
                {"type": "message.part.updated", "properties": {"part": {"id": "p", "messageID": mid, "sessionID": sid, "type": "text", "text": output[:4]}}},
                {"type": "message.part.delta", "properties": {"messageID": mid, "partID": "p", "sessionID": sid, "delta": output[4:]}},
                {"type": "message.part.updated", "properties": {"part": {"id": "p", "messageID": mid, "sessionID": sid, "type": "text", "text": output}}},
            ])
            if not server.disconnect:
                events.append({"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}})
            for event in events:
                server.sessions[sid].put(event)
            server.sessions[sid].put(None)

        def do_GET(self):
            sid = parse_qs(urlsplit(self.path).query)["sessionID"][0]
            self.send_response(server.stream_status)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            if server.stream_status != 200:
                self.close_connection = True
                return
            if server.replay:
                for event in [
                    {"type": "message.updated", "properties": {"info": {"id": "old-replay", "role": "assistant"}}},
                    {"type": "message.part.updated", "properties": {"part": {"messageID": "old-replay", "type": "text", "text": "STALE"}}},
                    {"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}},
                ]:
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                self.wfile.flush()
            try:
                while not server.stopping.is_set():
                    try:
                        event = server.sessions[sid].get(timeout=0.05)
                    except queue.Empty:
                        continue
                    if event is None:
                        break
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

    server = Server(("127.0.0.1", 0), Handler)
    server.sessions, server.prompts = {}, []
    server.lock, server.stopping = threading.Lock(), threading.Event()
    server.stream_status = server.prompt_status = 200
    server.hold = server.disconnect = False
    server.replay = False
    server.extra_events = 60
    server.canary = ""
    server.base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopping.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def endpoint(server, **kwargs):
    return EndpointConfig("synthetic", server.base + "/session/prompt", transport_kind="wesmart_dual_sse", timeout=2, **kwargs)


def test_merge_full_snapshots_long_stream_and_multiturn(wesmart_fixture):
    state = SessionState()
    first = VesmartTransport().send(endpoint(wesmart_fixture), "BASELINE", state)
    second = VesmartTransport().send(endpoint(wesmart_fixture), "SECOND", state)
    assert first.completion_status == second.completion_status == "completed"
    assert first.text == "BASELINE_OK"
    assert second.text == "SECOND_TURN_OK"
    assert len(first.raw_events) > 50
    assert first.metadata["association"] == "assistant_message"
    assert first.metadata["session_id"] == second.metadata["session_id"]
    assert first.metadata["message_id"] != second.metadata["message_id"]


def test_independent_states_and_identities_have_distinct_sessions(wesmart_fixture):
    state = SessionState()
    a = VesmartTransport().send(endpoint(wesmart_fixture, identity_ref="A"), "BASELINE", state)
    b = VesmartTransport().send(endpoint(wesmart_fixture, identity_ref="B"), "BASELINE", state)
    c = VesmartTransport().send(endpoint(wesmart_fixture, identity_ref="A"), "BASELINE", SessionState())
    assert len({a.metadata["session_id"], b.metadata["session_id"], c.metadata["session_id"]}) == 3


def test_failed_stream_does_not_submit_prompt(wesmart_fixture):
    wesmart_fixture.stream_status = 401
    response = VesmartTransport().send(endpoint(wesmart_fixture), "BASELINE")
    assert response.status_code == 401
    assert response.completion_status == "failed"
    assert not wesmart_fixture.prompts


def test_disconnect_is_not_success(wesmart_fixture):
    wesmart_fixture.disconnect = True
    response = VesmartTransport().send(endpoint(wesmart_fixture), "BASELINE")
    assert response.text == "BASELINE_OK"
    assert response.completion_status == "failed"


def test_cancel_closes_waiting_stream(wesmart_fixture):
    wesmart_fixture.hold = True
    state = SessionState()
    timer = threading.Timer(0.15, state.cancel_event.set)
    timer.start()
    response = VesmartTransport().send(endpoint(wesmart_fixture), "BASELINE", state)
    timer.join()
    assert response.completion_status == "cancelled"
    assert response.metadata["target_abort"] == "unsupported"


def test_event_limit_is_explicit(wesmart_fixture):
    config = endpoint(wesmart_fixture)
    config.max_events = 5
    response = VesmartTransport().send(config, "BASELINE")
    assert response.completion_status == "failed"
    assert response.metadata["truncated"]


def test_assembler_ignores_other_sessions_old_messages_and_user_echo():
    assembler = MessageAssembler("current", {"old"})
    assembler.consume({"type": "message.updated", "properties": {"info": {"id": "u", "role": "user"}}})
    for sid, mid in [("foreign", "x"), ("current", "old"), ("current", "u")]:
        assembler.consume({"type": "message.part.updated", "properties": {"part": {"sessionID": sid, "messageID": mid, "type": "text", "text": "echo"}}})
    assert not assembler.text


def test_pre_submission_replay_cannot_finish_new_turn(wesmart_fixture):
    wesmart_fixture.replay = True
    async def paced(request):
        if request.method == "POST" and request.url.path.endswith("/session/prompt"):
            await asyncio.sleep(0.15)
    config = endpoint(wesmart_fixture)
    config.request_hook = paced
    response = VesmartTransport().send(config, "BASELINE")
    assert response.completion_status == "completed"
    assert response.text == "BASELINE_OK"
