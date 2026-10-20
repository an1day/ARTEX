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
            server.requests.append(("POST", self.path, dict(self.headers)))
            if server.prefix:
                if not path.path.startswith(server.prefix):
                    self.json_response(404, {})
                    return
                path = path._replace(path=path.path[len(server.prefix):])
            if path.path == "/session/message/id":
                sid = parse_qs(path.query)["sessionID"][0]
                with server.lock:
                    server.sessions.setdefault(sid, queue.Queue())
                    server.allocations.append(sid)
                    allocated = "msg_request_" + str(1 if server.reuse_allocation else len(server.allocations))
                    server.allocated[sid] = allocated
                value = server.allocation_payload if server.allocation_payload is not None else {"messageID": allocated}
                self.json_response(server.allocation_status, value)
                return
            if path.path == "/session":
                if server.client_session:
                    self.json_response(404, {})
                    return
                with server.lock:
                    sid = "ses" + str(len(server.sessions) + 1)
                    server.sessions[sid] = queue.Queue()
                self.json_response(200, {"id": sid})
                return
            if path.path != "/session/prompt":
                self.json_response(404, {})
                return
            sid = parse_qs(path.query)["sessionID"][0]
            if server.client_session and body.get("messageID") != server.allocated.get(sid):
                self.json_response(400, {})
                return
            server.prompts.append((sid, body))
            self.json_response(server.prompt_status, {})
            if server.hold or server.prompt_status != 200:
                return
            mid = "msg" + str(len(server.prompts))
            text = body["parts"][0]["text"]
            output = server.canary if server.canary and "private internal" in text else "BASELINE_OK" if "BASELINE" in text else "SECOND_TURN_OK"
            events = [{"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}},
                      {"type": "message.updated", "properties": {"info": {"id": mid, "sessionID": sid, "role": "assistant"}}}]
            if server.client_session:
                events.insert(0, {"type": "message.part.delta", "properties": {"sessionID": sid,
                    "messageID": body["messageID"], "partID": "user-part", "field": "text", "delta": "USER_ECHO"}})
            for i in range(server.extra_events):
                events.append({"type": "trace", "properties": {"index": i}})
            events.extend([
                {"type": "message.part.updated", "properties": {"part": {"id": "p", "messageID": mid, "sessionID": sid, "type": "text", "text": output[:4]}}},
                {"type": "message.part.delta", "properties": {"messageID": mid, "partID": "p", "sessionID": sid, "delta": output[4:]}},
                {"type": "message.part.updated", "properties": {"part": {"id": "p", "messageID": mid, "sessionID": sid, "type": "text", "text": output}}},
            ])
            if not server.disconnect:
                if server.client_session:
                    events.append({"type": "message.updated", "properties": {"info": {"id": mid, "time": {"completed": 1}}}})
                events.append({"type": "session.status", "properties": {"sessionID": sid, "status": {"type": "idle"}}})
                if server.client_session and server.send_session_idle:
                    events.append({"type": "session.idle", "properties": {"sessionID": server.idle_session or sid}})
            for event in events:
                server.sessions[sid].put(event)
            server.sessions[sid].put(None)

        def do_GET(self):
            server.requests.append(("GET", self.path, dict(self.headers)))
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
    server.requests, server.prefix = [], ""
    server.client_session = server.reuse_allocation = False
    server.allocations, server.allocated = [], {}
    server.allocation_status, server.allocation_payload = 200, None
    server.send_session_idle, server.idle_session = True, ""
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


def test_gateway_prefix_context_headers_model_and_fresh_ids(wesmart_fixture):
    server = wesmart_fixture
    server.prefix = "/api/bullgpt-vega"
    config = EndpointConfig("fixture", server.base + server.prefix + "/session/prompt?appID=work",
        query_params={"workspaceID": "fixture-workspace"}, headers={"access_token": "fixture-token", "did": "fixture-device"},
        json_template={"model": {"modelID": "fixture-model", "providerID": "fixture-provider"},
            "messageID": "captured-message", "parts": [{"id": "captured-part", "type": "text", "text": ""}]},
        generate_message_ids=True, timestamp_header=True, timeout=2)
    state = SessionState()
    a = VesmartTransport().send(config, "BASELINE", state)
    b = VesmartTransport().send(config, "SECOND", state)
    assert a.completion_status == b.completion_status == "completed"
    assert a.metadata["session_id"] == b.metadata["session_id"]
    assert len(server.requests) == 5
    for method, url, headers in server.requests:
        parsed = urlsplit(url)
        assert parsed.path.startswith(server.prefix + "/session")
        assert parse_qs(parsed.query)["workspaceID"] == ["fixture-workspace"]
        assert parse_qs(parsed.query)["appID"] == ["work"]
        lowered = {key.lower(): value for key, value in headers.items()}
        assert lowered["access_token"] == "fixture-token"
        assert lowered["did"] == "fixture-device"
        assert int(lowered["t_time"]) > 0
    bodies = [body for _, body in server.prompts]
    assert bodies[0]["model"] == config.json_template["model"]
    assert len({body["messageID"] for body in bodies} | {"captured-message"}) == 3
    assert len({body["parts"][0]["id"] for body in bodies} | {"captured-part"}) == 3
    assert config.json_template["messageID"] == "captured-message"
    config.query_params["workspaceID"] = "another-workspace"
    c = VesmartTransport().send(config, "BASELINE", state)
    assert c.completion_status == "completed"
    assert c.metadata["session_id"] != a.metadata["session_id"]


def test_conflicting_or_duplicate_query_rejected_before_network(wesmart_fixture):
    for query in ["?workspaceID=a&workspaceID=b", "?workspaceID=a"]:
        config = endpoint(wesmart_fixture, query_params={"workspaceID": "b"})
        config.url += query
        assert VesmartTransport().send(config, "BASELINE").completion_status == "failed"
    assert not wesmart_fixture.requests


def test_client_allocated_ids_multiturn_echo_exclusion_and_idle_chain(wesmart_fixture):
    server = wesmart_fixture
    server.client_session = True
    state = SessionState()
    config = endpoint(server, session_mode="client_message_id", query_params={"workspaceID": "fixture-work", "appID": "work"},
        json_template={"messageID": "captured-id", "parts": [{"type": "text", "id": "captured-part", "text": ""}]})
    first = VesmartTransport().send(config, "BASELINE", state)
    second = VesmartTransport().send(config, "SECOND", state)
    assert first.completion_status == second.completion_status == "completed"
    assert first.text == "BASELINE_OK" and second.text == "SECOND_TURN_OK"
    assert first.metadata["session_id"].startswith("ses_")
    assert first.metadata["session_id"] == second.metadata["session_id"]
    assert first.metadata["request_message_id"] != second.metadata["request_message_id"]
    for result, (_, body) in zip([first, second], server.prompts):
        assert body["messageID"] == result.metadata["request_message_id"]
        assert "id" not in body["parts"][0]
        assert result.metadata["message_id"] != result.metadata["request_message_id"]
        assert result.metadata["association"] == "assistant_message"
        assert result.metadata["completion_event"] == "session.idle"
        assert result.raw_events[-1]["type"] == "session.idle"
    assert len(server.allocations) == 2
    assert all(urlsplit(url).path != "/session" for _, url, _ in server.requests)


@pytest.mark.parametrize("payload,status", [({}, 200), ({"messageID": "invalid"}, 200), ([], 200), ({}, 403)])
def test_client_invalid_allocation_never_submits(wesmart_fixture, payload, status):
    server = wesmart_fixture
    server.client_session = True
    server.allocation_payload, server.allocation_status = payload, status
    response = VesmartTransport().send(endpoint(server, session_mode="client_message_id"), "BASELINE")
    assert response.completion_status == "failed"
    assert not server.prompts
    assert not any(method == "GET" for method, _, _ in server.requests)


def test_client_reused_allocation_never_replays_second_prompt(wesmart_fixture):
    server = wesmart_fixture
    server.client_session = server.reuse_allocation = True
    state = SessionState()
    config = endpoint(server, session_mode="client_message_id")
    assert VesmartTransport().send(config, "BASELINE", state).completion_status == "completed"
    assert VesmartTransport().send(config, "SECOND", state).completion_status == "failed"
    assert len(server.prompts) == 1


@pytest.mark.parametrize("idle_session", ["", "foreign-session"])
def test_client_preliminary_idle_and_foreign_completion_are_not_success(wesmart_fixture, idle_session):
    server = wesmart_fixture
    server.client_session = True
    server.send_session_idle = bool(idle_session)
    server.idle_session = idle_session
    response = VesmartTransport().send(endpoint(server, session_mode="client_message_id"), "BASELINE")
    assert response.text == "BASELINE_OK"
    assert response.completion_status == "failed"
