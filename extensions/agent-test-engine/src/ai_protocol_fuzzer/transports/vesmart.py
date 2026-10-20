"""Dual-channel SSE, verified against synthetic fixtures pending local protocol review."""
from __future__ import annotations

import asyncio
import copy
import codecs
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx

from ai_protocol_fuzzer.models.config import EndpointConfig
from ai_protocol_fuzzer.models.session import SessionState
from ai_protocol_fuzzer.transports.base import BaseTransport, TransportResponse


class _StreamFailure(Exception):
    def __init__(self, status: str, message: str, code: int = 0):
        self.status, self.message, self.code = status, message, code


class MessageAssembler:
    """Merge snapshots/deltas per message and part, excluding known user echoes."""

    def __init__(self, session_id: str, previous_messages: set[str]):
        self.session_id = session_id
        self.previous = previous_messages
        self.roles: dict[str, str] = {}
        self.parts: dict[tuple[str, str], str] = {}
        self.message_id = ""
        self.correlated = False

    @property
    def text(self) -> str:
        if self.roles.get(self.message_id) == "user":
            return ""
        return "".join(value for (mid, _), value in self.parts.items() if mid == self.message_id)

    def consume(self, event: dict) -> None:
        props = event.get("properties", {})
        part, info = props.get("part", {}), props.get("info", {})
        sid = props.get("sessionID") or part.get("sessionID") or info.get("sessionID")
        if sid and sid != self.session_id:
            return
        kind = event.get("type")
        if kind == "message.updated":
            self.roles[info.get("id", "")] = info.get("role", "")
            self.correlated = self.roles.get(self.message_id) == "assistant"
            return
        mid = part.get("messageID") or props.get("messageID") or "unattributed"
        if mid in self.previous or self.roles.get(mid) == "user":
            return
        if kind == "message.part.updated" and part.get("type") == "text":
            pid, value = part.get("id", "text"), part.get("text", "")
            if not isinstance(value, str):
                return
            self.parts[(mid, pid)] = value
        elif kind == "message.part.delta" and props.get("field", "text") == "text":
            pid, delta = props.get("partID", "text"), props.get("delta", "")
            if not isinstance(delta, str):
                return
            self.parts[(mid, pid)] = self.parts.get((mid, pid), "") + delta
        else:
            return
        self.message_id = mid
        self.correlated = self.roles.get(mid) == "assistant" and mid != "unattributed"


class VesmartTransport(BaseTransport):
    def send(self, config: EndpointConfig, prompt: str, session: SessionState | None = None) -> TransportResponse:
        return asyncio.run(self.send_async(config, prompt, session))

    async def send_async(self, config: EndpointConfig, prompt: str, session: SessionState | None = None) -> TransportResponse:
        state = session if session is not None else SessionState()
        if state.cancel_event.is_set():
            return TransportResponse("", status_code=0, error="cancelled", completion_status="cancelled")
        events: list[dict] = []
        metadata: dict = {"target_abort": "unsupported", "truncated": False, "response_channel": config.response_channel}
        assembler = None
        tasks: list[asyncio.Task] = []

        async def cancelled():
            while not state.cancel_event.is_set():
                await asyncio.sleep(0.02)
            raise _StreamFailure("cancelled", "client cancelled; target execution may continue")

        async def exchange():
            nonlocal assembler
            if config.session_mode not in {"server_create", "client_message_id"} or config.response_channel not in {"session_event", "prompt_sse"}:
                raise _StreamFailure("failed", "unsupported protocol configuration")
            parsed = urlsplit(config.url)
            base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.split("/session/prompt")[0].rstrip("/"), "", ""))
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment:
                raise _StreamFailure("failed", "invalid endpoint")
            parsed_params = parse_qs(parsed.query, keep_blank_values=True)
            if any(len(values) != 1 for values in parsed_params.values()):
                raise _StreamFailure("failed", "duplicate endpoint query parameters")
            context = {name: values[0] for name, values in parsed_params.items() if name != "sessionID"}
            for name, value in config.query_params.items():
                if name == "sessionID" or (name in context and context[name] != value):
                    raise _StreamFailure("failed", "conflicting endpoint query parameters")
                context[name] = value
            material = json.dumps([base, config.identity_ref, sorted(config.headers.items()), sorted(context.items()), config.json_template, config.session_mode, config.response_channel], ensure_ascii=True, sort_keys=True)
            key = "wesmart:" + hashlib.sha256(material.encode()).hexdigest()
            binding = state.variables.get(key, {})
            session_id = parsed_params.get("sessionID", [""])[0]
            if config.session_mode == "client_message_id" and session_id not in {"", "auto"}:
                raise _StreamFailure("failed", "client sessions cannot reuse a captured session id")
            async def initial_request(request):
                if config.timestamp_header:
                    request.headers["t_time"] = str(time.time_ns() // 1_000_000)
                if config.request_hook:
                    await config.request_hook(request)
            async with httpx.AsyncClient(
                headers=dict(config.headers), verify=config.verify_ssl, proxy=config.proxy or None,
                trust_env=False, follow_redirects=False, timeout=float(config.timeout),
                event_hooks={"request": [initial_request]},
            ) as client:
                async def post_bounded(path: str, body: dict, params=None, byte_limit=65536):
                    raw = bytearray()
                    async with client.stream("POST", path, json=body, params=params, headers={"Accept-Encoding": "identity"}) as response:
                        if response.headers.get("content-encoding", "identity") not in {"identity", ""}:
                            raise _StreamFailure("failed", "compressed control response is not supported")
                        async for chunk in response.aiter_raw():
                            raw.extend(chunk)
                            if len(raw) > byte_limit:
                                metadata["truncated"] = True
                                raise _StreamFailure("failed", "control response byte budget exceeded")
                        return response.status_code, bytes(raw)

                if not session_id or session_id == "auto":
                    session_id = binding.get("session_id", "")
                    if not session_id:
                        if config.session_mode == "client_message_id":
                            session_id = "ses_" + uuid.uuid4().hex
                        else:
                            created_code, created_body = await post_bounded(base + "/session", {}, context)
                            if created_code not in {200, 201}:
                                raise _StreamFailure("failed", "session creation rejected", created_code)
                            try:
                                session_id = json.loads(created_body)["id"]
                            except (ValueError, KeyError, TypeError):
                                raise _StreamFailure("failed", "session creation returned no id")
                        if not isinstance(session_id, str) or not session_id:
                            raise _StreamFailure("failed", "invalid session id")
                if config.session_mode == "client_message_id":
                    allocation_code, _ = await post_bounded(base + "/session/message/id", {}, {**context, "sessionID": session_id})
                    if allocation_code not in {200, 201}:
                        raise _StreamFailure("failed", "message id allocation rejected", allocation_code)
                previous = set(binding.get("messages", [])) if binding.get("session_id") == session_id else set()
                state.variables[key] = {"session_id": session_id, "messages": list(previous)}
                metadata["session_id"] = session_id
                assembler = MessageAssembler(session_id, previous)
                ready, submitted = asyncio.Event(), asyncio.Event()
                size = 0

                async def guarded_request(request):
                    is_prompt = request.method == "POST" and request.url.path.endswith("/session/prompt")
                    await initial_request(request)
                    if state.cancel_event.is_set():
                        raise _StreamFailure("cancelled", "client cancelled before request submission")
                    if is_prompt:
                        submitted.set()

                client.event_hooks["request"] = [guarded_request]

                async def listen(prompt_body=None):
                    nonlocal size
                    stream_headers = {"Accept": "text/event-stream", "Accept-Encoding": "identity"}
                    method = "POST" if prompt_body is not None else "GET"
                    path = "/session/prompt" if prompt_body is not None else "/session/event"
                    kwargs = {"json": prompt_body} if prompt_body is not None else {}
                    async with client.stream(method, base + path, params={**context, "sessionID": session_id}, headers=stream_headers, **kwargs) as response:
                        if response.status_code != 200:
                            raise _StreamFailure("failed", "SSE connection rejected", response.status_code)
                        if "text/event-stream" not in response.headers.get("content-type", ""):
                            raise _StreamFailure("failed", "expected SSE content type", response.status_code)
                        if response.headers.get("content-encoding", "identity") not in {"identity", ""}:
                            raise _StreamFailure("failed", "compressed SSE is not supported by this bounded collector")
                        ready.set()
                        data_lines: list[str] = []
                        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                        buffer = ""

                        def handle_line(line: str) -> bool:
                            if line.startswith("data:"):
                                data_lines.append(line[5:].lstrip(" "))
                                return False
                            if line or not data_lines:
                                return False
                            raw = "\n".join(data_lines)
                            data_lines.clear()
                            try:
                                event = json.loads(raw)
                            except ValueError:
                                return False
                            if not isinstance(event, dict):
                                return False
                            if len(events) >= config.max_events:
                                metadata["truncated"] = True
                                raise _StreamFailure("failed", "SSE event budget exceeded")
                            events.append(event)
                            if not submitted.is_set():
                                props = event.get("properties", {})
                                mid = props.get("info", {}).get("id") or props.get("part", {}).get("messageID")
                                if mid:
                                    assembler.previous.add(mid)
                                return False
                            assembler.consume(event)
                            props = event.get("properties", {})
                            if props.get("sessionID") not in {None, session_id}:
                                return False
                            # New completion aliases require explicit session context on the
                            # subscription channel. A prompt response is request scoped.
                            contextual = props.get("sessionID") == session_id or prompt_body is not None
                            if event.get("type") == "session.error":
                                if config.session_mode == "server_create" or contextual:
                                    raise _StreamFailure("failed", "target session error")
                                return False
                            legacy_idle = event.get("type") == "session.status" and props.get("status", {}).get("type") == "idle"
                            terminal = legacy_idle or event.get("type") in {"session.idle", "turn-complete"}
                            if config.session_mode == "client_message_id" or not legacy_idle:
                                terminal = terminal and contextual
                            return bool(terminal and assembler.text)

                        async for chunk in response.aiter_raw():
                            size += len(chunk)
                            if size > config.max_event_bytes:
                                metadata["truncated"] = True
                                raise _StreamFailure("failed", "SSE byte budget exceeded")
                            buffer += decoder.decode(chunk)
                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)
                                if handle_line(line.rstrip("\r")):
                                    return
                        raise _StreamFailure("failed", "SSE ended without matching completion")

                body = self._build_body(config, prompt)
                if config.response_channel == "prompt_sse":
                    await listen(body)
                else:
                    listener = asyncio.create_task(listen())
                    ready_wait = asyncio.create_task(ready.wait())
                    tasks.extend([listener, ready_wait])
                    done, _ = await asyncio.wait([listener, ready_wait], return_when=asyncio.FIRST_COMPLETED)
                    if listener in done:
                        await listener
                    await ready_wait
                    # The POST may itself be streamed; drain it independently of the
                    # authoritative session events with a separate bounded byte budget.
                    submission = asyncio.create_task(post_bounded(base + "/session/prompt", body,
                        {**context, "sessionID": session_id}, config.max_event_bytes))
                    tasks.append(submission)
                    pending = {submission, listener}
                    while pending:
                        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                        for completed in done:
                            value = await completed
                            if completed is submission and value[0] not in {200, 202, 204}:
                                raise _StreamFailure("failed", "prompt submission rejected", value[0])
                previous.update(assembler.roles)
                if assembler.message_id:
                    previous.add(assembler.message_id)
                state.variables[key] = {"session_id": session_id, "messages": list(previous)}
                metadata["message_id"] = assembler.message_id
                metadata["association"] = "assistant_message" if assembler.correlated else "session_stream_only"

        status, error, code = "completed", "", 200
        try:
            exchange_task, cancel_task = asyncio.create_task(exchange()), asyncio.create_task(cancelled())
            tasks.extend([exchange_task, cancel_task])
            done, _ = await asyncio.wait([exchange_task, cancel_task], timeout=float(config.timeout), return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise _StreamFailure("timed_out", "turn deadline exceeded")
            if cancel_task in done:
                await cancel_task
            await exchange_task
        except _StreamFailure as exc:
            status, error, code = exc.status, exc.message, exc.code
        except (httpx.TimeoutException, TimeoutError):
            status, error, code = "timed_out", "transport timeout", 0
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            status, error, code = "failed", "transport or protocol error", 0
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        return TransportResponse(assembler.text if assembler else "", events, code, error, status, metadata)

    def _build_body(self, config: EndpointConfig, prompt: str) -> dict:
        body = copy.deepcopy(config.json_template) if config.json_template else {
            **({"role": "user"} if config.session_mode == "server_create" else {}),
            "parts": [{"type": "text", "text": ""}],
        }
        if config.generate_message_ids:
            body["messageID"] = "msg_" + uuid.uuid4().hex
            for part in body.get("parts", []):
                if isinstance(part, dict):
                    part["id"] = "prt_" + uuid.uuid4().hex
        if isinstance(body.get("parts"), list):
            for part in body["parts"]:
                if isinstance(part, dict) and part.get("type") == "text":
                    part["text"] = prompt
                    return body
        for key in ("text", "message"):
            if key in body:
                body[key] = prompt
                return body
        raise ValueError("prompt template has no supported text slot")
