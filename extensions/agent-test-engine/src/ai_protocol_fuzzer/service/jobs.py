from __future__ import annotations

import asyncio
import hashlib
import json
import ipaddress
import queue
import socket
import threading
import time
from dataclasses import replace
from uuid import uuid4
from urllib.parse import urlsplit

from ai_protocol_fuzzer.models.events import TestEvent, utc_now
from ai_protocol_fuzzer.models.session import SessionState
from ai_protocol_fuzzer.models.verdict import Verdict
from ai_protocol_fuzzer.transports.vesmart import VesmartTransport
from ai_protocol_fuzzer.verification.verifier import verify_canary
from .registry import CASES, RegisteredTarget, normalize_origin
from .store import LocalStore


class BudgetExceeded(ValueError):
    pass


class RequestBudget:
    def __init__(self, target: RegisteredTarget, deadline: float, limit: int = 100):
        self.target, self.deadline, self.limit = target, deadline, limit
        self.requests = self.case_requests = 0
        self.next_request = 0.0
        self.peer: str | None = None

    async def __call__(self, request):
        origin, _ = normalize_origin(str(request.url).split("?", 1)[0])
        allowed, _ = normalize_origin(self.target.base_url)
        if origin != allowed or self.requests >= self.limit or self.case_requests >= 12:
            raise BudgetExceeded("request scope or budget exhausted")
        wait = max(0.0, self.next_request - time.monotonic())
        if time.monotonic() + wait >= self.deadline:
            raise BudgetExceeded("run deadline exhausted")
        await asyncio.sleep(wait)
        self.requests += 1
        self.case_requests += 1
        self.next_request = time.monotonic() + 1 / self.target.requests_per_second
        if self.target.allow_remote:
            host = urlsplit(self.target.base_url).hostname
            if self.peer is None:
                port = urlsplit(self.target.base_url).port or 443
                records = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
                addresses = sorted({record[4][0] for record in records}, key=lambda value: (":" in value, value))
                networks = [ipaddress.ip_network(cidr) for cidr in self.target.allowed_peer_cidrs]
                if not addresses:
                    raise BudgetExceeded("target DNS returned no addresses")
                for address in addresses:
                    peer = ipaddress.ip_address(address)
                    if not peer.is_global and not any(peer in network for network in networks):
                        raise BudgetExceeded("target resolved to an unapproved private or special address")
                self.peer = addresses[0]
            request.extensions["sni_hostname"] = host
            request.url = request.url.copy_with(host=self.peer)


class JobManager:
    def __init__(self, registry: dict[str, RegisteredTarget], store: LocalStore):
        self.registry, self.store = registry, store
        self._queue: queue.Queue = queue.Queue(maxsize=32)
        self._lock = threading.RLock()
        self._stopping = False
        self._cancels: dict[str, threading.Event] = {}
        self._worker = threading.Thread(target=self._work, name="agent-test-worker", daemon=True)
        self._worker.start()

    def capabilities(self, target_id: str = "") -> list[dict]:
        if target_id and target_id not in self.registry:
            raise ValueError("unknown target_id")
        return [t.public() for t in self.registry.values() if not target_id or t.target_id == target_id]

    def start(self, target_id: str, case_ids: list[str], scope_revision: str, idempotency_key: str,
              task_id: str = "", intent_id: str = "") -> dict:
        target = self.registry.get(target_id)
        if not target or not target.enabled:
            raise ValueError("target is not registered and enabled")
        if scope_revision != target.scope_revision:
            raise ValueError("scope_revision mismatch")
        if not case_ids or len(case_ids) > 3 or len(set(case_ids)) != len(case_ids) or any(c not in target.allowed_cases for c in case_ids):
            raise ValueError("case selection is not allowed")
        if not 1 <= len(idempotency_key) <= 128 or len(task_id) > 100 or len(intent_id) > 100:
            raise ValueError("invalid correlation or idempotency key")
        request = {"target_id": target_id, "case_ids": case_ids, "scope_revision": scope_revision, "task_id": task_id, "intent_id": intent_id}
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        with self._lock:
            if self._stopping:
                raise ValueError("service is shutting down")
            if self._queue.full():
                raise ValueError("run queue is full")
            run_id = str(uuid4())
            record = {"schema_version": 1, "run_id": run_id, **request, "status": "queued", "created_at": utc_now(),
                      "source_commit": target.source_commit, "identity_ref": target.identity_ref, "simulation": target.simulation,
                      "case_pack_version": "1.0", "requests": 0, "results": [], "target_abort": "unsupported"}
            record, created = self.store.create(idempotency_key, fingerprint, record)
            if created:
                self._cancels[run_id] = threading.Event()
                self._queue.put_nowait(run_id)
            return record

    def cancel(self, run_id: str) -> dict:
        with self._lock:
            run = self.store.get(run_id)
            if run["status"] not in {"queued", "running", "cancelling"}:
                return run
            event = self._cancels.get(run_id)
            if event:
                event.set()
            return self.store.update(run_id, status="cancelling", target_abort="unsupported; target execution may continue")

    def _work(self):
        while True:
            run_id = self._queue.get()
            if run_id is None:
                self._queue.task_done()
                return
            try:
                self._execute(run_id)
            except Exception:
                # No target body, auth value or exception URL is persisted.
                self.store.update(run_id, status="failed", error="runner failed; inspect local diagnostics", finished_at=utc_now())
            finally:
                with self._lock:
                    self._cancels.pop(run_id, None)
                self._queue.task_done()

    def _execute(self, run_id: str):
        run = self.store.get(run_id)
        target = self.registry[run["target_id"]]
        cancel = self._cancels[run_id]
        budget = RequestBudget(target, time.monotonic() + 1200)
        run_deadline = budget.deadline
        self.store.update(run_id, status="running", started_at=utc_now())
        results = []
        status = "completed"
        for case_id in run["case_ids"]:
            if cancel.is_set():
                status = "cancelled"
                break
            budget.case_requests = 0
            case = CASES[case_id]
            if case.get("blocked") or case_id == "T08" and not target.canary:
                reason = case.get("blocked") or "target-owned canary is not configured"
                results.append({"case_id": case_id, "verdict": Verdict("blocked", limitations=(reason,), simulation=target.simulation).to_dict(), "observations": []})
                self.store.update(run_id, results=results)
                continue
            case_deadline = min(run_deadline, time.monotonic() + target.case_timeout)
            budget.deadline = case_deadline
            observations, refs = [], []
            state = SessionState(cancel_event=cancel)
            for prompt in case["prompts"]:
                if cancel.is_set():
                    status = "cancelled"
                    break
                if time.monotonic() >= case_deadline:
                    status = "timed_out"
                    break
                if case_id == "T08":
                    state = SessionState(cancel_event=cancel)
                config = replace(target.endpoint(), timeout=min(target.request_timeout, case_deadline - time.monotonic()), request_hook=budget)
                response = VesmartTransport().send(config, prompt, state)
                attempt_id = str(uuid4())
                event_list = [TestEvent(run_id, attempt_id, i, str(e.get("type", "unknown")), "target_client_event", e,
                    response.metadata.get("session_id", ""), response.metadata.get("message_id", "")).to_dict() for i, e in enumerate(response.raw_events)]
                event_list.append(TestEvent(run_id, attempt_id, len(event_list), "turn.result", "attacker_runner", {
                    "text": response.text, "status": response.completion_status, "error": response.error, "metadata": response.metadata,
                }).to_dict())
                ref = self.store.put_artifact(run_id, attempt_id, event_list, target.simulation)
                refs.append(ref)
                observations.append({"attempt_id": attempt_id, "session_id": response.metadata.get("session_id", ""),
                    "healthy": response.completion_status == "completed" and not response.metadata.get("truncated") and bool(response.text),
                    "canary_present": bool(target.canary and target.canary in response.text), "target_owned_marker": bool(target.canary),
                    "input_contains_canary": bool(target.canary and target.canary in prompt), "completion_status": response.completion_status})
                observations[-1]["association"] = response.metadata.get("association", "unknown")
                self.store.update(run_id, requests=budget.requests)
                if response.completion_status != "completed":
                    status = "cancelled" if cancel.is_set() else "timed_out" if response.completion_status == "timed_out" else "failed"
                    break
            if case_id == "T08":
                verdict = verify_canary(observations, tuple(refs), simulation=target.simulation)
            else:
                healthy = len(observations) == 2 and all(o["healthy"] for o in observations)
                verdict = Verdict("no_violation_observed" if healthy else "inconclusive", evidence_refs=tuple(refs),
                                  limitations=("protocol baseline only; does not establish Agent security",), simulation=target.simulation)
            results.append({"case_id": case_id, "verdict": verdict.to_dict(), "observations": observations})
            self.store.update(run_id, results=results, requests=budget.requests)
            if status != "completed":
                break
        with self._lock:
            if cancel.is_set():
                status = "cancelled"
            self.store.update(run_id, status=status, results=results, requests=budget.requests, finished_at=utc_now())

    def verify(self, run_id: str, case_id: str) -> dict:
        run = self.store.get(run_id)
        if run["status"] not in {"completed", "failed", "timed_out", "cancelled"}:
            raise ValueError("run has not settled")
        result = next((r for r in run["results"] if r["case_id"] == case_id), None)
        if not result:
            raise ValueError("unknown result")
        for ref in result["verdict"]["evidence_refs"]:
            self.store.read_artifact(run_id, ref)
        if case_id == "T08" and result["observations"]:
            return verify_canary(result["observations"], tuple(result["verdict"]["evidence_refs"]), simulation=run["simulation"]).to_dict()
        return result["verdict"]

    def close(self):
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            for event in self._cancels.values():
                event.set()
        self._queue.put(None)
        self._worker.join(timeout=70)
        if self._worker.is_alive():
            raise RuntimeError("worker did not stop; store left open")
        self.store.close()
