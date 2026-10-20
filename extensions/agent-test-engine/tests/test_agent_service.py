from __future__ import annotations

import json
import time
import asyncio
from dataclasses import replace

import pytest

from ai_protocol_fuzzer.evaluators.llm_judge import LLMJudge
from ai_protocol_fuzzer.service.jobs import JobManager
from ai_protocol_fuzzer.service.registry import RegisteredTarget, load_registry, local_origin
from ai_protocol_fuzzer.service.store import LocalStore
from ai_protocol_fuzzer.verification.verifier import verify_canary
from test_wesmart_transport import wesmart_fixture  # shared synthetic server fixture


def target(server):
    return RegisteredTarget("fixture", server.base, "fixture-v1", "test-a", True, ("T03", "T08", "T09"), "synthetic-v1", True, {},
                            server.canary, request_timeout=2, requests_per_second=1000)


def wait_run(manager, run_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        run = manager.store.get(run_id)
        if run["status"] not in {"queued", "running", "cancelling"}:
            return run
        time.sleep(0.02)
    pytest.fail("synthetic run failed to settle")


def test_controller_cannot_promote_evidence():
    judge = LLMJudge()
    for result in [judge.evaluate_multiturn("SUCCESS: executed"), judge.evaluate_staged("SUCCESS: executed\nNEW_INFO: tool called"), judge.heuristic_or_controller("SUCCESS: yes", "ok")]:
        assert result.evidence_level == "L1"
        assert result.finding_status == "candidate"


@pytest.mark.parametrize("url", ["https://example.com", "http://10.0.0.1", "http://127.0.0.1.evil.test", "http://u:p@127.0.0.1", "http://127.0.0.1/?x=1"])
def test_scope_fails_closed(url):
    with pytest.raises(ValueError):
        local_origin(url)


def test_registry_disabled_and_live_review_required(tmp_path):
    path = tmp_path / "registry.yaml"
    raw = {"schema_version": 1, "targets": [{"target_id": "local", "base_url": "http://127.0.0.1:9000", "allowed_origins": ["http://127.0.0.1:9000"], "scope_revision": "v1", "identity_ref": "A", "allowed_cases": ["T03"], "enabled": False}]}
    path.write_text(json.dumps(raw))
    assert not load_registry(path)["local"].enabled
    raw["targets"][0]["enabled"] = True
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="protocol_reviewed"):
        load_registry(path)


def test_idempotency_artifacts_blocked_and_integrity(tmp_path, wesmart_fixture):
    store = LocalStore(tmp_path / "data", ("fixture-private-secret",))
    manager = JobManager({"fixture": target(wesmart_fixture)}, store)
    try:
        run = manager.start("fixture", ["T03", "T09"], "fixture-v1", "request-1")
        again = manager.start("fixture", ["T03", "T09"], "fixture-v1", "request-1")
        assert run["run_id"] == again["run_id"]
        with pytest.raises(ValueError):
            manager.start("fixture", ["T03"], "fixture-v1", "request-1")
        settled = wait_run(manager, run["run_id"])
        assert settled["status"] == "completed"
        assert settled["requests"] == 5  # create + (stream + prompt) * two turns
        assert settled["results"][1]["verdict"]["outcome"] == "blocked"
        assert len(store.manifest(run["run_id"])) == 2
        item = store.manifest(run["run_id"])[0]
        assert len(store.read_artifact(run["run_id"], item["artifact_id"])) == item["bytes"]
        (store.root / (item["artifact_id"] + ".ndjson")).write_bytes(b"tampered")
        with pytest.raises(ValueError, match="integrity"):
            manager.verify(run["run_id"], "T03")
        with pytest.raises(ValueError):
            store.read_artifact(run["run_id"], "../../etc/passwd")
    finally:
        manager.close()


def test_simulated_canary_does_not_become_real_finding(tmp_path, wesmart_fixture):
    wesmart_fixture.canary = "TEST-4c8e91a2-PRIVATE-CANARY-76b3"
    store = LocalStore(tmp_path / "data", (wesmart_fixture.canary,))
    manager = JobManager({"fixture": target(wesmart_fixture)}, store)
    try:
        run = manager.start("fixture", ["T08"], "fixture-v1", "canary-1")
        settled = wait_run(manager, run["run_id"])
        verdict = manager.verify(run["run_id"], "T08")
        assert settled["status"] == "completed"
        assert verdict["outcome"] == "violated"
        assert verdict["finding_status"] == "candidate"
        assert verdict["simulation"]
        for item in store.manifest(run["run_id"]):
            assert wesmart_fixture.canary.encode() not in store.read_artifact(run["run_id"], item["artifact_id"])
    finally:
        manager.close()


def test_restart_marks_running_interrupted(tmp_path):
    store = LocalStore(tmp_path)
    store.create("key", "fingerprint", {"run_id": "run", "status": "running"})
    with pytest.raises(ValueError, match="another service"):
        LocalStore(tmp_path)
    store.close()
    reopened = LocalStore(tmp_path)
    assert reopened.get("run")["status"] == "interrupted"
    reopened.close()


def test_canary_echo_and_missing_proof_never_confirmed():
    observation = {"healthy": True, "canary_present": True, "target_owned_marker": True, "input_contains_canary": True, "session_id": "same"}
    verdict = verify_canary([observation] * 3, ("a", "b", "c"), simulation=False)
    assert verdict.finding_status != "confirmed"


def test_mcp_requires_auth_and_serves_official_sdk(tmp_path):
    from starlette.testclient import TestClient
    from ai_protocol_fuzzer.service.server import create_app
    token = "synthetic-service-token-32-characters-minimum"
    manager = JobManager({}, LocalStore(tmp_path))
    with TestClient(create_app(manager, token), base_url="http://127.0.0.1:8791") as client:
        assert client.post("/mcp", json={}).status_code == 401
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"}
        init = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}})
        assert init.status_code == 200
        response = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_test_run", "arguments": {}}})
        assert response.status_code == 200
        result = response.json()["result"]
        assert not result.get("isError"), result
        content = result.get("structuredContent") or json.loads(result["content"][0]["text"])
        assert content == {"runs": []}


def test_pre_dns_is_pinned_and_private_peers_require_explicit_network(monkeypatch, wesmart_fixture):
    import socket
    import httpx
    from ai_protocol_fuzzer.service.jobs import RequestBudget, BudgetExceeded
    remote = replace(target(wesmart_fixture), base_url="https://pre.example.test:443", allow_remote=True, environment="pre")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.2.3.4", 443))])
    request = httpx.Request("GET", "https://pre.example.test/session/event?sessionID=test")
    with pytest.raises(BudgetExceeded, match="unapproved"):
        asyncio.run(RequestBudget(remote, time.monotonic()+5)(request))
    allowed = replace(remote, allowed_peer_cidrs=("10.2.3.4/32",))
    request = httpx.Request("GET", "https://pre.example.test/session/event?sessionID=test")
    asyncio.run(RequestBudget(allowed, time.monotonic()+5)(request))
    assert request.url.host == "10.2.3.4"
    assert request.headers["host"] == "pre.example.test"
    assert request.extensions["sni_hostname"] == "pre.example.test"
    wrong = httpx.Request("GET", "https://pre.example.test.evil.test/session")
    with pytest.raises(BudgetExceeded):
        asyncio.run(RequestBudget(allowed, time.monotonic()+5)(wrong))


def test_pre_registry_requires_https_and_exact_origin(tmp_path):
    path = tmp_path / "pre.yaml"
    raw = {"schema_version": 1, "targets": [{"target_id": "pre", "environment": "pre", "allow_remote": True,
        "base_url": "https://pre.example.test", "allowed_origins": ["https://pre.example.test"], "scope_revision": "pre-v1",
        "identity_ref": "A", "allowed_cases": ["T03"], "enabled": False}]}
    path.write_text(json.dumps(raw))
    assert load_registry(path)["pre"].allow_remote
    raw["targets"][0]["base_url"] = "http://pre.example.test"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="HTTPS"):
        load_registry(path)


def test_gateway_registry_env_credentials_and_protocol_options(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXTURE_TOKEN", "fixture-credential-only")
    monkeypatch.setenv("FIXTURE_DEVICE", "fixture-device-only")
    monkeypatch.setenv("FIXTURE_WORKSPACE", "fixture-workspace-only")
    path = tmp_path / "registry.yaml"
    item = {"target_id": "gateway", "base_url": "http://127.0.0.1:9000/api/bullgpt-vega",
        "allowed_origins": ["http://127.0.0.1:9000"], "scope_revision": "v1", "identity_ref": "A",
        "allowed_cases": ["T03"], "enabled": False,
        "headers": {"app": "global", "origin": "https://ui.example.test"},
        "headers_env": {"access_token": "FIXTURE_TOKEN", "did": "FIXTURE_DEVICE"},
        "query_params": {"appID": "work"}, "query_params_env": {"workspaceID": "FIXTURE_WORKSPACE"},
        "model_selection": {"modelID": "fixture-model", "providerID": "fixture"},
        "generate_message_ids": True, "timestamp_header": True}
    path.write_text(json.dumps({"schema_version": 1, "targets": [item]}))
    registered = load_registry(path)["gateway"]
    config = registered.endpoint()
    assert config.query_params == {"appID": "work", "workspaceID": "fixture-workspace-only"}
    assert config.headers["access_token"] == "fixture-credential-only"
    assert config.generate_message_ids and config.timestamp_header
    assert config.json_template["model"]["modelID"] == "fixture-model"
    assert "fixture-credential-only" not in repr(registered)
    assert "fixture-workspace-only" not in json.dumps(registered.public())
    item["headers"]["access_token"] = "inline-secret-forbidden"
    path.write_text(json.dumps({"schema_version": 1, "targets": [item]}))
    with pytest.raises(ValueError, match="headers_env"):
        load_registry(path)


def test_gateway_sensitive_fields_are_redacted(tmp_path):
    store = LocalStore(tmp_path)
    try:
        fields = {key: "fixture-value" for key in ["access_token", "refresh_token", "did", "workspaceID"]}
        assert set(store.redact(fields).values()) == {"[REDACTED]"}
    finally:
        store.close()


def test_positive_canary_requires_correlated_repeated_observation():
    base = {"healthy": True, "target_owned_marker": True, "input_contains_canary": False, "association": "assistant_message"}
    observations = [{**base, "session_id": "baseline", "canary_present": False},
                    {**base, "session_id": "first", "canary_present": True},
                    {**base, "session_id": "second", "canary_present": True}]
    assert verify_canary(observations, ("a", "b", "c"), simulation=False).finding_status == "confirmed"
    observations[2]["association"] = "session_stream_only"
    assert verify_canary(observations, ("a", "b", "c"), simulation=False).finding_status != "confirmed"


def test_job_cancel_settles_and_preserves_abort_limitation(tmp_path, wesmart_fixture):
    wesmart_fixture.hold = True
    manager = JobManager({"fixture": target(wesmart_fixture)}, LocalStore(tmp_path))
    try:
        run = manager.start("fixture", ["T03"], "fixture-v1", "cancel-1")
        manager.cancel(run["run_id"])
        settled = wait_run(manager, run["run_id"])
        assert settled["status"] == "cancelled"
        assert "unsupported" in settled["target_abort"]
    finally:
        manager.close()
