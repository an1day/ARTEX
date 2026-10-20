"""Real Go bridge ↔ MCP SDK ↔ synthetic SSE target. Opt in via ARTEX_CHECKOUT."""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import threading
import time

import pytest


def test_real_go_bridge_against_synthetic_target(tmp_path):
    checkout = os.environ.get("ARTEX_CHECKOUT")
    if not checkout:
        pytest.skip("set ARTEX_CHECKOUT for the cross-language synthetic integration")
    import uvicorn
    from ai_protocol_fuzzer.service.demo import SyntheticTarget
    from ai_protocol_fuzzer.service.jobs import JobManager
    from ai_protocol_fuzzer.service.server import create_app
    from ai_protocol_fuzzer.service.store import LocalStore

    token = secrets.token_hex(32)
    target = SyntheticTarget()
    manager = JobManager({"synthetic-wesmart": target.target()}, LocalStore(tmp_path, (token, target.canary)))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(manager, token), log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "synthetic MCP server failed to start"
        env = {**os.environ, "ARTEX_AGENT_TEST_INTEGRATION_URL": f"http://127.0.0.1:{port}/mcp", "AGENT_TEST_SERVICE_TOKEN": token}
        result = subprocess.run(["go", "test", "-p", "2", "./agentsecurity", "-run", "^TestLivePythonSidecar$", "-count=1"],
                                cwd=checkout, env=env, text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        manager.close()
        target.stop()
        sock.close()
