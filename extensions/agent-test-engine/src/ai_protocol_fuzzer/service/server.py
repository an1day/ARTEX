"""Authenticated local Streamable HTTP MCP service using the official v1 SDK."""
from __future__ import annotations

import argparse
import hmac
import os
from contextlib import asynccontextmanager

from .jobs import JobManager
from .registry import CASES, load_registry
from .store import LocalStore


class BearerAuth:
    def __init__(self, app, token: str):
        if len(token) < 32:
            raise ValueError("service token must contain at least 32 characters")
        self.app, self.expected = app, ("Bearer " + token).encode("utf-8")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            auth = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
            if len(auth) != 1 or not hmac.compare_digest(auth[0], self.expected):
                await send({"type": "http.response.start", "status": 401, "headers": [(b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"Unauthorized"})
                return
        await self.app(scope, receive, send)


def create_app(manager: JobManager, token: str):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("ARTEX Agent Test Service", stateless_http=True, json_response=True,
                  max_request_body_size=64 * 1024)

    @mcp.tool()
    def list_target_capabilities(target_id: str = "") -> dict:
        """List registered targets, permitted cases and observation limitations."""
        return {"targets": manager.capabilities(target_id)}

    @mcp.tool()
    def list_test_cases() -> dict:
        """List versioned built-in cases; no arbitrary prompt or code execution."""
        return {"case_pack_version": "1.0", "cases": [{"case_id": key, "title": case["title"], "blocked_reason": case.get("blocked", "")} for key, case in CASES.items()]}

    @mcp.tool()
    def start_test_run(target_id: str, case_ids: list[str], scope_revision: str, idempotency_key: str,
                       task_id: str = "", intent_id: str = "") -> dict:
        """Enqueue an allowlisted local test; return immediately, never start arbitrary commands."""
        return manager.start(target_id, case_ids, scope_revision, idempotency_key, task_id, intent_id)

    @mcp.tool()
    def get_test_run(run_id: str = "") -> dict:
        """Fetch a run; omit run_id to list the latest 50 runs."""
        return manager.store.get(run_id) if run_id else {"runs": manager.store.list_runs()}

    @mcp.tool()
    def cancel_test_run(run_id: str) -> dict:
        """Stop new client actions; target-side abort remains explicitly unsupported."""
        return manager.cancel(run_id)

    @mcp.tool()
    def get_evidence_manifest(run_id: str) -> dict:
        """Return immutable redacted artifact IDs, provenance, hashes and sizes."""
        return {"run_id": run_id, "artifacts": manager.store.manifest(run_id)}

    @mcp.tool()
    def get_evidence_preview(run_id: str, artifact_id: str) -> dict:
        """Read at most 8192 bytes of a hash-verified redacted artifact, by ID only."""
        raw = manager.store.read_artifact(run_id, artifact_id)
        return {"artifact_id": artifact_id, "untrusted_target_data": True, "preview": raw[:8192].decode("utf-8", errors="replace"), "preview_truncated": len(raw) > 8192}

    @mcp.tool()
    def verify_candidate(run_id: str, case_id: str) -> dict:
        """Recheck collector observations and artifact integrity; accepts no verdict or proof from the caller."""
        return manager.verify(run_id, case_id)

    app = mcp.streamable_http_app()
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def app_lifespan(application):
        # Server lifespan runs per stateless request; jobs belong to the app.
        async with original_lifespan(application):
            try:
                yield
            finally:
                manager.close()

    app.router.lifespan_context = app_lifespan
    return BearerAuth(app, token)


def main():
    parser = argparse.ArgumentParser(description="Local ARTEX Agent test MCP service")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--host", choices=["127.0.0.1", "::1"], default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()
    token = os.environ.get("AGENT_TEST_SERVICE_TOKEN", "")
    if len(token) < 32:
        parser.error("set AGENT_TEST_SERVICE_TOKEN to a random value of at least 32 characters")
    registry = load_registry(args.registry)
    secrets = [token]
    for target in registry.values():
        secrets.extend(target.headers.values())
        secrets.extend(value.split(" ", 1)[-1] for value in target.headers.values())
        if target.canary:
            secrets.append(target.canary)
    store = LocalStore(args.data_dir, tuple(secrets))
    manager = JobManager(registry, store)
    import uvicorn
    uvicorn.run(create_app(manager, token), host=args.host, port=args.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
