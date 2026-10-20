"""Local single-process store; durable jobs and immutable redacted artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from uuid import uuid4

from ai_protocol_fuzzer.models.events import utc_now


class LocalStore:
    def __init__(self, root: str | Path, secrets: tuple[str, ...] = ()):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.secrets = tuple(sorted({s for s in secrets if s}, key=len, reverse=True))
        self.lock = threading.RLock()
        self._process_lock = (self.root / ".service.lock").open("a+b")
        try:
            self._process_lock.seek(0)
            if self._process_lock.read(1) == b"":
                self._process_lock.write(b"0")
                self._process_lock.flush()
            self._process_lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._process_lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._process_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._process_lock.close()
            raise ValueError("another service owns this data directory") from None
        self.db = sqlite3.connect(self.root / "runs.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
          PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, idem TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL, body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, body TEXT NOT NULL);
        """)
        with self.lock:
            for row in self.db.execute("SELECT id, body FROM runs").fetchall():
                body = json.loads(row["body"])
                if body["status"] in {"queued", "running", "cancelling"}:
                    body.update(status="interrupted", finished_at=utc_now(), error="service restarted; no automatic replay")
                    self.db.execute("UPDATE runs SET body=? WHERE id=?", (json.dumps(body), row["id"]))
            self.db.commit()

    def redact(self, value):
        if isinstance(value, dict):
            return {k: "[REDACTED]" if str(k).lower() in {"authorization", "cookie", "set-cookie", "password", "api_key", "token", "secret", "access_token", "refresh_token", "id_token", "did", "workspaceid"} else self.redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact(v) for v in value]
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        return value

    def create(self, idem: str, fingerprint: str, body: dict) -> tuple[dict, bool]:
        with self.lock:
            row = self.db.execute("SELECT fingerprint,body FROM runs WHERE idem=?", (idem,)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise ValueError("idempotency key already belongs to different inputs")
                return json.loads(row["body"]), False
            self.db.execute("INSERT INTO runs VALUES (?,?,?,?)", (body["run_id"], idem, fingerprint, json.dumps(body)))
            self.db.commit()
            return body, True

    def get(self, run_id: str) -> dict:
        with self.lock:
            row = self.db.execute("SELECT body FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise ValueError("unknown run_id")
            return json.loads(row["body"])

    def update(self, run_id: str, **changes) -> dict:
        with self.lock:
            body = self.get(run_id)
            body.update(changes)
            self.db.execute("UPDATE runs SET body=? WHERE id=?", (json.dumps(body, allow_nan=False), run_id))
            self.db.commit()
            return body

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT body FROM runs ORDER BY rowid DESC LIMIT ?", (min(max(limit, 1), 100),))]

    def put_artifact(self, run_id: str, attempt_id: str, events: list[dict], simulation: bool) -> str:
        self.get(run_id)
        artifact_id = str(uuid4())
        content = "".join(json.dumps(self.redact(event), ensure_ascii=False, allow_nan=False) + "\n" for event in events).encode("utf-8")
        if len(content) > 8 * 1024 * 1024:
            raise ValueError("artifact byte budget exceeded")
        path = self.root / (artifact_id + ".ndjson")
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
        manifest = {"artifact_id": artifact_id, "run_id": run_id, "attempt_id": attempt_id,
                    "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content), "redacted": True,
                    "simulation": simulation, "source": "target_client_event", "created_at": utc_now()}
        with self.lock:
            self.db.execute("INSERT INTO artifacts VALUES (?,?,?,?)", (artifact_id, run_id, attempt_id, json.dumps(manifest)))
            self.db.commit()
        return artifact_id

    def manifest(self, run_id: str) -> list[dict]:
        self.get(run_id)
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT body FROM artifacts WHERE run_id=? ORDER BY rowid", (run_id,))]

    def read_artifact(self, run_id: str, artifact_id: str) -> bytes:
        with self.lock:
            row = self.db.execute("SELECT body FROM artifacts WHERE run_id=? AND id=?", (run_id, artifact_id)).fetchone()
        if not row:
            raise ValueError("artifact not found in this run")
        item = json.loads(row[0])
        # ID comes from the DB index, never interpreted as a supplied filesystem path.
        content = (self.root / (item["artifact_id"] + ".ndjson")).read_bytes()
        if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError("artifact integrity check failed")
        return content

    def close(self):
        with self.lock:
            if self._process_lock.closed:
                return
            self.db.close()
            if os.name == "nt":
                import msvcrt
                self._process_lock.seek(0)
                msvcrt.locking(self._process_lock.fileno(), msvcrt.LK_UNLCK, 1)
            self._process_lock.close()
