"""Versioned event envelope; target data never sets its own provenance."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4


EventSource = Literal["controller", "attacker_runner", "target_client_event", "target_server", "tool_stub"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class TestEvent:
    run_id: str
    attempt_id: str
    sequence: int
    event_type: str
    source: EventSource
    payload: dict[str, Any]
    session_id: str = ""
    message_id: str = ""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=utc_now)
    schema_version: int = 1

    def to_dict(self) -> dict:
        return asdict(self)
