from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List

from ai_protocol_fuzzer.models.config import EndpointConfig
from ai_protocol_fuzzer.models.session import SessionState


@dataclass(slots=True)
class TransportResponse:
    text: str
    raw_events: List[Any] = field(default_factory=list)
    status_code: int = 200
    error: str = ""
    completion_status: str = "completed"
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseTransport:
    def send(self, config: EndpointConfig, prompt: str, session: SessionState | None = None) -> TransportResponse:
        raise NotImplementedError
