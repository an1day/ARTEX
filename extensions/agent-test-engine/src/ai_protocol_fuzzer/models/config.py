from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class HistoryConfig:
    enabled: bool = False
    field: str = "historyConvs"


@dataclass(slots=True)
class WebSocketConfig:
    config_message: Optional[Dict[str, Any] | str] = None
    ack_timeout: int = 2


@dataclass(slots=True)
class EndpointConfig:
    name: str
    url: str
    headers: Dict[str, Any] = field(default_factory=dict, repr=False)
    json_template: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    verify_ssl: bool = True
    proxy: str = ""
    history: HistoryConfig = field(default_factory=HistoryConfig)
    websocket: WebSocketConfig = field(default_factory=WebSocketConfig)
    response_extractors: List[str] = field(default_factory=list)
    model: str = ""
    transport_kind: str = "auto"
    identity_ref: str = ""
    query_params: Dict[str, str] = field(default_factory=dict, repr=False)
    generate_message_ids: bool = False
    timestamp_header: bool = False
    max_event_bytes: int = 4 * 1024 * 1024
    max_events: int = 10000
    request_hook: Any = field(default=None, repr=False)

    @property
    def transport(self) -> str:
        aliases = {"vesmart": "wesmart_dual_sse", "wesmart": "wesmart_dual_sse"}
        selected = aliases.get(self.transport_kind, self.transport_kind)
        if selected != "auto":
            if selected not in {"http", "websocket", "wesmart_dual_sse"}:
                raise ValueError("unsupported transport")
            return selected
        if self.url.startswith(("ws://", "wss://")):
            return "websocket"
        return "http"


@dataclass(slots=True)
class RunConfig:
    attacker: EndpointConfig
    target: EndpointConfig
    controller: EndpointConfig
