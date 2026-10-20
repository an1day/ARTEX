from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from threading import Event


@dataclass(slots=True)
class SessionState:
    cancel_event: Event = field(default_factory=Event, repr=False)
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    learning_history: Dict[str, List[Any]] = field(
        default_factory=lambda: {
            "successful_patterns": [],
            "failed_patterns": [],
            "defense_mechanisms": [],
        }
    )
    variables: Dict[str, Any] = field(default_factory=dict)
