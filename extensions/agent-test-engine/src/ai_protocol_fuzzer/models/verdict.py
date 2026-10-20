from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal


Outcome = Literal["violated", "no_violation_observed", "inconclusive", "blocked", "error", "skipped"]


@dataclass(frozen=True, slots=True)
class Verdict:
    outcome: Outcome
    finding_status: Literal["candidate", "confirmed", "rejected", "none"] = "none"
    evidence_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    assertion_results: dict[str, bool] = field(default_factory=dict)
    violated_policy: str = ""
    verifier_version: str = "1.0"
    simulation: bool = False

    def to_dict(self) -> dict:
        return asdict(self)
