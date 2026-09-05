"""
AVAF Pro - Attack Result

An AttackResult represents the output of an attack detector AFTER
a real HTTP execution.

Important:
    AttackResult != confirmed vulnerability.

AttackResult only says that the attack module detected something
interesting in a real response.

Final confirmation belongs to the validation pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AttackResult:

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    attack: str
    vector: Any

    # ------------------------------------------------------------------
    # Detector result
    # ------------------------------------------------------------------

    success: bool = False

    payload: str | None = None

    indicator: str = ""

    evidence: str = ""

    confidence: float = 0.0

    # ------------------------------------------------------------------
    # REAL HTTP execution proof
    # ------------------------------------------------------------------

    request_sent: bool = False

    response_received: bool = False

    status_code: int | None = None

    response_time: float | None = None

    request_url: str = ""

    response_url: str = ""

    # ------------------------------------------------------------------
    # HTTP objects
    #
    # Kept in metadata rather than becoming part of the public
    # serialized finding.
    # ------------------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict
    )