"""
AVAF Pro

Finding Model

Represents a validated security finding produced by Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:

    # ------------------------------------------------------------------
    # Vulnerability
    # ------------------------------------------------------------------

    attack: str
    title: str

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    severity: str
    confidence: float

    # ------------------------------------------------------------------
    # Target
    # ------------------------------------------------------------------

    url: str
    method: str
    parameter: str

    # ------------------------------------------------------------------
    # Optional classification
    # ------------------------------------------------------------------

    cvss_score: float | None = None
    cwe: str | None = None
    owasp: str | None = None

    # ------------------------------------------------------------------
    # Attack
    # ------------------------------------------------------------------

    payload: str | None = None

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    evidence: str = ""

    request: Any = None

    response: Any = None

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    recommendation: str = ""

    references: list[str] = field(
        default_factory=list
    )

    # ------------------------------------------------------------------
    # Extra
    # ------------------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict
    )