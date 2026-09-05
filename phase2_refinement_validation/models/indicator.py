
"""
===============================================================================
Indicator Model

Represents one raw detection produced by an attack detector.

Indicators are consumed by validators to determine whether a vulnerability
should become a validated Finding.
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Indicator:
    """
    Raw detection indicator.
    """

    # Detection source
    source: str

    # Indicator type
    type: str

    # Matched value
    value: str

    # Confidence
    confidence: float = 0.0

    # Additional information
    metadata: dict[str, Any] = field(default_factory=dict)