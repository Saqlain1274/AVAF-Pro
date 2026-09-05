"""
===============================================================================

AVAF Pro

Algorithm Result Model

Standard output format for every validation/refinement algorithm.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any

from phase2_refinement_validation.core.evidence import Evidence


@dataclass(slots=True)
class AlgorithmResult:
    """
    Standard result returned by every algorithm.
    """

    # ----------------------------------------------
    # Identity
    # ----------------------------------------------

    name: str

    category: str

    # ----------------------------------------------
    # Decision
    # ----------------------------------------------

    passed: bool

    confidence: float

    # ----------------------------------------------
    # Human Explanation
    # ----------------------------------------------

    summary: str

    evidence: list[Evidence] = field(default_factory=list)

    # ----------------------------------------------
    # Raw Algorithm Data
    # ----------------------------------------------

    metrics: dict[str, Any] = field(default_factory=dict)

    metadata: dict[str, Any] = field(default_factory=dict)