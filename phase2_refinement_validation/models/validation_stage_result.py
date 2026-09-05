"""
===============================================================================

Validation Stage Result

Represents the result produced by one validation stage.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phase2_refinement_validation.core.evidence import Evidence


@dataclass(slots=True)
class ValidationStageResult:

    # Stage Name
    stage: str

    # Pass / Fail
    passed: bool

    # Confidence added by this stage
    confidence: float = 0.0

    # Human readable explanation
    reason: str = ""

    # Evidence collected
    evidence: list[Evidence] = field(default_factory=list)

    # Extra metadata
    metadata: dict[str, Any] = field(default_factory=dict)