"""
===============================================================================
AVAF Pro

Attack Plan

Produced by the Response Engine from a Phase-1 candidate.

One AttackPlan represents ONE validation workflow.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AttackPlan:
    """
    Validation plan for a single Phase-1 candidate.
    """

    # ---------------------------------------------------------
    # Phase-1 Candidate
    # ---------------------------------------------------------

    vector_id: str

    vulnerability_type: str

    confidence: float

    risk: str

    # ---------------------------------------------------------
    # Target
    # ---------------------------------------------------------

    method: str

    url: str

    parameter: str

    location: str
    
    content_type: str = ""
    
    

    original_value: Any = None
    
    # ---------------------------------------------------------
    # Validation Limits
    # ---------------------------------------------------------
    
    max_attempts: int = 5
    
    timeout: int = 15
    

    # ---------------------------------------------------------
    # Runtime
    # ---------------------------------------------------------

    metadata: dict[str, Any] = field(default_factory=dict)