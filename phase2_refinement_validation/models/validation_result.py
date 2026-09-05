"""
Validation Result

Represents the output of a validation stage.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from phase2_refinement_validation.models.indicator import Indicator


@dataclass
class ValidationResult:
    """
    Result returned by a validator.
    """

    # Validator name
    validator: str

    # Whether validation succeeded
    success: bool
    
    status: str = "passed"

    # Confidence score (0-100)
    confidence: float = 0.0
    
    duration: float = 0.0

    # Human-readable summary
    summary: str = ""

    # Supporting evidence
    evidence: List[Any] = field(default_factory=list)

    # Indicators discovered
    indicators: list[Indicator] = field(default_factory=list)

    # Extra runtime data
    metadata: Dict[str, Any] = field(default_factory=dict)