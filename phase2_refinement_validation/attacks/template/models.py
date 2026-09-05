"""
===============================================================================
Internal Plugin Models

These models are private to one attack implementation.

They must never be imported by the framework.
===============================================================================
"""

from dataclasses import dataclass


@dataclass
class DetectionMatch:
    """
    Example internal detection model.
    """

    payload: str
    evidence: str
    confidence: float