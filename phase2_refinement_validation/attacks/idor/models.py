"""
===============================================================================
IDOR Models
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class IdentifierCandidate:
    """
    Represents a possible object identifier discovered in a request.
    """

    source: str              # url, query, json, form
    name: str                # id, user_id, account, order_id...
    original_value: str
    replacement_value: str


@dataclass(slots=True)
class ResponseComparison:

    original_status: int

    modified_status: int

    similarity: float

    original_length: int

    modified_length: int

    significant_change: bool

    differences: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IDOREvidence:

    identifier: IdentifierCandidate

    comparison: ResponseComparison

    original_response: Any

    modified_response: Any