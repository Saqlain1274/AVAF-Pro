from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ==========================================================
# REQUEST
# ==========================================================

@dataclass(slots=True)
class ReplayableRequest:

    method: str

    url: str

    headers: dict[str, str]

    body: str = ""


# ==========================================================
# RESPONSE
# ==========================================================

@dataclass(slots=True)
class ReplayableResponse:

    status: int

    headers: dict[str, str]

    body_hash: str

    length: int


# ==========================================================
# HTTP EXCHANGE
# ==========================================================

@dataclass(slots=True)
class HttpExchange:

    request: ReplayableRequest

    response: ReplayableResponse

    resource_type: str = ""

    content_type: str = ""

    redirected: bool = False

    duration: float = 0.0

    metadata: dict[str, Any] = field(
        default_factory=dict
    )