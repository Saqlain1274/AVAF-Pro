"""
===============================================================================
AVAF Pro

HTTP Exchange Models

Represents a complete HTTP transaction used throughout the
validation pipeline.

These models are shared by:

• HTTP Client
• Replay Validator
• Analysis Validator
• Verification Validator
• Evidence Engine
• Reporting Engine

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# HTTP REQUEST
# =============================================================================

@dataclass(slots=True)
class HTTPRequest:
    """
    Represents an outgoing HTTP request.
    """

    method: str

    url: str

    http_version: str = "HTTP/1.1"
   
    headers: dict[str, str] = field(default_factory=dict)

    cookies: dict[str, str] = field(default_factory=dict)

    params: dict[str, Any] = field(default_factory=dict)

    data: dict[str, Any] = field(default_factory=dict)

    json: dict[str, Any] | None = None

    body: str | None = None


# =============================================================================
# HTTP RESPONSE
# =============================================================================

@dataclass(slots=True)
class HTTPResponse:
    """
    Represents an incoming HTTP response.
    """

    status: int

    url: str

    headers: dict[str, str] = field(default_factory=dict)

    cookies: dict[str, str] = field(default_factory=dict)

    body: str = ""

    elapsed: float = 0.0

    content_length: int = 0

    redirect_history: list[str] = field(default_factory=list)

    encoding: str = "utf-8"


# =============================================================================
# HTTP EXCHANGE
# =============================================================================

@dataclass(slots=True)
class HTTPExchange:
    """
    Complete HTTP transaction.
    """

    request: HTTPRequest

    response: HTTPResponse
    
    final_url: str = ""

    successful: bool = True

    error: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)