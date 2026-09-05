"""
===============================================================================
Prepared Request

Represents an HTTP request ready to be executed.

Produced by:

    AttackRequestBuilder

Consumed by:

    AttackExecutor
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass(slots=True)
class PreparedRequest:

    # HTTP Method

    method: str

    # Target URL

    url: str

    # HTTP Headers

    headers: dict[str, Any] = field(default_factory=dict)

    # Cookies

    cookies: dict[str, Any] = field(default_factory=dict)

    # Query Parameters

    params: dict[str, Any] = field(default_factory=dict)

    # Form Body

    data: dict[str, Any] = field(default_factory=dict)

    # JSON Body

    json: dict[str, Any] = field(default_factory=dict)

    # Multipart Files

    files: dict[str, Any] = field(default_factory=dict)

    # Optional raw body

    body: str | bytes | None = None

    # Extra data

    metadata: dict[str, Any] = field(default_factory=dict)
