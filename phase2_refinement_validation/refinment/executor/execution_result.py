"""
===============================================================================
Execution Result

Represents the result of one executed HTTP request.

Produced by:
    AttackExecutor

Consumed by:
    SQLi Detector
    XSS Detector
    LFI Detector
    SSRF Detector
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass(slots=True)
class ExecutionResult:

    # Final URL
    url: str

    # HTTP Method
    method: str

    # Payload used
    payload: str

    # Status Code
    status_code: int

    # Response Headers
    headers: dict[str, Any]

    # Response Cookies
    cookies: dict[str, Any]

    # Response Body
    body: str

    # Response Time (seconds)
    elapsed: float

    # Raw HTTP objects
    request: Any = None
    response: Any = None

    # Future extensions
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (
            301,
            302,
            303,
            307,
            308,
        )

    @property
    def content_type(self) -> str:
        return self.headers.get(
            "Content-Type",
            "",
        )