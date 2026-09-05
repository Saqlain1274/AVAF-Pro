"""
===============================================================================
Open Redirect Payloads
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


ABSOLUTE_URLS = (

    "https://example.com",

    "https://google.com",

)

SCHEME_RELATIVE = (

    "//example.com",

    "//google.com",

)

ENCODED = (

    "%2F%2Fexample.com",

    "https:%2F%2Fexample.com",

)

PAYLOAD_DATABASE = {

    "absolute": ABSOLUTE_URLS,

    "scheme_relative": SCHEME_RELATIVE,

    "encoded": ENCODED,

}


class OpenRedirectPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )