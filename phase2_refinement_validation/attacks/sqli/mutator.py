"""
SQL Injection Payload Mutator
"""

from __future__ import annotations


class SQLInjectionMutator:

    """
    Generates payload mutations for refinement.
    """

    def mutate(

        self,

        payload: str,

    ) -> list[str]:

        return [

            payload,

            payload.replace(" ", "/**/"),

            payload.replace("'", "%27"),

            payload.replace(" ", "%20"),

            payload.upper(),

            payload.lower(),

        ]