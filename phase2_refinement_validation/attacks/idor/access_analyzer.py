"""
===============================================================================
IDOR Access Analyzer

Determines whether the observed response differences indicate a potential
Insecure Direct Object Reference (IDOR) vulnerability.
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.models.attack_result import AttackResult


class AccessAnalyzer:

    """
    Analyze response comparison results and determine
    whether an IDOR vulnerability is likely.
    """

    def analyze(
        self,
        vector,
        identifier,
        comparison,
        original_response,
        modified_response,
    ):

        # ------------------------------------------------------------
        # Access denied -> secure
        # ------------------------------------------------------------

        if comparison.modified_status in (401, 403):

            return None

        # ------------------------------------------------------------
        # Resource not found
        # ------------------------------------------------------------

        if comparison.modified_status == 404:

            return None

        # ------------------------------------------------------------
        # Successful access with changed content
        # ------------------------------------------------------------

        if (
            comparison.modified_status == 200
            and comparison.significant_change
        ):

            return AttackResult(
                attack="idor",
                vector=vector,
                payload=identifier.replacement_value,
                evidence=(
                    f"{identifier.original_value}"
                    f" -> "
                    f"{identifier.replacement_value}"
                ),
                indicator="Unauthorized Object Access",
                confidence=0.90,
                metadata={
                    "identifier": identifier.name,
                    "source": identifier.source,
                    "similarity": comparison.similarity,
                    "differences": comparison.differences,
                },
            )

        return None