"""
===============================================================================

AVAF Pro

False Positive Filter

Purpose
-------
Evaluates all refinement evidence and determines whether a finding should
proceed to the decision engine or be rejected as a false positive.

===============================================================================
"""

from __future__ import annotations


class FalsePositiveFilter:

    """
    Multi-factor false positive elimination.
    """

    def evaluate(

        self,

        behavior: dict,

        statistics: dict,

        replay: dict,

        fingerprint: dict,

    ) -> dict:

        score = 100

        reasons = []

        # -----------------------------------------------------
        # Replay Consistency
        # -----------------------------------------------------

        if not replay["consistent"]:

            score -= 35

            reasons.append(
                "Replay behaviour is inconsistent."
            )

        # -----------------------------------------------------
        # Similarity Stability
        # -----------------------------------------------------

        if not statistics["stable_similarity"]:

            score -= 20

            reasons.append(
                "Similarity varies between replays."
            )

        # -----------------------------------------------------
        # Timing Stability
        # -----------------------------------------------------

        if not statistics["stable_timing"]:

            score -= 10

            reasons.append(
                "Timing is unstable."
            )

        # -----------------------------------------------------
        # Fingerprint
        # -----------------------------------------------------

        if not fingerprint["identical"]:

            score -= 15

            reasons.append(
                "Normalized responses differ."
            )

        # -----------------------------------------------------
        # Behavior
        # -----------------------------------------------------

        if len(behavior["features"]) == 0:

            score -= 30

            reasons.append(
                "No behavioural indicators detected."
            )

        # Never go below zero
        score = max(score, 0)

        return {

            "score": score,

            "passed": score >= 70,

            "classification": self._classification(score),

            "reasons": reasons,

        }

    # ==========================================================
    # PRIVATE
    # ==========================================================

    def _classification(
        self,
        score: int,
    ) -> str:

        if score >= 90:
            return "VERY_LOW_FALSE_POSITIVE"

        if score >= 70:
            return "LOW_FALSE_POSITIVE"

        if score >= 50:
            return "MEDIUM_FALSE_POSITIVE"

        return "HIGH_FALSE_POSITIVE"