"""
===============================================================================
AVAF Pro

Heuristic Analysis Engine

Purpose
-------
Convert behavioural changes into generic indicators.

This engine NEVER decides whether a vulnerability exists.

It simply converts behaviour into reusable indicators that are later
consumed by:

    • Rule Engine
    • SQLi Validator
    • XSS Validator
    • LFI Validator

===============================================================================
"""

from __future__ import annotations


class HeuristicAnalyzer:
    """
    Converts behaviour into heuristic indicators.
    """

    # ==========================================================
    # PUBLIC
    # ==========================================================

    def analyze(
        self,
        behavior: dict,
    ) -> list[str]:
        """
        Convert behaviour analysis into indicators.
        """

        indicators = []

        # ---------------------------------------
        # Status
        # ---------------------------------------

        if behavior["status_changed"]:

            indicators.append("STATUS_CHANGED")

        # ---------------------------------------
        # Body
        # ---------------------------------------

        if behavior["body_changed"]:

            indicators.append("BODY_CHANGED")

        # ---------------------------------------
        # Length
        # ---------------------------------------

        if behavior["length_changed"]:

            indicators.append("CONTENT_CHANGED")

        # ---------------------------------------
        # Headers
        # ---------------------------------------

        if behavior["headers_changed"]:

            indicators.append("HEADERS_CHANGED")

        # ---------------------------------------
        # Cookies
        # ---------------------------------------

        if behavior["cookies_changed"]:

            indicators.append("COOKIES_CHANGED")

        # ---------------------------------------
        # Redirect
        # ---------------------------------------

        if behavior["redirect_changed"]:

            indicators.append("REDIRECT_CHANGED")

        # ---------------------------------------
        # Timing
        # ---------------------------------------

        if behavior["timing_changed"]:

            indicators.append("TIME_DELAY")

        # ---------------------------------------
        # Similarity
        # ---------------------------------------

        similarity = behavior["similarity"]

        if similarity < 30:

            indicators.append("VERY_LOW_SIMILARITY")

        elif similarity < 60:

            indicators.append("LOW_SIMILARITY")

        elif similarity < 80:

            indicators.append("MEDIUM_SIMILARITY")

        # ---------------------------------------
        # Response Size
        # ---------------------------------------

        delta = behavior["length_delta"]

        if delta > 5000:

            indicators.append("HUGE_RESPONSE_CHANGE")

        elif delta > 1000:

            indicators.append("LARGE_RESPONSE_CHANGE")

        elif delta > 200:

            indicators.append("SMALL_RESPONSE_CHANGE")

        return indicators