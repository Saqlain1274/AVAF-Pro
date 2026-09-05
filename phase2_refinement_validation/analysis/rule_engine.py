"""
===============================================================================
AVAF Pro

Rule Engine

Purpose
-------
Correlates behavioural indicators into evidence.

This module NEVER detects vulnerabilities.

It simply evaluates whether enough behavioural evidence exists
to justify further validation.

Used by

    SQLi Validator
    XSS Validator
    LFI Validator
    XXE Validator
    SSRF Validator

===============================================================================
"""

from __future__ import annotations


class RuleEngine:
    """
    Generic behavioural rule engine.
    """

    def evaluate(
        self,
        indicators: list[str],
    ) -> dict:
        """
        Evaluate heuristic indicators.

        Returns a generic evidence summary.
        """

        score = 0

        matched = []

        # --------------------------------------------------
        # Response behaviour
        # --------------------------------------------------

        if "STATUS_CHANGED" in indicators:

            score += 10

            matched.append("STATUS_CHANGED")

        if "BODY_CHANGED" in indicators:

            score += 10

            matched.append("BODY_CHANGED")

        if "CONTENT_CHANGED" in indicators:

            score += 8

            matched.append("CONTENT_CHANGED")

        # --------------------------------------------------
        # Timing
        # --------------------------------------------------

        if "TIME_DELAY" in indicators:

            score += 15

            matched.append("TIME_DELAY")

        # --------------------------------------------------
        # Similarity
        # --------------------------------------------------

        if "VERY_LOW_SIMILARITY" in indicators:

            score += 20

            matched.append("VERY_LOW_SIMILARITY")

        elif "LOW_SIMILARITY" in indicators:

            score += 10

            matched.append("LOW_SIMILARITY")

        # --------------------------------------------------
        # Headers / Cookies
        # --------------------------------------------------

        if "HEADERS_CHANGED" in indicators:

            score += 4

            matched.append("HEADERS_CHANGED")

        if "COOKIES_CHANGED" in indicators:

            score += 4

            matched.append("COOKIES_CHANGED")

        # --------------------------------------------------
        # Large Response
        # --------------------------------------------------

        if "HUGE_RESPONSE_CHANGE" in indicators:

            score += 10

            matched.append("HUGE_RESPONSE_CHANGE")

        elif "LARGE_RESPONSE_CHANGE" in indicators:

            score += 6

            matched.append("LARGE_RESPONSE_CHANGE")

        elif "SMALL_RESPONSE_CHANGE" in indicators:

            score += 2

            matched.append("SMALL_RESPONSE_CHANGE")

        # --------------------------------------------------
        # Normalize
        # --------------------------------------------------

        score = min(score, 100)

        if score >= 70:

            level = "STRONG"

        elif score >= 40:

            level = "MEDIUM"

        elif score >= 20:

            level = "WEAK"

        else:

            level = "NONE"

        return {

            "score": score,

            "level": level,

            "matched": matched,

        }