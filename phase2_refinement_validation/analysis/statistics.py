"""
===============================================================================

AVAF Pro

Statistical Analysis Engine

Purpose
-------
Analyse the stability and consistency of server behaviour across
multiple replay attacks.

This engine NEVER confirms a vulnerability.

Instead it produces statistical evidence that later contributes to:

    • Rule Engine
    • ML Engine
    • Voting Engine
    • False Positive Elimination

===============================================================================
"""

from __future__ import annotations

from statistics import mean
from statistics import median
from statistics import pstdev


class StatisticsAnalyzer:
    """
    Behaviour Statistics Engine.
    """

    # ==========================================================
    # PUBLIC
    # ==========================================================

    def analyze(
        self,
        behavior_reports: list[dict],
    ) -> dict:

        if not behavior_reports:

            return {}

        similarities = [
            report["similarity"]
            for report in behavior_reports
        ]

        timings = [
            report["response_time_delta"]
            for report in behavior_reports
        ]

        lengths = [
            report["length_delta"]
            for report in behavior_reports
        ]

        return {

            "sample_size": len(behavior_reports),

            "similarity_mean": round(mean(similarities), 2),

            "similarity_median": round(median(similarities), 2),

            "similarity_std": round(
                pstdev(similarities), 2
            ),

            "timing_mean": round(mean(timings), 3),

            "timing_std": round(
                pstdev(timings), 3
            ),

            "length_mean": round(mean(lengths), 2),

            "length_std": round(
                pstdev(lengths), 2
            ),

            "stable_similarity": self._stable(
                similarities,
                tolerance=10,
            ),

            "stable_timing": self._stable(
                timings,
                tolerance=0.5,
            ),

            "stable_length": self._stable(
                lengths,
                tolerance=100,
            ),

            "repeatability": self._repeatability(
                behavior_reports,
            ),

        }

    # ==========================================================
    # PRIVATE
    # ==========================================================

    def _stable(
        self,
        values,
        tolerance,
    ) -> bool:

        if len(values) <= 1:
            return True

        return (max(values) - min(values)) <= tolerance

    def _repeatability(
        self,
        reports,
    ) -> float:
        """
        Percentage of replays showing behavioural change.
        """

        changed = 0

        for report in reports:

            if report["features"]:

                changed += 1

        return round(

            (changed / len(reports)) * 100,

            2,

        )