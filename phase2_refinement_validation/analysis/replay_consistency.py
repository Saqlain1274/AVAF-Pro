"""
===============================================================================

AVAF Pro

Replay Consistency Analyzer

Purpose
-------
Determines whether a suspected vulnerability behaves consistently across
multiple replay attacks.

A real vulnerability should generally produce reproducible behaviour.

===============================================================================
"""

from __future__ import annotations

from collections import Counter


class ReplayConsistencyAnalyzer:

    """
    Analyse replay consistency.
    """

    def analyze(
        self,
        behavior_reports: list[dict],
    ) -> dict:

        if not behavior_reports:

            return {}

        total = len(behavior_reports)

        feature_counter = Counter()

        similarities = []

        timings = []

        for report in behavior_reports:

            similarities.append(report["similarity"])

            timings.append(report["response_time_delta"])

            feature_counter.update(report["features"])

        feature_frequency = {}

        for feature, count in feature_counter.items():

            feature_frequency[feature] = round(
                (count / total) * 100,
                2,
            )

        consistent_features = []

        unstable_features = []

        for feature, percent in feature_frequency.items():

            if percent >= 80:

                consistent_features.append(feature)

            elif percent <= 30:

                unstable_features.append(feature)

        replay_score = self._calculate_score(
            feature_frequency
        )

        return {

            "replay_count": total,

            "feature_frequency": feature_frequency,

            "consistent_features": consistent_features,

            "unstable_features": unstable_features,

            "average_similarity": round(
                sum(similarities) / total,
                2,
            ),

            "average_time_delta": round(
                sum(timings) / total,
                3,
            ),

            "replay_score": replay_score,

            "consistent": replay_score >= 70,

        }

    # ==========================================================
    # PRIVATE
    # ==========================================================

    def _calculate_score(
        self,
        feature_frequency,
    ) -> float:

        if not feature_frequency:

            return 0.0

        total = 0

        for percent in feature_frequency.values():

            total += percent

        return round(
            total / len(feature_frequency),
            2,
        )