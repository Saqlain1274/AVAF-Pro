"""
===============================================================================

AVAF Pro

Voting Engine

Purpose
-------
Aggregates the results of all validation and refinement algorithms to
produce a final, explainable decision.

===============================================================================
"""

from __future__ import annotations

from models.algorithm_result import AlgorithmResult


class VotingEngine:

    """
    Multi-stage decision engine.
    """

    def __init__(self):

        self.weights = {

            "Behavior Analysis": 20,

            "Statistics Analysis": 15,

            "Replay Consistency": 25,

            "Response Fingerprinting": 20,

            "Rule Engine": 10,

            "Machine Learning": 10,

        }

        self.critical = {

            "Behavior Analysis",

            "Replay Consistency",

        }

    def decide(

        self,

        results: list[AlgorithmResult],

    ) -> dict:

        failures = []

        supported = []

        total_weight = 0

        achieved = 0

        evidence = []

        for result in results:

            weight = self.weights.get(

                result.name,

                10,

            )

            total_weight += weight

            if result.name in self.critical:

                if not result.passed:

                    failures.append(result.name)

            if result.passed:

                achieved += weight

                supported.append(result.name)

                evidence.extend(result.evidence)

        if failures:

            return {

                "status": "FALSE_POSITIVE",

                "confidence": 0,

                "reason": "Critical validation failed.",

                "failed": failures,

                "supported": supported,

                "evidence": evidence,

            }

        confidence = round(

            (achieved / total_weight) * 100,

            2,

        )

        return {

            "status": self._status(confidence),

            "confidence": confidence,

            "supported": supported,

            "failed": [],

            "evidence": evidence,

        }

    def _status(

        self,

        confidence: float,

    ) -> str:

        if confidence >= 95:

            return "CONFIRMED"

        if confidence >= 80:

            return "LIKELY_CONFIRMED"

        if confidence >= 60:

            return "MANUAL_REVIEW"

        return "FALSE_POSITIVE"