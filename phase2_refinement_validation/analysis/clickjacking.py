"""
===============================================================================
Clickjacking Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


class ClickjackingAnalyzer(BaseAnalyzer):

    id = "clickjacking"

    name = "Clickjacking"

    def analyze(self, response, context):

        findings = []

        headers = response.headers

        if (
            "X-Frame-Options" not in headers
            and
            "Content-Security-Policy" not in headers
        ):

            findings.append(

                AttackResult(
                    attack="clickjacking",
                    vector=None,
                    payload=None,
                    evidence="Missing frame protection",
                    indicator="Clickjacking Risk",
                    confidence=1.0,
                )

            )

        return findings