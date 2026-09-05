"""
===============================================================================
Robots.txt Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


class RobotsAnalyzer(BaseAnalyzer):

    id = "robots"

    name = "Robots.txt Analysis"

    def analyze(self, response, context):

        findings = []

        url = getattr(context, "url", "")

        if not url.endswith("/robots.txt"):

            return findings

        body = getattr(response, "text", "")

        if "Disallow:" in body:

            findings.append(

                AttackResult(

                    attack="robots",

                    vector=None,

                    payload=None,

                    evidence="robots.txt contains Disallow entries",

                    indicator="Sensitive Paths Advertised",

                    confidence=0.80,

                )

            )

        return findings