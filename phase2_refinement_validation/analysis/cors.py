"""
===============================================================================
CORS Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


class CORSAnalyzer(BaseAnalyzer):

    id = "cors"

    name = "Cross-Origin Resource Sharing"

    def analyze(self, response, context):

        findings = []

        headers = response.headers

        origin = headers.get(
            "Access-Control-Allow-Origin"
        )

        credentials = headers.get(
            "Access-Control-Allow-Credentials"
        )

        if origin == "*":

            findings.append(

                AttackResult(
                    attack="cors",
                    vector=None,
                    payload=None,
                    evidence="Access-Control-Allow-Origin: *",
                    indicator="Wildcard Origin",
                    confidence=1.0,
                )

            )

        if origin == "*" and credentials == "true":

            findings.append(

                AttackResult(
                    attack="cors",
                    vector=None,
                    payload=None,
                    evidence="Wildcard + Credentials",
                    indicator="Dangerous CORS",
                    confidence=1.0,
                )

            )

        return findings