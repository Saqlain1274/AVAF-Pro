"""
===============================================================================
Technology Detection Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


TECH_HEADERS = (

    "Server",

    "X-Powered-By",

    "X-AspNet-Version",

    "X-Runtime",

)


class TechnologyDetectionAnalyzer(BaseAnalyzer):

    id = "technology_detection"

    name = "Technology Detection"

    def analyze(self, response, context):

        findings = []

        headers = getattr(response, "headers", {})

        for header in TECH_HEADERS:

            if header in headers:

                findings.append(

                    AttackResult(

                        attack="technology_detection",

                        vector=None,

                        payload=None,

                        evidence=f"{header}: {headers[header]}",

                        indicator="Technology Disclosure",

                        confidence=1.0,

                        metadata={
                            "header": header,
                            "value": headers[header],
                        },

                    )

                )

        return findings