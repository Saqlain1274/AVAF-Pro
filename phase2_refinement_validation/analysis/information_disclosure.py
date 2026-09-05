"""
===============================================================================
Information Disclosure Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


DISCLOSURE_KEYWORDS = (

    "stack trace",

    "exception",

    "traceback",

    "fatal error",

    "warning:",

    "notice:",

    "debug",

)


class InformationDisclosureAnalyzer(BaseAnalyzer):

    id = "information_disclosure"

    name = "Information Disclosure"

    def analyze(self, response, context):

        findings = []

        body = getattr(response, "text", "")

        body_lower = body.lower()

        for keyword in DISCLOSURE_KEYWORDS:

            if keyword in body_lower:

                findings.append(

                    AttackResult(

                        attack="information_disclosure",

                        vector=None,

                        payload=None,

                        evidence=keyword,

                        indicator="Sensitive Information",

                        confidence=0.90,

                    )

                )

        return findings