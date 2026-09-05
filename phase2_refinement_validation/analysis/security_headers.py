"""
===============================================================================
Security Headers Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


REQUIRED_HEADERS = {

    "Content-Security-Policy",

    "Strict-Transport-Security",

    "X-Content-Type-Options",

    "X-Frame-Options",

    "Referrer-Policy",

    "Permissions-Policy",

}


class SecurityHeadersAnalyzer(BaseAnalyzer):

    id = "security_headers"

    name = "Security Headers"

    def analyze(
        self,
        response,
        context,
    ):

        findings = []

        headers = getattr(response, "headers", {})

        for header in REQUIRED_HEADERS:

            if header not in headers:

                findings.append(

                    AttackResult(

                        attack="missing_security_header",

                        vector=None,

                        payload=None,

                        evidence=header,

                        indicator="Missing Security Header",

                        confidence=1.0,

                        metadata={

                            "header": header,

                        },

                    )

                )

        return findings