"""
===============================================================================
Cookie Security Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


class CookieSecurityAnalyzer(BaseAnalyzer):

    id = "cookie_security"

    name = "Cookie Security"

    def analyze(self, response, context):

        findings = []

        cookies = response.headers.get("Set-Cookie", "")

        if not cookies:
            return findings

        if "Secure" not in cookies:

            findings.append(
                AttackResult(
                    attack="cookie_security",
                    vector=None,
                    payload=None,
                    evidence="Secure attribute missing",
                    indicator="Insecure Cookie",
                    confidence=1.0,
                )
            )

        if "HttpOnly" not in cookies:

            findings.append(
                AttackResult(
                    attack="cookie_security",
                    vector=None,
                    payload=None,
                    evidence="HttpOnly attribute missing",
                    indicator="Accessible Cookie",
                    confidence=1.0,
                )
            )

        if "SameSite" not in cookies:

            findings.append(
                AttackResult(
                    attack="cookie_security",
                    vector=None,
                    payload=None,
                    evidence="SameSite attribute missing",
                    indicator="CSRF Risk",
                    confidence=1.0,
                )
            )

        return findings