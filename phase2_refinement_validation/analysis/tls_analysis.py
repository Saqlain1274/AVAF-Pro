"""
===============================================================================
TLS Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


class TLSAnalyzer(BaseAnalyzer):

    id = "tls"

    name = "TLS Analysis"

    def analyze(self, response, context):

        findings = []

        scheme = getattr(context, "scheme", "").lower()

        if scheme != "https":

            findings.append(

                AttackResult(

                    attack="tls",

                    vector=None,

                    payload=None,

                    evidence="Application served over HTTP",

                    indicator="TLS Not Used",

                    confidence=1.0,

                )

            )

        return findings