"""
===============================================================================
Passive Analysis Engine

Executes all registered passive analyzers.
===============================================================================
"""

from __future__ import annotations


class AnalyzerEngine:

    def __init__(
        self,
        registry,
    ):

        self.registry = registry

    def analyze(
        self,
        response,
        context,
    ):

        findings = []

        for analyzer in self.registry.get_supported(response):

            try:

                results = analyzer.analyze(
                    response,
                    context,
                )

                if results:

                    findings.extend(results)

            except Exception as exc:

                print(
                    f"[Analyzer] {analyzer.id} failed: {exc}"
                )

        return findings