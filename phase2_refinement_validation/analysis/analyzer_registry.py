"""
===============================================================================
Analyzer Registry

Registers and manages passive analyzers.
===============================================================================
"""

from __future__ import annotations

from typing import Iterable

from .base_analyzer import BaseAnalyzer


class AnalyzerRegistry:

    def __init__(self):

        self._analyzers: list[BaseAnalyzer] = []

    def register(
        self,
        analyzer: BaseAnalyzer,
    ):

        self._analyzers.append(analyzer)

    def register_many(
        self,
        analyzers: Iterable[BaseAnalyzer],
    ):

        for analyzer in analyzers:
            self.register(analyzer)

    def get_supported(
        self,
        response,
    ):

        return [

            analyzer

            for analyzer in self._analyzers

            if analyzer.supports(response)

        ]

    def __iter__(self):

        return iter(self._analyzers)

    def __len__(self):

        return len(self._analyzers)

    def __contains__(
        self,
        analyzer_id: str,
    ):

        return any(

            analyzer.id == analyzer_id

            for analyzer in self._analyzers

        )