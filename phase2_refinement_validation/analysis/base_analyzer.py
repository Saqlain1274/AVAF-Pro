"""
===============================================================================
Base Analyzer

Base class for passive security analyzers.

Passive analyzers inspect responses without modifying requests.

Examples
--------
- Security Headers
- Cookie Security
- CORS
- Clickjacking
- robots.txt
- Directory Listing
- Technology Detection
===============================================================================
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):

    id = ""

    name = ""

    @abstractmethod
    def analyze(
        self,
        response,
        context,
    ):
        """
        Analyze a response.

        Returns:
            list[AttackResult]
        """
        raise NotImplementedError

    def supports(
        self,
        response,
    ) -> bool:

        return True