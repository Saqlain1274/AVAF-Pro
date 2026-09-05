"""
===============================================================================
Base Detector Template

Each attack implements its own detector.

Responsibilities
----------------
✔ Analyze HTTP responses
✔ Detect attack-specific indicators
✔ Return AttackResult or None

Never
-----
✘ Execute HTTP requests
✘ Generate payloads
✘ Perform validation

===============================================================================
"""

from abc import ABC, abstractmethod


class BaseDetector(ABC):

    @abstractmethod
    def detect(
        self,
        vector,
        payload,
        response,
    ):
        """
        Analyze one response.

        Returns:
            AttackResult | None
        """
        raise NotImplementedError
