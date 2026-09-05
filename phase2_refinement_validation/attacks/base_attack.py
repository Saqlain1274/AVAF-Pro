"""
===============================================================================
Base Attack

Every attack engine in AVAF Pro inherits from this class.

Examples:
    SQLInjectionAttack
    XSSAttack
    LFIAttack
    SSRFAttack
===============================================================================
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod


class BaseAttack(ABC):

    # Unique attack id
    id: str = ""

    # Human readable name
    name: str = ""

    @abstractmethod
    def supports(
        self,
        vector,
    ) -> bool:
        """
        Returns True if this attack supports
        the supplied attack vector.
        """
        pass

    @abstractmethod
    def generate_payloads(
        self,
        vector,
    ):
        """
        Generate payloads for this vector.
        """
        pass

    @abstractmethod
    def execute(
        self,
        vector,
        context,
    ):
        """
        Execute the attack.

        Returns:
            list[PotentialFinding]
        """
        pass