"""
===============================================================================
Payload Provider Template

Responsible only for producing payloads.

No networking.
No detection.
===============================================================================
"""

from abc import ABC, abstractmethod


class BasePayloadProvider(ABC):

    @abstractmethod
    def generate(
        self,
        vector,
    ):
        """
        Return an iterable of payloads.
        """
        raise NotImplementedError