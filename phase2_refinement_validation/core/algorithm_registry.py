"""
===============================================================================

AVAF Pro

Algorithm Registry

Central registry for all validation and refinement algorithms.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class AlgorithmMetadata:

    id: str

    name: str

    category: str

    weight: float

    critical: bool

    enabled: bool = True


class AlgorithmRegistry:

    def __init__(self):

        self._algorithms = {}

    def register(

        self,

        metadata: AlgorithmMetadata,

    ):

        self._algorithms[metadata.id] = metadata

    def get(

        self,

        algorithm_id: str,

    ):

        return self._algorithms[algorithm_id]

    def all(self):

        return list(self._algorithms.values())