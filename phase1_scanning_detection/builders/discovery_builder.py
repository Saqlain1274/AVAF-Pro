"""
===============================================================================
AVAF Pro

Discovery Builder

Builds the final DiscoveryResult by combining all discovery modules.

Responsibilities
----------------
✓ Static DOM
✓ Runtime
✓ Network

Never
-----
✘ Crawl pages
✘ Execute JavaScript
✘ Parse HTML
✘ Validate vulnerabilities
===============================================================================
"""

from __future__ import annotations

from phase1_scanning_detection.discovery.model import (
    DiscoveryResult,
    StaticDOMResult,
    RuntimeResult,
    NetworkResult,
)


class DiscoveryBuilder:
    """
    Builds the final DiscoveryResult.
    """

    def __init__(self):

        self.reset()

    # ==========================================================
    # RESET
    # ==========================================================

    def reset(self) -> "DiscoveryBuilder":

        self._result = DiscoveryResult()
    
        return self

    # ==========================================================
    # STATIC DOM
    # ==========================================================

    def add_static_dom(
        self,
        result: StaticDOMResult,
    ) -> "DiscoveryBuilder":

        self._result.static_dom = result

        return self

    # ==========================================================
    # RUNTIME
    # ==========================================================

    def add_runtime(
        self,
        result: RuntimeResult,
    ) -> "DiscoveryBuilder":

        self._result.runtime = result

        return self

    # ==========================================================
    # NETWORK
    # ==========================================================

    def add_network(
        self,
        result: NetworkResult,
    ) -> "DiscoveryBuilder":

        self._result.network = result

        return self

    # ==========================================================
    # BUILD
    # ==========================================================

    def build(self) -> DiscoveryResult:

        result = self._result

        self.reset()

        return result