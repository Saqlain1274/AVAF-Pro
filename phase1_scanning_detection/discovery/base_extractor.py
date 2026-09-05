"""
===============================================================================
AVAF Pro
Base Extractor

Common functionality shared by all passive discovery extractors.

Responsibilities
----------------
✔ Logging
✔ Statistics
✔ Warning collection
✔ Error counting
✔ Timing
✔ Duplicate helpers
===============================================================================
"""

from __future__ import annotations

import logging
import time

from typing import Any

from .model import DiscoveryStatistics
from .model import ExtractorResult


class BaseExtractor:

    def __init__(self):

        self.logger = logging.getLogger(
            self.__class__.__name__
        )

        self.result = ExtractorResult()

        self._started = 0.0

    # ==========================================================
    # Lifecycle
    # ==========================================================

    def start(self) -> None:

        self.result = ExtractorResult()

        self._started = time.perf_counter()

        self.logger.info(
            "Starting %s...",
            self.__class__.__name__
        )

    def finish(self) -> ExtractorResult:

        elapsed = time.perf_counter() - self._started

        self.result.statistics.extra["duration"] = round(
            elapsed,
            3
        )

        self.logger.info(
            "%s completed in %.3fs",
            self.__class__.__name__,
            elapsed
        )

        return self.result

    # ==========================================================
    # Helpers
    # ==========================================================

    def add_item(self, item: Any):

        self.result.items.append(item)

        self.result.statistics.discovered += 1

    def ignore(self):

        self.result.statistics.ignored += 1

    def duplicate(self):

        self.result.statistics.duplicates += 1

    def error(self, exc: Exception | None = None):

        self.result.statistics.errors += 1

        if exc is not None:
            self.logger.debug(str(exc))

    def warning(self, message: str):

        self.result.warnings.append(message)

    def set_total(self, total: int):

        self.result.statistics.total = total
