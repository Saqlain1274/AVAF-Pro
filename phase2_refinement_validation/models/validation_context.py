"""
===============================================================================
AVAF Pro

Validation Context

Central runtime object shared across the entire validation pipeline.

Every validator reads from and writes to this object instead of
passing data between modules.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .attack_plan import AttackPlan
from .http_exchange import HTTPExchange
from .validation_result import ValidationResult
from .indicator import Indicator


@dataclass(slots=True)
class ValidationContext:
    """
    Shared runtime context used throughout the validation pipeline.
    """

    # ==========================================================
    # Attack Plan
    # ==========================================================

    attack_plan: AttackPlan

    # ==========================================================
    # Baseline Exchange
    # ==========================================================

    baseline: HTTPExchange | None = None

    # ==========================================================
    # Replay Exchanges
    # ==========================================================

    exchanges: list[HTTPExchange] = field(default_factory=list)
    
    # ==========================================================
    # Analysis Indicators
    # ==========================================================
    
    indicators: list[Indicator] = field(default_factory=list)

    # ==========================================================
    # Loaded Knowledge
    # ==========================================================

    knowledge: dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Validation Results
    # ==========================================================

    results: dict[str, ValidationResult] = field(default_factory=dict)

    # ==========================================================
    # Runtime Cache
    # ==========================================================

    cache: dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Runtime Metadata
    # ==========================================================

    metadata: dict[str, Any] = field(default_factory=dict)

    # ==========================================================
    # Response Methods
    # ==========================================================

    def add_response(self, exchange: HTTPExchange) -> None:
        """Store an HTTP exchange."""
        self.exchanges.append(exchange)
    
    def add_indicator(self, indicator: Indicator) -> None:
        """Store an analysis indicator."""
        self.indicators.append(indicator)
    

    def get_indicators(self) -> list[Indicator]:
        """Return all collected indicators."""
        return self.indicators

    # ==========================================================
    # Result Methods
    # ==========================================================

    def add_result(self, result: ValidationResult) -> None:
        """Store a validation result."""
        self.results[result.validator] = result

    def get_result(self, validator: str) -> ValidationResult | None:
        """Retrieve a validation result."""
        return self.results.get(validator)

    # ==========================================================
    # Knowledge Methods
    # ==========================================================

    def set_knowledge(self, category: str, data: Any) -> None:
        """Store loaded knowledge."""
        self.knowledge[category] = data

    def get_knowledge(self, category: str) -> Any:
        """Retrieve loaded knowledge."""
        return self.knowledge.get(category)

    # ==========================================================
    # Cache Methods
    # ==========================================================

    def set_cache(self, key: str, value: Any) -> None:
        self.cache[key] = value

    def get_cache(self, key: str) -> Any:
        return self.cache.get(key)

    # ==========================================================
    # Reset
    # ==========================================================

    def clear(self) -> None:
        """
        Clear runtime state while preserving the AttackPlan.
        """
        self.baseline = None
        self.exchanges.clear()
        self.indicators.clear()
        self.knowledge.clear()
        self.results.clear()
        self.cache.clear()
        self.metadata.clear()
        