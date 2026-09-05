"""
===============================================================================
Attack Context

Provides shared services and configuration to attack modules.

This object is created once by the dispatcher and passed to every attack.

It avoids passing dozens of arguments between components.
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phase2_refinement_validation.attacks.attack_request_builder import (
    AttackRequestBuilder,
)
from phase2_refinement_validation.refinment.executor.attack_executor import (
    AttackExecutor,
)


@dataclass(slots=True)
class AttackContext:
    """
    Shared execution context for all attack modules.
    """

    # Core services
    builder: AttackRequestBuilder
    executor: AttackExecutor

    # Runtime configuration
    # Original response from Phase 1
    original_response: Any | None = None
    timeout: int = 15
    
    verify_ssl: bool = False
    
    follow_redirects: bool = True
    
    # Target information
    scheme: str = ""
    
    url: str = ""

    # Optional HTTP settings
    proxies: dict[str, str] = field(default_factory=dict)

    # Shared metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from shared metadata.
        """
        return self.metadata.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Store a value in shared metadata.
        """
        self.metadata[key] = value