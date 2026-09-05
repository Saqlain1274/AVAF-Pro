"""
===============================================================================
Attack Capability

Describes what an attack module is capable of testing.

This allows the framework to match attack modules with compatible attack
vectors before execution.
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AttackCapability:
    """
    Describes the execution capabilities of an attack.
    """

    supported_methods: set[str] = field(default_factory=set)

    supported_parameter_types: set[str] = field(default_factory=set)

    supported_content_types: set[str] = field(default_factory=set)
    
    category: str = "payload"

    requires_body: bool = False

    supports_file_upload: bool = False

    supports_headers: bool = True

    supports_cookies: bool = True