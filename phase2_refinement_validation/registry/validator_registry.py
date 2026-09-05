"""
===============================================================================
Validator Registry

Central registry for all validator implementations.

The ValidationOrchestrator retrieves validators from this registry instead of
hardcoding knowledge of SQLi, XSS, LFI, etc.

===============================================================================
"""

from __future__ import annotations

from typing import Dict
from typing import Iterable

from phase2_refinement_validation.validators.base_validator import BaseValidator


class ValidatorRegistry:
    """
    Stores validator implementations.
    """

    def __init__(self) -> None:
        self._validators: Dict[str, BaseValidator] = {}
        
        self._locked = False

    def register(
        self,
        validator: BaseValidator,
    ) -> None:

        if self._locked:
           raise RuntimeError("Validator registry is locked.")
        validator_id = validator.id.lower()

        if validator_id in self._validators:
            raise ValueError(
                f"Validator '{validator_id}' is already registered."
            )

        self._validators[validator_id] = validator

    def get(
        self,
        validator_id: str,
    ) -> BaseValidator:

        try:
            return self._validators[
                validator_id.lower()
            ]

        except KeyError as exc:
            raise ValueError(
                f"Unknown validator '{validator_id}'."
            ) from exc

    def supports(
        self,
        validator_id: str,
    ) -> bool:

        return validator_id.lower() in self._validators

    def all(
        self,
    ) -> Iterable[BaseValidator]:

        return self._validators.values()
    
    def lock(self) -> None:
       self._locked = True