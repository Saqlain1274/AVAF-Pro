"""
===============================================================================

AVAF Pro

Base Validator

Defines the common interface used by all Phase 2 validators.

===============================================================================
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from phase2_refinement_validation.models.attack_result import AttackResult
from phase2_refinement_validation.models.validation_context import ValidationContext
from phase2_refinement_validation.models.validation_result import ValidationResult


class BaseValidator(ABC):
    """
    Base interface for all Phase 2 validators.

    Validators receive AttackResult objects produced by active attacks
    and return ValidationResult objects after refinement/validation.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    id: str = ""

    name: str = ""

    # ------------------------------------------------------------------
    # SUPPORT CHECK
    # ------------------------------------------------------------------

    @abstractmethod
    def supports(
        self,
        result: AttackResult,
    ) -> bool:
        """
        Return True when this validator can validate the supplied
        AttackResult.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------

    @abstractmethod
    def validate(
        self,
        *,
        result: AttackResult,
        context: ValidationContext,
    ) -> ValidationResult | None:
        """
        Validate an AttackResult.

        Returns:
            ValidationResult when validation was performed,
            otherwise None.
        """
        raise NotImplementedError