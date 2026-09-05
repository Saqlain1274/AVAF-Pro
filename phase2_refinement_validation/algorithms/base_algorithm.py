"""
Base Validation Algorithm

All validation stages inherit from this class.
"""

from abc import ABC, abstractmethod

from phase2_refinement_validation.models.validation_context import ValidationContext
from phase2_refinement_validation.models.validation_result import ValidationResult


class BaseAlgorithm(ABC):
    """
    Base class for every validation stage.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def run(self, context: ValidationContext) -> ValidationResult:
        """
        Execute the validation stage.

        Args:
            context: Shared validation context.

        Returns:
            ValidationResult
        """
        raise NotImplementedError


