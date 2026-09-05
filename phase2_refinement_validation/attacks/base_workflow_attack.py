"""
===============================================================================
Base Workflow Attack

Base class for attacks that execute workflows rather than simple payload
injection.

Examples
--------
- IDOR
- Authentication Bypass
- CSRF
- Business Logic
===============================================================================
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from phase2_refinement_validation.attacks.base_attack import BaseAttack


class BaseWorkflowAttack(
    BaseAttack,
    ABC,
):
    """
    Base class for workflow-driven attacks.
    """

    def generate_payloads(
        self,
        vector,
    ):
        """
        Workflow attacks do not use
        the standard payload-generation pipeline.
        """
        return []

    @abstractmethod
    def execute(
        self,
        vector,
        context,
    ):
        """
        Execute workflow attack.
        """
        raise NotImplementedError