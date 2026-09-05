"""
===============================================================================
Phase 2 Engine

Public entry point.
===============================================================================
"""

from __future__ import annotations
from typing import Iterable

from phase2_refinement_validation.context.attack_context import AttackContext
from phase2_refinement_validation.engine.integration_engine import IntegrationEngine
from phase2_refinement_validation.models.attack_vector import AttackVector
from phase2_refinement_validation.models.finding import Finding


class Phase2Engine:

    def __init__(

        self,

        integration_engine: IntegrationEngine,

    ):

        self.integration_engine = integration_engine

    def run(
        self,
        vectors: Iterable[AttackVector],
        context: AttackContext,
        progress_cb=None,
    ) -> list[Finding]:

        return self.integration_engine.execute(
            vectors=vectors,
            context=context,
            progress_cb=progress_cb,
        )