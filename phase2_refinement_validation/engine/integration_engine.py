"""
===============================================================================
AVAF Pro - Phase 2 Integration Engine
===============================================================================

Canonical Phase-2 flow:

    Phase-1 AttackVectors
            |
            v
    AttackDispatcher
            |
            v
    AttackResults
            |
            v
    ValidationOrchestrator
            |
            +--> one ValidationContext per AttackResult
            |
            v
    confirmed ValidationResults

Important invariants
--------------------
1. Every Phase-1 active vector is dispatched.
2. Every produced AttackResult is validated independently.
3. No single vectors[0] context is reused for all candidates.
4. Vector identity is preserved through AttackResult.vector.
5. Progress 0-50 belongs to attack dispatch.
6. Progress 50-99 belongs to candidate validation.
7. 100 is emitted only after validation really finishes.
===============================================================================
"""

from __future__ import annotations

import inspect
from typing import Iterable

from phase2_refinement_validation.analysis.analyzer_engine import (
    AnalyzerEngine,
)

from phase2_refinement_validation.context.attack_context import (
    AttackContext,
)

from phase2_refinement_validation.dispatcher.attack_dispatcher import (
    AttackDispatcher,
)

from phase2_refinement_validation.engine.validation_orchestrator import (
    ValidationOrchestrator,
)

from phase2_refinement_validation.models.attack_vector import (
    AttackVector,
)

from phase2_refinement_validation.registry.attack_registry import (
    AttackRegistry,
)


class IntegrationEngine:

    def __init__(
        self,
        attack_registry: AttackRegistry,
        attack_dispatcher: AttackDispatcher,
        analyzer_engine: AnalyzerEngine,
        validation_orchestrator: ValidationOrchestrator,
    ) -> None:

        self.attack_registry = attack_registry
        self.attack_dispatcher = attack_dispatcher
        self.analyzer_engine = analyzer_engine
        self.validation = validation_orchestrator

    # =========================================================================
    # PUBLIC
    # =========================================================================

    def execute(
        self,
        vectors: Iterable[AttackVector],
        context: AttackContext,
        progress_cb=None,
    ) -> list:

        vectors = list(vectors or [])

        total_vectors = len(vectors)

        if not total_vectors:
            self._progress(progress_cb, 100.0)
            return []

        print(
            f"[PHASE2] Phase-1 active vectors received: "
            f"{total_vectors}",
            flush=True,
        )

        # =====================================================================
        # STAGE 1
        # ATTACK DISPATCH
        #
        # 0 -> 50
        # =====================================================================

        def dispatch_progress(value):

            try:
                value = max(
                    0.0,
                    min(100.0, float(value)),
                )

                mapped = value * 0.50

                self._progress(
                    progress_cb,
                    mapped,
                )

            except Exception:
                pass

        print(
            "[PHASE2] Attack dispatch started.",
            flush=True,
        )

        dispatch_signature = inspect.signature(
            self.attack_dispatcher.dispatch
        )

        dispatch_kwargs = {
            "vectors": vectors,
            "context": context,
        }

        if "progress_cb" in dispatch_signature.parameters:

            dispatch_kwargs["progress_cb"] = (
                dispatch_progress
            )

        elif "progress_callback" in dispatch_signature.parameters:

            dispatch_kwargs["progress_callback"] = (
                dispatch_progress
            )

        else:

            raise TypeError(
                "Installed AttackDispatcher.dispatch() has "
                "no supported progress callback parameter."
            )

        attack_results = (
            self.attack_dispatcher.dispatch(
                **dispatch_kwargs
            )
        )

        attack_results = list(
            attack_results or []
        )

        self._progress(
            progress_cb,
            50.0,
        )

        # =====================================================================
        # DISPATCH AUDIT
        # =====================================================================

        vectors_with_results = set()

        for result in attack_results:

            vector = getattr(
                result,
                "vector",
                None,
            )

            if vector is None:
                continue

            vector_id = self._vector_id(
                vector
            )

            vectors_with_results.add(
                vector_id
            )

        print(
            f"[PHASE2] Attack dispatch complete.",
            flush=True,
        )

        print(
            f"[PHASE2] Phase-1 vectors       : "
            f"{total_vectors}",
            flush=True,
        )

        print(
            f"[PHASE2] AttackResults produced: "
            f"{len(attack_results)}",
            flush=True,
        )

        print(
            f"[PHASE2] Vectors producing results: "
            f"{len(vectors_with_results)}",
            flush=True,
        )

        # =====================================================================
        # IMPORTANT
        #
        # A vector producing zero AttackResults is NOT silently converted into
        # a vulnerability.
        #
        # It means its registered attack modules did not produce a candidate.
        # =====================================================================

        if not attack_results:

            print(
                "[PHASE2] No AttackResults were produced.",
                flush=True,
            )

            self._progress(
                progress_cb,
                100.0,
            )

            return []

        # =====================================================================
        # STAGE 2
        # VALIDATION
        #
        # 50 -> 99
        #
        # Every AttackResult gets its own ValidationContext.
        # =====================================================================

        print(
            f"[PHASE2] Starting validation of "
            f"{len(attack_results)} AttackResults.",
            flush=True,
        )

        # This parent context contains ONLY shared runtime information.
        # It is never mutated as the candidate context.
        parent_context = (
            self.validation.build_parent_context(
                attack_context=context
            )
        )

        def validation_progress(value):

            try:

                value = max(
                    0.0,
                    min(100.0, float(value)),
                )

                mapped = (
                    50.0
                    + (
                        value
                        * 0.49
                        / 100.0
                    )
                )

                self._progress(
                    progress_cb,
                    min(
                        99.0,
                        mapped,
                    ),
                )

            except Exception:
                pass

        validated = (
            self.validation.validate_parallel(
                attack_results=attack_results,
                context=parent_context,
                max_workers=8,
                progress_cb=validation_progress,
            )
        )

        validated = list(
            validated or []
        )

        # =====================================================================
        # REAL COMPLETION
        # =====================================================================

        self._progress(
            progress_cb,
            99.0,
        )

        print(
            f"[PHASE2] Validation complete.",
            flush=True,
        )

        print(
            f"[PHASE2] AttackResults validated: "
            f"{len(attack_results)}",
            flush=True,
        )

        print(
            f"[PHASE2] Confirmed findings: "
            f"{len(validated)}",
            flush=True,
        )

        self._progress(
            progress_cb,
            100.0,
        )

        print(
            "[PHASE2] Phase-2 execution reached 100%.",
            flush=True,
        )

        return validated

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _vector_id(vector) -> str:

        metadata = getattr(
            vector,
            "metadata",
            {},
        ) or {}

        return str(
            getattr(
                vector,
                "id",
                None,
            )
            or getattr(
                vector,
                "vector_id",
                None,
            )
            or metadata.get(
                "vector_id",
                "",
            )
            or ""
        )

    @staticmethod
    def _progress(
        callback,
        value,
    ):

        if not callable(callback):
            return

        try:

            callback(
                max(
                    0.0,
                    min(
                        100.0,
                        float(value),
                    ),
                )
            )

        except Exception:
            pass