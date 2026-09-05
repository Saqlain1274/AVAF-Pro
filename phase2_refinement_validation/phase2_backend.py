"""
===============================================================================
AVAF Pro - Phase 2 Backend Entry Point
===============================================================================

Responsibilities
----------------
Phase-1 output
    ->
deserialize observed Phase-1 parameter candidates
    ->
existing Phase-2 engine
    ->
validation / confirmation
    ->
GUI

This module does NOT:
    - crawl
    - target a website
    - discover parameters
    - generate Phase-1 vectors
    - generate attack payloads
    - select attacks
    - implement vulnerability detection
    - implement validation algorithms
    - implement confirmation rules
    - calculate validation progress
"""

from __future__ import annotations

import json
from pathlib import Path

from phase2_refinement_validation.analysis.analyzer_registry import (
    AnalyzerRegistry,
)
from phase2_refinement_validation.attacks.attack_request_builder import (
    AttackRequestBuilder,
)
from phase2_refinement_validation.bootstrap import (
    create_phase2_engine,
)
from phase2_refinement_validation.context.attack_context import (
    AttackContext,
)
from phase2_refinement_validation.models.attack_vector import (
    AttackVector,
)
from phase2_refinement_validation.refinment.executor.attack_executor import (
    AttackExecutor,
)


# =============================================================================
# PROJECT PATHS
# =============================================================================

ROOT = Path(__file__).resolve().parent.parent

PHASE1_VECTOR_FILE = (
    ROOT
    / "phase1_scanning_detection"
    / "output"
    / "parameter_candidates.json"
)


# =============================================================================
# PHASE-1 INPUT
# =============================================================================

def _load_phase1_vectors():
    """
    Load only the parameter candidates actually produced by Phase 1.

    No discovery is performed here.
    No new URLs are generated.
    No parameters are guessed.
    """

    if not PHASE1_VECTOR_FILE.exists():
        raise FileNotFoundError(
            "Phase-1 output was not found: "
            f"{PHASE1_VECTOR_FILE}"
        )

    with PHASE1_VECTOR_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        raw = json.load(file)

    if not isinstance(raw, list):
        raise TypeError(
            "Phase-1 parameter_candidates.json must contain a list."
        )

    vectors = []

    for item in raw:

        if not isinstance(item, dict):
            continue

        parameter = str(
            item.get(
                "parameter",
                "",
            )
            or ""
        ).strip()

        # Route-only observations are not active vectors.
        if not parameter:
            continue

        url = str(
            item.get(
                "url",
                "",
            )
            or ""
        ).strip()

        if not url:
            continue

        vector = AttackVector(
            url=url,

            method=str(
                item.get(
                    "method",
                    "GET",
                )
                or "GET"
            ).upper(),

            parameter=parameter,

            parameter_type=str(
                item.get(
                    "parameter_type",
                    item.get(
                        "location",
                        "query",
                    ),
                )
                or "query"
            ),

            original_value=item.get(
                "original_value",
                item.get(
                    "value",
                    "",
                ),
            ),
        )

        # Preserve metadata that Phase 1 actually supplied.
        metadata = item.get(
            "metadata"
        )

        if isinstance(
            metadata,
            dict,
        ):
            vector.metadata.update(
                metadata
            )

        vector.metadata.update(
            {
                "phase1_source": item.get(
                    "source"
                ),

                "phase1_candidate_type": item.get(
                    "candidate_type"
                ),

                "phase1_observed": item.get(
                    "observed"
                ),
            }
        )

        vectors.append(
            vector
        )

    return vectors


# =============================================================================
# PHASE-2 BACKEND ENTRYPOINT
# =============================================================================

async def run_phase2(
    output_callback=None,
) -> int:
    """
    Execute the existing Phase-2 backend using Phase-1 output.

    The GUI supplies no target and no vectors.
    """

    def emit(message):
        if callable(
            output_callback
        ):
            output_callback(
                message
            )
        else:
            print(
                str(message),
                flush=True,
            )

    # -------------------------------------------------------------------------
    # Load Phase-1 output
    # -------------------------------------------------------------------------

    emit(
        "[PHASE2] Loading Phase-1 parameter candidates."
    )

    vectors = _load_phase1_vectors()

    emit(
        "[PHASE2] Active vectors received: "
        f"{len(vectors)}"
    )

    # -------------------------------------------------------------------------
    # Create the existing Phase-2 engine.
    #
    # Bootstrap only wires the already-existing Phase-2 components.
    # -------------------------------------------------------------------------

    engine = create_phase2_engine(
        analyzer_registry=AnalyzerRegistry()
    )

    # -------------------------------------------------------------------------
    # Phase-2 execution context.
    #
    # No target is supplied by the GUI.
    # Each AttackVector already contains the URL observed by Phase 1.
    # -------------------------------------------------------------------------

    context = AttackContext(
        builder=AttackRequestBuilder(),
        executor=AttackExecutor(),
    )

    
    (
        {
            "phase": 2,
            "phase1_vector_count": len(vectors),
        }
    )

    # -------------------------------------------------------------------------
    # Give the existing backend its Phase-1 vectors.
    #
    # Attack generation, execution, validation and confirmation remain
    # inside the existing Phase-2 components.
    # -------------------------------------------------------------------------

    findings = engine.execute(
        vectors=vectors,
        context=context,
    )

    findings = list(
        findings or []
    )

    # -------------------------------------------------------------------------
    # Results
    # -------------------------------------------------------------------------

    emit(
        "[RESULT] Phase-1 active vectors: "
        f"{len(vectors)}"
    )

    confirmed_count = len(findings)

    emit(
        "[RESULT] Confirmed findings: "
        f"{confirmed_count}"
    )

    return confirmed_count

if __name__ == "__main__":
    import asyncio

    raise SystemExit(
        asyncio.run(
            run_phase2()
        )
    )