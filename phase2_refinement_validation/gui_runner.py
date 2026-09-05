"""
===============================================================================
AVAF Pro - Phase 2 GUI Bridge
===============================================================================

ONLY responsibility:

    GUI
      |
      v
    Phase-2 backend
      |
      v
    GUI stdout

This file contains NO Phase-2 processing logic.

It does NOT:
    - receive a target
    - crawl
    - discover URLs
    - discover parameters
    - create AttackVectors
    - generate payloads
    - select attacks
    - validate vulnerabilities
    - calculate progress
    - execute attacks
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path


# =============================================================================
# PROJECT PATH
# =============================================================================

ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# =============================================================================
# GUI OUTPUT BRIDGE
# =============================================================================

def emit(message: str) -> None:
    print(
        str(message),
        flush=True,
    )


# =============================================================================
# MAIN
# =============================================================================

async def main() -> int:

    emit(
        "[GUI] Phase-2 Started"
    )

    try:

        # ---------------------------------------------------------------------
        # ONLY backend import.
        #
        # Phase-2 backend owns:
        #
        #   Phase-1 output loading
        #   AttackVector construction
        #   attack execution
        #   validation
        #   confirmation
        #
        # ---------------------------------------------------------------------

        from phase2_refinement_validation.phase2_backend import (
            run_phase2,
        )

        # ---------------------------------------------------------------------
        # ONLY backend call.
        # ---------------------------------------------------------------------

        result = await run_phase2(
            output_callback=emit,
        )

        return int(
            result or 0
        )

    except Exception as exc:

        emit(
            "[ERROR] Phase-2 Failed: "
            f"{type(exc).__name__}: {exc}"
        )

        return 1


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    raise SystemExit(
        asyncio.run(
            main()
        )
    )