"""
===============================================================================
AVAF Pro

Response Engine

Phase-2 Validation Orchestrator

Input:
    Phase-1 Candidate Attack Vectors

Output:
    Confirmed Findings

Pipeline

Candidate
    ↓
Attack Plan
    ↓
Replay Original Request
    ↓
Baseline Response
    ↓
Validator
    ↓
Response Analysis
    ↓
Refinement
    ↓
Evidence
    ↓
Finding

===============================================================================
"""

from __future__ import annotations

import logging

from ..attack_context import AttackContext
from ..models.attack_plan import AttackPlan

logger = logging.getLogger(__name__)


class ResponseEngine:

    def __init__(
        self,
        attack_engine,
        finding_builder,
    ):

        self.attack_engine = attack_engine
        self.finding_builder = finding_builder

    # ============================================================
    # MAIN ENTRY
    # ============================================================

    def validate(
        self,
        context: AttackContext,
        candidates: list[dict],
    ):

        findings = []

        logger.info(
            "Starting Phase-2 validation (%d candidates)",
            len(candidates),
        )

        for candidate in candidates:

            plan = self._build_plan(candidate)

            evidence = self.attack_engine.execute(
                context=context,
                plan=plan,
            )

            if evidence is None:
                continue

            finding = self.finding_builder.build(
                evidence
            )

            if finding is not None:
                findings.append(finding)

        logger.info(
            "Confirmed %d findings",
            len(findings),
        )

        return findings

    # ============================================================
    # BUILD PLAN
    # ============================================================

    def _build_plan(
        self,
        candidate: dict,
    ) -> AttackPlan:

        return AttackPlan(

            vector_id=candidate["vector_id"],

            vulnerability=candidate.get(
                "vulnerability",
                "UNKNOWN"
            ),

            confidence=float(
                candidate.get(
                    "confidence",
                    0.0
                )
            ),

            risk=candidate.get(
                "risk",
                "Unknown"
            ),

            method=candidate["method"],

            url=candidate["url"],

            parameter=candidate["parameter"],

            location=candidate["location"],

            original_value=candidate.get(
                "value"
            ),

            metadata={
                "phase1": candidate
            }
        )