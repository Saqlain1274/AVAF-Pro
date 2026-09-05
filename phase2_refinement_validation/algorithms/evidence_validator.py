"""
===============================================================================
AVAF Pro - Evidence Validation Algorithm
===============================================================================

Collects evidence produced by the attack engine and analysis stage.

Evidence is NEVER invented here.
===============================================================================
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

from phase2_refinement_validation.algorithms.base_algorithm import (
    BaseAlgorithm,
)
from phase2_refinement_validation.models.evidence import Evidence
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)


class EvidenceValidator(BaseAlgorithm):

    def __init__(self) -> None:
        super().__init__("Evidence")

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def run(
        self,
        context: ValidationContext,
    ) -> ValidationResult:

        try:

            attack_result = context.cache.get(
                "attack_result"
            )

            if attack_result is None:
                return self._result(
                    context,
                    False,
                    0.0,
                    "Evidence failed: AttackResult unavailable.",
                )

            evidence_text = self._text(
                getattr(
                    attack_result,
                    "evidence",
                    "",
                )
            )

            indicator_text = self._text(
                getattr(
                    attack_result,
                    "indicator",
                    "",
                )
            )

            if not (
                evidence_text
                or indicator_text
            ):
                return self._result(
                    context,
                    False,
                    0.0,
                    "Evidence failed: no attack evidence supplied.",
                )

            exchanges = list(
                getattr(
                    context,
                    "exchanges",
                    [],
                )
                or []
            )

            # IMPORTANT:
            # Attack response is not the replay baseline.
            #
            # Keep both separately.
            attack_response = context.cache.get(
                "attack_response"
            )

            evidence = self._build_evidence(
                context=context,
                attack_result=attack_result,
                exchanges=exchanges,
                attack_response=attack_response,
            )

            context.metadata[
                "evidence"
            ] = evidence

            context.cache[
                "evidence"
            ] = evidence

            attack_confidence = self._normalise_confidence(
                getattr(
                    attack_result,
                    "confidence",
                    0.0,
                )
            )

            return self._result(
                context,
                True,
                max(
                    1.0,
                    attack_confidence,
                ),
                (
                    "Validation evidence collected from "
                    "AttackResult, attack response, "
                    "analysis indicators, and replay exchange."
                ),
            )

        except Exception as exc:

            return self._result(
                context,
                False,
                0.0,
                (
                    "Evidence failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                error=str(exc),
            )

    # =========================================================================
    # EVIDENCE MODEL
    # =========================================================================

    @staticmethod
    def _build_evidence(
        context,
        attack_result,
        exchanges,
        attack_response,
    ):

        plan = context.attack_plan

        attack_name = str(
            getattr(
                attack_result,
                "attack",
                "",
            )
            or ""
        )

        attack_evidence = getattr(
            attack_result,
            "evidence",
            "",
        )

        attack_indicator = getattr(
            attack_result,
            "indicator",
            "",
        )

        payload = getattr(
            attack_result,
            "payload",
            "",
        )

        confidence = (
            EvidenceValidator._normalise_confidence(
                getattr(
                    attack_result,
                    "confidence",
                    0.0,
                )
            )
        )

        values = {
            "attack_plan": plan,
            "vulnerability": attack_name,
            "attack": attack_name,
            "payload": payload,
            "evidence": attack_evidence,
            "indicator": attack_indicator,
            "indicators": list(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
            "exchanges": exchanges,
            "responses": exchanges,
            "attack_response": attack_response,
            "response": attack_response,
            "confidence": confidence,
            "verified": False,
        }

        try:

            signature = inspect.signature(
                Evidence
            )

            kwargs = {}

            for name in signature.parameters:

                if name in values:
                    kwargs[name] = values[name]

            return Evidence(
                **kwargs
            )

        except Exception:

            return SimpleNamespace(
                attack_plan=plan,
                vulnerability=attack_name,
                attack=attack_name,
                payload=payload,
                evidence=attack_evidence,
                indicator=attack_indicator,
                indicators=values["indicators"],
                exchanges=exchanges,
                responses=exchanges,
                attack_response=attack_response,
                response=attack_response,
                confidence=confidence,
                verified=False,
            )

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _text(
        value,
    ) -> str:

        if value is None:
            return ""

        if isinstance(
            value,
            str,
        ):
            return value.strip()

        for attribute in (
            "value",
            "evidence",
            "indicator",
            "marker",
            "pattern",
            "expected",
        ):

            candidate = getattr(
                value,
                attribute,
                None,
            )

            if candidate not in (
                None,
                "",
            ):
                return str(
                    candidate
                ).strip()

        return str(
            value
        ).strip()

    @staticmethod
    def _normalise_confidence(
        value,
    ) -> float:

        try:
            value = float(
                value or 0.0
            )
        except Exception:
            return 0.0

        if 0.0 < value <= 1.0:
            value *= 100.0

        return max(
            0.0,
            min(
                100.0,
                value,
            ),
        )

    @staticmethod
    def _result(
        context,
        success,
        confidence,
        summary,
        error=None,
    ):

        metadata = {
            "exchange_count": len(
                getattr(
                    context,
                    "exchanges",
                    [],
                )
                or []
            ),
            "indicator_count": len(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
            "attack_response_available": (
                context.cache.get(
                    "attack_response"
                ) is not None
            ),
        }

        if error:
            metadata["error"] = error

        result = ValidationResult(
            validator="Evidence",
            success=bool(success),
            confidence=float(confidence),
            summary=summary,
            evidence=(
                [context.metadata["evidence"]]
                if "evidence" in context.metadata
                else []
            ),
            indicators=list(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
            metadata=metadata,
        )

        context.add_result(
            result
        )

        return result
