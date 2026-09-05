"""
===============================================================================
AVAF Pro - Analysis Validation Algorithm
===============================================================================

Purpose
-------
Analyze the AttackResult's actual attack response.

Important:
    ValidationContext uses `exchanges`, NOT `responses`.

The attack detector has already produced an AttackResult containing:
    - attack
    - payload
    - evidence
    - indicator
    - confidence
    - originating vector

This stage converts that detector evidence into canonical Indicators.

Analysis does NOT confirm the vulnerability.
Verification owns confirmation.
===============================================================================
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

from phase2_refinement_validation.algorithms.base_algorithm import (
    BaseAlgorithm,
)
from phase2_refinement_validation.core.knowledge_loader import (
    KnowledgeLoader,
)
from phase2_refinement_validation.models.indicator import Indicator
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)


class AnalysisValidator(BaseAlgorithm):

    def __init__(self) -> None:
        super().__init__("Analysis")
        self.loader = KnowledgeLoader()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def run(
        self,
        context: ValidationContext,
    ) -> ValidationResult:

        try:
            self._load_knowledge(context)

            attack_result = context.cache.get(
                "attack_result"
            )

            if attack_result is None:
                return self._result(
                    context,
                    False,
                    0.0,
                    "Analysis failed: AttackResult unavailable.",
                )

            # -------------------------------------------------------------
            # IMPORTANT:
            #
            # Do NOT use context.responses.
            #
            # ValidationContext owns:
            #     context.exchanges
            #
            # The attack response is kept separately in:
            #     context.cache["attack_response"]
            # -------------------------------------------------------------

            attack_response = context.cache.get(
                "attack_response"
            )

            exchanges = list(
                getattr(
                    context,
                    "exchanges",
                    [],
                )
                or []
            )

            evidence = self._text(
                getattr(
                    attack_result,
                    "evidence",
                    "",
                )
            )

            indicator = self._text(
                getattr(
                    attack_result,
                    "indicator",
                    "",
                )
            )

            payload = self._text(
                getattr(
                    attack_result,
                    "payload",
                    "",
                )
            )

            attack_name = self._text(
                getattr(
                    attack_result,
                    "attack",
                    "",
                )
            )

            # -------------------------------------------------------------
            # An AttackResult without evidence is not analytically useful.
            # -------------------------------------------------------------

            if not (
                evidence
                or indicator
            ):
                return self._result(
                    context,
                    False,
                    0.0,
                    "Analysis failed: AttackResult contains no evidence.",
                )

            # -------------------------------------------------------------
            # Build one canonical indicator.
            # -------------------------------------------------------------

            canonical_value = (
                indicator
                or evidence
            )

            analysis_indicator = (
                self._build_indicator(
                    attack_name=attack_name,
                    evidence=evidence,
                    indicator=indicator,
                    payload=payload,
                    value=canonical_value,
                    attack_response=attack_response,
                )
            )

            context.add_indicator(
                analysis_indicator
            )

            context.metadata[
                "analysis_attack_response_available"
            ] = attack_response is not None

            context.metadata[
                "analysis_evidence_available"
            ] = bool(evidence)

            context.metadata[
                "analysis_indicator_available"
            ] = bool(indicator)

            context.metadata[
                "analysis_exchange_count"
            ] = len(exchanges)

            confidence = self._normalise_confidence(
                getattr(
                    attack_result,
                    "confidence",
                    0.0,
                )
            )

            return self._result(
                context,
                True,
                confidence,
                (
                    f"Analysis extracted "
                    f"{len(context.indicators)} indicator(s) "
                    f"from attack={attack_name or 'unknown'}."
                ),
            )

        except Exception as exc:

            return self._result(
                context,
                False,
                0.0,
                (
                    "Analysis failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                error=str(exc),
            )

    # =========================================================================
    # KNOWLEDGE
    # =========================================================================

    def _load_knowledge(
        self,
        context: ValidationContext,
    ) -> None:

        try:
            context.set_knowledge(
                "heuristics",
                self.loader.load(
                    "heuristics",
                    "generic",
                ),
            )
        except Exception:
            context.set_knowledge(
                "heuristics",
                {},
            )

        try:
            context.set_knowledge(
                "rules",
                self.loader.load(
                    "rules",
                    "generic",
                ),
            )
        except Exception:
            context.set_knowledge(
                "rules",
                {},
            )

        try:
            context.set_knowledge(
                "signatures",
                self.loader.load(
                    "signatures",
                    "generic",
                ),
            )
        except Exception:
            context.set_knowledge(
                "signatures",
                {},
            )

    # =========================================================================
    # INDICATOR ADAPTER
    # =========================================================================

    @staticmethod
    def _build_indicator(
        attack_name: str,
        evidence: str,
        indicator: str,
        payload: str,
        value: str,
        attack_response,
    ):

        values = {
            "attack": attack_name,
            "attack_type": attack_name,
            "vulnerability": attack_name,
            "type": attack_name,
            "description": evidence or indicator,
            "evidence": evidence,
            "indicator": indicator,
            "marker": indicator or evidence,
            "pattern": indicator or evidence,
            "expected": indicator or evidence,
            "value": value,
            "payload": payload,
            "source": "AttackResult",
            "verified": False,
            "response": attack_response,
        }

        # -------------------------------------------------------------
        # Prefer the project's real Indicator model.
        # -------------------------------------------------------------

        try:

            signature = inspect.signature(
                Indicator
            )

            kwargs = {}

            for name in signature.parameters:

                if name in values:
                    kwargs[name] = values[name]

            return Indicator(
                **kwargs
            )

        except Exception:

            # ---------------------------------------------------------
            # Compatibility fallback.
            #
            # This still satisfies the ValidationContext indicator
            # contract and preserves every relevant field.
            # ---------------------------------------------------------

            return SimpleNamespace(
                attack=attack_name,
                attack_type=attack_name,
                vulnerability=attack_name,
                type=attack_name,
                description=evidence or indicator,
                evidence=evidence,
                indicator=indicator,
                marker=indicator or evidence,
                pattern=indicator or evidence,
                expected=indicator or evidence,
                value=value,
                payload=payload,
                source="AttackResult",
                verified=False,
                response=attack_response,
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
            "indicator_count": len(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
        }

        if error:
            metadata["error"] = error

        result = ValidationResult(
            validator="Analysis",
            success=bool(success),
            confidence=float(confidence),
            summary=summary,
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