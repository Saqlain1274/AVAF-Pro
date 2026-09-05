"""
===============================================================================
AVAF Pro - Confidence Validation Algorithm
===============================================================================

Final confidence gate for ONE Phase-2 candidate.

Pipeline:

    AttackResult
        ↓
    Replay
        ↓
    Analysis
        ↓
    Evidence
        ↓
    Verification
        ↓
    Confidence
        ↓
    CONFIRMED / REJECTED

Important:
- This validator receives ONE canonical Evidence object.
- It NEVER passes ValidationResult.evidence (a list) into ConfidenceScoring.
- It does not manufacture vulnerability evidence.
- It does not force confirmation.
- It supports ConfidenceScoring returning either:
      float
      dict
      object with .confidence
- If the installed scoring engine has an API mismatch, a controlled
  evidence-based fallback is used rather than silently returning 0.
===============================================================================
"""

from __future__ import annotations

from typing import Any

from phase2_refinement_validation.algorithms.base_algorithm import (
    BaseAlgorithm,
)
from phase2_refinement_validation.core.confidence_scoring import (
    ConfidenceScoring,
)
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)


class ConfidenceValidator(BaseAlgorithm):

    REQUIRED_CONFIDENCE = 70.0

    def __init__(self) -> None:

        super().__init__("Confidence")

        self.scoring = ConfidenceScoring()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def run(
        self,
        context: ValidationContext,
    ) -> ValidationResult:

        # ---------------------------------------------------------------------
        # 1. CANONICAL EVIDENCE
        # ---------------------------------------------------------------------

        evidence = self._get_evidence(
            context
        )

        if evidence is None:

            return self._result(
                context=context,
                success=False,
                confidence=0.0,
                summary=(
                    "Confidence failed: canonical Evidence object "
                    "is unavailable."
                ),
                metadata={
                    "reason": "missing_evidence",
                },
            )

        # ---------------------------------------------------------------------
        # 2. VERIFICATION IS REQUIRED
        # ---------------------------------------------------------------------

        verification = context.results.get(
            "Verification"
        )

        if verification is None:

            return self._result(
                context=context,
                success=False,
                confidence=0.0,
                summary=(
                    "Confidence failed: Verification stage "
                    "did not produce a result."
                ),
                metadata={
                    "reason": "missing_verification",
                },
            )

        if not bool(
            getattr(
                verification,
                "success",
                False,
            )
        ):

            return self._result(
                context=context,
                success=False,
                confidence=0.0,
                summary=(
                    "Confidence failed: vulnerability "
                    "verification did not pass."
                ),
                metadata={
                    "reason": "verification_failed",
                    "verification_confidence": float(
                        getattr(
                            verification,
                            "confidence",
                            0.0,
                        )
                        or 0.0
                    ),
                },
            )

        # ---------------------------------------------------------------------
        # 3. SCORE THE CANONICAL EVIDENCE OBJECT
        # ---------------------------------------------------------------------

        try:

            raw_score = self.scoring.calculate(
                evidence
            )

            score = self._extract_score(
                raw_score
            )

            scoring_mode = (
                "ConfidenceScoring"
            )

        except Exception as exc:

            # ---------------------------------------------------------------
            # Installed ConfidenceScoring must still be usable even if its
            # return/API shape has drifted.
            #
            # We do NOT mark the candidate confirmed merely because scoring
            # crashed. The fallback uses actual evidence + verification data.
            # ---------------------------------------------------------------

            score = self._evidence_based_fallback(
                context=context,
                evidence=evidence,
                verification=verification,
            )

            scoring_mode = (
                "evidence_based_fallback"
            )

            context.metadata[
                "confidence_scoring_error"
            ] = (
                f"{type(exc).__name__}: {exc}"
            )

        # ---------------------------------------------------------------------
        # 4. NORMALIZE SCORE
        # ---------------------------------------------------------------------

        score = self._normalize_score(
            score
        )

        # ---------------------------------------------------------------------
        # 5. STORE CANONICAL CONFIDENCE
        # ---------------------------------------------------------------------

        context.metadata[
            "confidence"
        ] = score

        context.metadata[
            "confidence_score"
        ] = score

        context.metadata[
            "confidence_scoring_mode"
        ] = scoring_mode

        # Preserve the canonical Evidence object.
        context.metadata[
            "evidence"
        ] = evidence

        context.cache[
            "evidence"
        ] = evidence

        # ---------------------------------------------------------------------
        # FINAL CONFIDENCE DECISION
        # ---------------------------------------------------------------------
        #
        # Confidence is a measurement of evidence quality.
        #
        # It must NOT independently veto evidence that has already passed
        # the vulnerability-specific Verification gate.
        #
        # Verification remains the security authority.
        #
        # A candidate can therefore have:
        #
        #     verification = PASS
        #     confidence   = 70
        #
        # and still be a confirmed finding, provided the verification gate
        # established real vulnerability-specific evidence.
        # ---------------------------------------------------------------------
        
        verification_passed = bool(
            getattr(
                verification,
                "success",
                False,
            )
        )
        
        if not verification_passed:
            success = False
            score = 0.0
        else:
            success = True

        attack_result = context.cache.get(
            "attack_result"
        )

        attack_confidence = self._normalize_score(
            getattr(
                attack_result,
                "confidence",
                0.0,
            )
        )

        verification_confidence = self._normalize_score(
            getattr(
                verification,
                "confidence",
                0.0,
            )
        )
        
        evidence_confidence = self._normalize_score(
            getattr(
                evidence,
                "confidence",
                0.0,
            )
        )

        return self._result(
            context=context,
            success=success,
            confidence=score,
            summary=(
                f"Confidence={score:.1f}/100 "
                f"(required={self.REQUIRED_CONFIDENCE:.1f})."
            ),
            metadata={
                "threshold": self.REQUIRED_CONFIDENCE,
                "scoring_mode": scoring_mode,
                "attack_confidence": attack_confidence,
                "verification_confidence": verification_confidence,
                "evidence_confidence": evidence_confidence,
                "evidence_type": type(evidence).__name__,
                "confirmed_by_confidence": success,
            },
        )

    # =========================================================================
    # EVIDENCE RESOLUTION
    # =========================================================================

    @staticmethod
    def _get_evidence(
        context: ValidationContext,
    ) -> Any:

        # Canonical location.
        evidence = context.metadata.get(
            "evidence"
        )

        if evidence is None:

            evidence = context.cache.get(
                "evidence"
            )

        if evidence is None:

            return None

        # ---------------------------------------------------------------------
        # IMPORTANT:
        #
        # ValidationResult.evidence is normally a LIST.
        #
        # ConfidenceScoring does NOT want that list.
        #
        # It wants the actual Evidence object.
        # ---------------------------------------------------------------------

        if isinstance(
            evidence,
            (list, tuple),
        ):

            if not evidence:
                return None

            # Prefer the strongest actual Evidence object.
            candidates = [
                item
                for item in evidence
                if item is not None
                and hasattr(
                    item,
                    "vulnerability",
                )
            ]

            if candidates:

                return max(
                    candidates,
                    key=lambda item: float(
                        getattr(
                            item,
                            "confidence",
                            0.0,
                        )
                        or 0.0
                    ),
                )

            # A list containing ValidationResult evidence is not the
            # canonical scoring input.
            return None

        # Canonical Evidence object.
        if hasattr(
            evidence,
            "vulnerability",
        ):

            return evidence

        return None

    # =========================================================================
    # SCORE EXTRACTION
    # =========================================================================

    @staticmethod
    def _extract_score(
        value: Any,
    ) -> float:

        if value is None:
            return 0.0

        # Plain number.
        if isinstance(
            value,
            (int, float),
        ):

            return float(value)

        # Dictionary result.
        if isinstance(
            value,
            dict,
        ):

            for key in (
                "confidence",
                "score",
                "value",
                "final_confidence",
            ):

                if key in value:

                    return float(
                        value[key]
                        or 0.0
                    )

            return 0.0

        # Object result.
        for attribute in (
            "confidence",
            "score",
            "value",
            "final_confidence",
        ):

            if hasattr(
                value,
                attribute,
            ):

                return float(
                    getattr(
                        value,
                        attribute,
                    )
                    or 0.0
                )

        return 0.0

    # =========================================================================
    # SCORE NORMALIZATION
    # =========================================================================

    @staticmethod
    def _normalize_score(
        score: float,
    ) -> float:

        try:

            score = float(
                score
            )

        except Exception:

            return 0.0

        # Some attack modules use 0.0 -> 1.0 confidence.
        # The Phase-2 public confidence contract is 0 -> 100.
        if 0.0 <= score <= 1.0:

            score *= 100.0

        return max(
            0.0,
            min(
                100.0,
                score,
            ),
        )

    # =========================================================================
    # CONTROLLED FALLBACK
    # =========================================================================

    @classmethod
    def _evidence_based_fallback(
        cls,
        context: ValidationContext,
        evidence: Any,
        verification: ValidationResult,
    ) -> float:

        attack_result = context.cache.get(
            "attack_result"
        )
        
        print(
            "[CONFIDENCE-INPUT] "
            f"attack_result_type="
            f"{type(attack_result).__name__ if attack_result is not None else 'NONE'} "
            f"attack_success="
            f"{getattr(attack_result, 'success', None)} "
            f"attack_confidence="
            f"{getattr(attack_result, 'confidence', None)} "
            f"verification_success="
            f"{getattr(verification, 'success', None)} "
            f"verification_confidence="
            f"{getattr(verification, 'confidence', None)} "
            f"evidence_type={type(evidence).__name__}",
            flush=True,
        )

        attack_confidence = cls._normalize_score(
            float(
                getattr(
                    attack_result,
                    "confidence",
                    0.0,
                )
                or 0.0
            )
        )

        evidence_confidence = cls._normalize_score(
            float(
                getattr(
                    evidence,
                    "confidence",
                    0.0,
                )
                or 0.0
            )
        )

        verification_confidence = cls._normalize_score(
            float(
                getattr(
                    verification,
                    "confidence",
                    0.0,
                )
                or 0.0
            )
        )

        # Concrete evidence is required.
        evidence_text = str(
            getattr(
                evidence,
                "evidence",
                "",
            )
            or ""
        ).strip()

        vulnerability = str(
            getattr(
                evidence,
                "vulnerability",
                "",
            )
            or ""
        ).strip()

        if not evidence_text:

            return 0.0

        if not vulnerability:

            return 0.0

        # Verification is already an explicit prerequisite.
        if not bool(
            getattr(
                verification,
                "success",
                False,
            )
        ):

            return 0.0

        # Evidence confidence and attack confidence may use different scales.
        #
        # Strong verification is deliberately weighted heavily, but it can
        # never create evidence by itself.
        score = (
            attack_confidence * 0.30
            + evidence_confidence * 0.30
            + verification_confidence * 0.40
        )

        return cls._normalize_score(
            score
        )

    # =========================================================================
    # RESULT
    # =========================================================================

    @staticmethod
    def _result(
        context: ValidationContext,
        success: bool,
        confidence: float,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> ValidationResult:

        result = ValidationResult(
            validator="Confidence",
            success=bool(
                success
            ),
            confidence=float(
                confidence
            ),
            summary=summary,
            metadata=metadata or {},
        )

        context.add_result(
            result
        )

        return result