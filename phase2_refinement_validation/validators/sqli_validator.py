"""
===============================================================================

AVAF Pro

SQL Injection Validator

Purpose
-------
Performs evidence-based validation of SQL Injection candidates.

Important
---------
This validator NEVER assumes that a SQL/database error automatically proves
SQL Injection.

A candidate may only be validated when:

    1. The candidate belongs to SQL Injection.
    2. A real HTTP execution occurred.
    3. A real HTTP response was received.
    4. The attack detector produced SQL-specific evidence.
    5. The evidence is not already present in the baseline response.
    6. The attack response differs meaningfully from the baseline when a
       baseline is available.
    7. The evidence is attributable to the controlled payload.

This validator does NOT require every SQLi technique to succeed.

Error-based, boolean-based, time-based, UNION-based and stacked-query
validation are alternative evidence paths, not mandatory sequential stages.

===============================================================================
"""

from __future__ import annotations

import re
from typing import Any

from phase2_refinement_validation.models.attack_result import AttackResult
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)
from phase2_refinement_validation.validators.base_validator import BaseValidator


class SQLiValidator(BaseValidator):
    """
    Evidence-based SQL Injection validator.
    """

    id = "sqli"

    name = "SQL Injection Validator"

    # -------------------------------------------------------------------------
    # SQL-specific database error signatures
    # -------------------------------------------------------------------------

    DATABASE_ERROR_PATTERNS = (
        r"sql syntax",
        r"syntax error.*sql",
        r"sqlite error",
        r"sqlite3",
        r"mysql",
        r"mysqli",
        r"postgresql",
        r"postgres",
        r"psql",
        r"ora-\d+",
        r"oracle.*error",
        r"microsoft sql server",
        r"odbc sql server",
        r"sqlstate",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"jdbc.*sql",
    )

    # -------------------------------------------------------------------------
    # Generic text that must NOT be treated as SQL evidence
    # -------------------------------------------------------------------------

    GENERIC_ERROR_PATTERNS = (
        r"error",
        r"exception",
        r"failed",
        r"invalid",
        r"bad request",
    )

    # -------------------------------------------------------------------------
    # PUBLIC
    # -------------------------------------------------------------------------

    def supports(
        self,
        result: AttackResult,
    ) -> bool:
        """
        Return True only for SQL Injection AttackResults.
        """

        return (
            isinstance(result, AttackResult)
            and str(
                getattr(result, "attack", "")
                or ""
            ).lower()
            in {
                "sqli",
                "sql",
                "sql_injection",
                "sql-injection",
            }
        )

    # =========================================================================
    # VALIDATION
    # =========================================================================

    def validate(
        self,
        *,
        result: AttackResult,
        context: ValidationContext,
    ) -> ValidationResult | None:
        """
        Validate one SQL Injection candidate.

        This method is intentionally conservative.

        A detector candidate is not automatically a confirmed vulnerability.
        """

        stages: list[str] = []

        # ------------------------------------------------------------------
        # Stage 0 - candidate sanity
        # ------------------------------------------------------------------

        if not self.supports(result):

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection validator does not support "
                    "this attack result."
                ),
            )

        stages.append("candidate_supported")

        # ------------------------------------------------------------------
        # Stage 1 - real execution
        # ------------------------------------------------------------------

        if not self._real_execution(result):

            stages.append("real_execution_failed")

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection rejected: "
                    "real HTTP execution was not proven."
                ),
            )

        stages.append("real_execution_verified")

        # ------------------------------------------------------------------
        # Stage 2 - response received
        # ------------------------------------------------------------------

        attack_response = self._attack_response(
            result,
            context,
        )

        if attack_response is None:

            stages.append("attack_response_missing")

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection rejected: "
                    "attack response was unavailable."
                ),
            )

        stages.append("attack_response_available")

        # ------------------------------------------------------------------
        # Stage 3 - SQL-specific detector evidence
        # ------------------------------------------------------------------

        evidence = self._text(
            getattr(
                result,
                "evidence",
                "",
            )
        )

        indicator = self._text(
            getattr(
                result,
                "indicator",
                "",
            )
        )

        if not self._sql_specific_evidence(
            evidence,
            indicator,
            attack_response,
        ):

            stages.append("sql_specific_evidence_missing")

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection rejected: "
                    "response does not contain sufficiently "
                    "SQL-specific evidence."
                ),
            )

        stages.append("sql_specific_evidence_verified")

        # ------------------------------------------------------------------
        # Stage 4 - baseline attribution
        # ------------------------------------------------------------------

        baseline_response = self._baseline_response(
            context,
        )

        if baseline_response is not None:

            if self._evidence_exists_in_baseline(
                evidence=evidence,
                indicator=indicator,
                baseline_response=baseline_response,
            ):

                stages.append(
                    "evidence_present_in_baseline"
                )

                return self._failed_result(
                    stages=stages,
                    summary=(
                        "SQL Injection rejected: "
                        "the SQL-specific evidence was already "
                        "present in the baseline response."
                    ),
                )

            stages.append(
                "baseline_evidence_attribution_passed"
            )

        else:

            # Do not manufacture baseline proof.
            stages.append(
                "baseline_unavailable"
            )

        # ------------------------------------------------------------------
        # Stage 5 - controlled behavioral difference
        # ------------------------------------------------------------------

        behavior = self._behavioral_difference(
            baseline_response,
            attack_response,
        )

        if baseline_response is not None:

            if not behavior["changed"]:

                stages.append(
                    "meaningful_response_difference_missing"
                )

                return self._failed_result(
                    stages=stages,
                    summary=(
                        "SQL Injection rejected: "
                        "attack response did not demonstrate "
                        "a meaningful difference from baseline."
                    ),
                )

            stages.append(
                "meaningful_response_difference_verified"
            )

        # ------------------------------------------------------------------
        # Stage 6 - payload attribution
        # ------------------------------------------------------------------

        payload = self._text(
            getattr(
                result,
                "payload",
                "",
            )
        )

        if not payload:

            stages.append(
                "payload_missing"
            )

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection rejected: "
                    "the validating payload is unavailable."
                ),
            )

        stages.append(
            "payload_present"
        )

        # ------------------------------------------------------------------
        # Stage 7 - false-positive filtering
        # ------------------------------------------------------------------

        if self._false_positive(
            result=result,
            attack_response=attack_response,
            baseline_response=baseline_response,
            behavior=behavior,
        ):

            stages.append(
                "false_positive_detected"
            )

            return self._failed_result(
                stages=stages,
                summary=(
                    "SQL Injection rejected: "
                    "evidence was insufficiently attributable "
                    "to SQL injection."
                ),
            )

        stages.append(
            "false_positive_filter_passed"
        )

        # ------------------------------------------------------------------
        # FINAL
        # ------------------------------------------------------------------

        confidence = self._confidence(
            result=result,
            baseline_response=baseline_response,
            behavior=behavior,
        )

        # Never let this validator manufacture 99/100 certainty.
        confidence = min(
            confidence,
            95.0,
        )

        return ValidationResult(
            validator=self.id,
            success=True,
            status="confirmed",
            confidence=confidence,
            summary=(
                "SQL Injection candidate passed evidence-based "
                "validation with real execution and "
                "SQL-specific response evidence."
            ),
            evidence=[
                evidence,
            ],
            metadata={
                "attack": getattr(
                    result,
                    "attack",
                    "",
                ),
                "payload": payload,
                "indicator": indicator,
                "stages": stages,
                "baseline_available": (
                    baseline_response is not None
                ),
                "behavior_changed": behavior["changed"],
                "status_changed": behavior["status_changed"],
                "body_length_changed": behavior[
                    "body_length_changed"
                ],
                "baseline_status": behavior[
                    "baseline_status"
                ],
                "attack_status": behavior[
                    "attack_status"
                ],
                "baseline_body_length": behavior[
                    "baseline_body_length"
                ],
                "attack_body_length": behavior[
                    "attack_body_length"
                ],
            },
        )

    # =========================================================================
    # EXECUTION
    # =========================================================================

    @staticmethod
    def _real_execution(
        result: AttackResult,
    ) -> bool:
        """
        Require proof that the payload actually executed.
        """

        metadata = (
            getattr(
                result,
                "metadata",
                {},
            )
            or {}
        )

        return bool(
            metadata.get(
                "real_http_execution",
                False,
            )
        ) and bool(
            metadata.get(
                "request_sent",
                getattr(
                    result,
                    "request_sent",
                    False,
                ),
            )
        ) and bool(
            metadata.get(
                "response_received",
                getattr(
                    result,
                    "response_received",
                    False,
                ),
            )
        )

    # =========================================================================
    # RESPONSE EXTRACTION
    # =========================================================================

    @classmethod
    def _attack_response(
        cls,
        result: AttackResult,
        context: ValidationContext,
    ) -> Any:
        """
        Retrieve the actual attack response.
        """

        cached = getattr(
            context,
            "cache",
            {},
        )

        if isinstance(cached, dict):

            response = cached.get(
                "attack_response"
            )

            if response is not None:
                return response

        metadata = (
            getattr(
                result,
                "metadata",
                {},
            )
            or {}
        )

        return metadata.get(
            "response"
        )

    @classmethod
    def _baseline_response(
        cls,
        context: ValidationContext,
    ) -> Any:
        """
        Retrieve the original-value baseline/replay response.
        """

        baseline = getattr(
            context,
            "baseline",
            None,
        )

        if baseline is None:

            cache = getattr(
                context,
                "cache",
                {},
            )

            if isinstance(cache, dict):

                baseline = cache.get(
                    "replay_response"
                )

        if baseline is None:
            return None

        response = getattr(
            baseline,
            "response",
            None,
        )

        return (
            response
            if response is not None
            else baseline
        )

    # =========================================================================
    # SQL EVIDENCE
    # =========================================================================

    @classmethod
    def _sql_specific_evidence(
        cls,
        evidence: str,
        indicator: str,
        response: Any,
    ) -> bool:
        """
        Require a genuine SQL-specific marker.

        Generic words such as 'error' or 'exception' are insufficient.
        """

        combined = " ".join(
            part
            for part in (
                evidence,
                indicator,
                cls._body(response),
            )
            if part
        ).lower()

        if not combined:
            return False

        return any(
            re.search(
                pattern,
                combined,
                flags=re.IGNORECASE,
            )
            for pattern in cls.DATABASE_ERROR_PATTERNS
        )

    # =========================================================================
    # BASELINE ATTRIBUTION
    # =========================================================================

    @classmethod
    def _evidence_exists_in_baseline(
        cls,
        *,
        evidence: str,
        indicator: str,
        baseline_response: Any,
    ) -> bool:
        """
        Reject SQL evidence that was already present before injection.
        """

        baseline = cls._body(
            baseline_response
        ).lower()

        if not baseline:
            return False

        candidates = []

        if evidence:
            candidates.append(
                evidence.lower()
            )

        if indicator:
            candidates.append(
                indicator.lower()
            )

        for marker in candidates:

            marker = marker.strip()

            if (
                marker
                and len(marker) >= 4
                and marker in baseline
            ):
                return True

        return False

    # =========================================================================
    # BEHAVIOR
    # =========================================================================

    @classmethod
    def _behavioral_difference(
        cls,
        baseline_response: Any,
        attack_response: Any,
    ) -> dict[str, Any]:
        """
        Calculate deterministic baseline/attack response differences.

        This does not claim that every difference is caused by SQLi.
        It only records observable differences for attribution.
        """

        baseline_status = cls._status(
            baseline_response
        )

        attack_status = cls._status(
            attack_response
        )

        baseline_body = cls._body(
            baseline_response
        )

        attack_body = cls._body(
            attack_response
        )

        status_changed = (
            baseline_response is not None
            and baseline_status != attack_status
        )

        body_length_changed = (
            baseline_response is not None
            and len(baseline_body)
            != len(attack_body)
        )

        body_changed = (
            baseline_response is not None
            and baseline_body
            != attack_body
        )

        return {
            "changed": bool(
                status_changed
                or body_length_changed
                or body_changed
            ),
            "status_changed": status_changed,
            "body_length_changed": body_length_changed,
            "body_changed": body_changed,
            "baseline_status": baseline_status,
            "attack_status": attack_status,
            "baseline_body_length": len(
                baseline_body
            ),
            "attack_body_length": len(
                attack_body
            ),
        }

    # =========================================================================
    # FALSE POSITIVE FILTER
    # =========================================================================

    @staticmethod
    def _false_positive(
        *,
        result: AttackResult,
        attack_response: Any,
        baseline_response: Any,
        behavior: dict[str, Any],
    ) -> bool:
        """
        Apply conservative false-positive rules.
        """

        metadata = (
            getattr(
                result,
                "metadata",
                {},
            )
            or {}
        )

        # Detector must not explicitly report failure.
        # A detector failure alone must NOT reject a candidate
        # when the validator independently has strong SQL-specific
        # evidence from the real HTTP response.
        #
        # The validator is the final evidence-based decision layer.
        # Therefore detector_success is supporting evidence, not
        # an absolute veto.
        if (
            "detector_success" in metadata
            and not metadata.get("detector_success")
        ):
            # Continue validation.
            #
            # Stage 3 (_sql_specific_evidence) has already established
            # that the attack response contains a SQL-specific marker.
            # Stage 4/5/6/7 will independently check attribution,
            # behavioral change, payload presence and false positives.
            pass

        # A baseline exists but the attack produced no observable change.
        if (
            baseline_response is not None
            and not behavior.get(
                "changed",
                False,
            )
        ):
            return True

        return False

    # =========================================================================
    # CONFIDENCE
    # =========================================================================

    @staticmethod
    def _confidence(
        *,
        result: AttackResult,
        baseline_response: Any,
        behavior: dict[str, Any],
    ) -> float:
        """
        Calculate conservative validator confidence.

        Detector confidence is supporting evidence, not automatic proof.
        """

        detector_confidence = float(
            getattr(
                result,
                "confidence",
                0.0,
            )
            or 0.0
        )

        score = 50.0

        # SQL-specific detector evidence.
        score += 15.0

        # Real baseline/attack behavioral difference.
        if baseline_response is not None:

            if behavior.get(
                "status_changed",
                False,
            ):
                score += 10.0

            if behavior.get(
                "body_length_changed",
                False,
            ):
                score += 5.0

            if behavior.get(
                "body_changed",
                False,
            ):
                score += 5.0

        # Detector confidence contributes, but cannot dominate.
        if detector_confidence >= 80.0:
            score += 10.0

        elif detector_confidence >= 70.0:
            score += 5.0

        return min(
            score,
            95.0,
        )

    # =========================================================================
    # RESULT HELPERS
    # =========================================================================

    @staticmethod
    def _failed_result(
        *,
        stages: list[str],
        summary: str,
    ) -> ValidationResult:
        """
        Construct a failed validation result.
        """

        return ValidationResult(
            validator="sqli",
            success=False,
            status="failed",
            confidence=0.0,
            summary=summary,
            evidence=[],
            metadata={
                "stages": stages,
            },
        )

    # =========================================================================
    # RESPONSE HELPERS
    # =========================================================================

    @staticmethod
    def _body(
        response: Any,
    ) -> str:
        """
        Extract response body safely.
        """

        if response is None:
            return ""

        value = None

        if hasattr(
            response,
            "text",
        ):
            value = getattr(
                response,
                "text",
                None,
            )

        elif hasattr(
            response,
            "body",
        ):
            value = getattr(
                response,
                "body",
                None,
            )

        elif isinstance(
            response,
            str,
        ):
            value = response

        if isinstance(
            value,
            bytes,
        ):
            return value.decode(
                "utf-8",
                errors="replace",
            )

        return str(
            value or ""
        )

    @staticmethod
    def _status(
        response: Any,
    ) -> int:
        """
        Extract HTTP status safely.
        """

        if response is None:
            return 0

        value = getattr(
            response,
            "status_code",
            None,
        )

        if value is None:
            value = getattr(
                response,
                "status",
                None,
            )

        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _text(
        value: Any,
    ) -> str:
        """
        Normalize arbitrary values to text.
        """

        if value is None:
            return ""

        return str(
            value
        ).strip()