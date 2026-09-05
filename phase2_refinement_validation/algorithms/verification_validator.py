"""
===============================================================================
AVAF Pro - Phase 2 Verification Validator
===============================================================================

Purpose
-------
Final security-evidence gate for an existing AttackResult.

This validator does NOT:
    - create payloads
    - create attack vectors
    - send HTTP requests
    - invent responses
    - manufacture evidence
    - confirm based on registry success alone

A vulnerability is verified only when the existing attack execution provides
real HTTP execution proof AND the vulnerability-specific detector provides
evidence that is actually present in the attack response.

Required evidence chain
-----------------------
1. AttackResult exists.
2. Real HTTP execution metadata exists.
3. Request was actually sent.
4. Response was actually received.
5. Payload was transmitted through the real HTTP request.
6. A real HTTP response object exists.
7. Detector succeeded.
8. Detector confidence >= 70.
9. Detector evidence/indicator exists in the attack response.
10. Evidence is not merely payload reflection.
11. Strong detector results require attack-response corroboration.
12. Medium detector results require BOTH:
        - evidence introduced by the attack
        - meaningful response corroboration

Generic registry/pipeline validators can NEVER independently confirm a
vulnerability.
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.algorithms.base_algorithm import (
    BaseAlgorithm,
)
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)


class VerificationValidator(BaseAlgorithm):

    STRONG_DETECTOR_CONFIDENCE = 80.0
    MEDIUM_DETECTOR_CONFIDENCE = 70.0

    GENERIC_VALIDATORS = {
        "",
        "analysis",
        "evidence",
        "replay",
        "verification",
        "confidence",
        "phase2_algorithm_pipeline",
    }

    def __init__(self) -> None:
        super().__init__("Verification")

    # =========================================================================
    # PUBLIC ENTRY POINT
    # =========================================================================

    def run(
        self,
        context: ValidationContext,
    ) -> ValidationResult:

        cache = (
            getattr(context, "cache", {}) or {}
        )

        attack_result = cache.get(
            "attack_result"
        )

        if attack_result is None:
            return self._finish(
                context,
                False,
                0.0,
                "AttackResult unavailable.",
            )

        attack_metadata = (
            getattr(
                attack_result,
                "metadata",
                {},
            )
            or {}
        )

        # ---------------------------------------------------------------------
        # REAL HTTP EXECUTION PROOF
        #
        # These values MUST originate from the actual executor.
        # This validator does not manufacture them.
        # ---------------------------------------------------------------------

        real_http_execution = bool(
            attack_metadata.get(
                "real_http_execution",
                False,
            )
        )

        request_sent = bool(
            attack_metadata.get(
                "request_sent",
                False,
            )
        )

        response_received = bool(
            attack_metadata.get(
                "response_received",
                False,
            )
        )

        payload_executed = bool(
            attack_metadata.get(
                "payload_executed",
                False,
            )
        )

        attack_response = self._get_attack_response(
            context,
            attack_result,
        )

        attack_status = self._status(
            attack_response
        )

        attack_body = self._body(
            attack_response
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

        detector_confidence = (
            self._normalise_confidence(
                getattr(
                    attack_result,
                    "confidence",
                    0.0,
                )
            )
        )

        detector_success = bool(
            getattr(
                attack_result,
                "success",
                False,
            )
        )

        attack_name = (
            self._text(
                getattr(
                    attack_result,
                    "vulnerability",
                    "",
                )
            )
            or self._text(
                getattr(
                    attack_result,
                    "attack",
                    "",
                )
            )
            or self._text(
                getattr(
                    context,
                    "metadata",
                    {},
                ).get(
                    "attack",
                    "",
                )
            )
        )

        print(
            "[VERIFICATION-INPUT] "
            f"attack={attack_name or 'unknown'} "
            f"result_type={type(attack_result).__name__} "
            f"real_http_execution={real_http_execution} "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"payload_executed={payload_executed} "
            f"detector_success={detector_success} "
            f"confidence={detector_confidence:.1f} "
            f"status={attack_status} "
            f"evidence={evidence!r} "
            f"indicator={indicator!r}",
            flush=True,
        )

        # =========================================================================
        # HARD EXECUTION GATES
        # =========================================================================

        if not real_http_execution:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: real HTTP execution was not proven.",
            )

        if not request_sent:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: attack request was not proven sent.",
            )

        if not response_received:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: attack response was not proven received.",
            )

        # -------------------------------------------------------------------------
        # PAYLOAD EXECUTION / APPLICATION-EFFECT GATE
        # -------------------------------------------------------------------------
        #
        # AttackExecutor proves HTTP transmission only.
        # Application-level payload execution must be established from the
        # vulnerability-specific attack response below.
        #
        # Therefore we do NOT reject here merely because the executor reported
        # payload_executed=False.
        #
        # The final verification_evidence_gate later requires:
        #   - direct_attack_match
        #   - introduced_evidence
        #   - no baseline match
        #   - no payload reflection
        #   - response change
        #   - sufficient detector confidence
        #
        # Those conditions collectively establish the security effect.
        #
        # Keep the executor's original value untouched for audit purposes.
        executor_payload_executed = payload_executed

        if attack_response is None:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: real attack response is unavailable.",
            )

        if attack_status <= 0:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: attack response has no valid HTTP status.",
            )

        if not attack_body:
            return self._finish(
                context,
                False,
                0.0,
                "Verification rejected: attack response body is empty.",
            )

        # =========================================================================
        # DETECTOR EVIDENCE GATES
        # =========================================================================
        #
        # AttackResult.success is detector-level status only.
        # It is NOT the final vulnerability decision.
        #
        # Verification independently examines:
        #
        #   real HTTP execution
        #   actual attack response
        #   vulnerability-specific evidence
        #   baseline attribution
        #   payload reflection
        #   response corroboration
        #
        # Therefore detector_success=False must NOT automatically reject
        # an AttackResult when concrete detector evidence is present.
        # =========================================================================

        if not evidence and not indicator:
            return self._finish(
                context,
                False,
                0.0,
                (
                    "Verification rejected: detector supplied neither "
                    "evidence nor an indicator."
                ),
            )

        if detector_confidence < self.MEDIUM_DETECTOR_CONFIDENCE:
            return self._finish(
                context,
                False,
                0.0,
                (
                    "Verification rejected: detector confidence "
                    f"{detector_confidence:.1f} is below "
                    f"{self.MEDIUM_DETECTOR_CONFIDENCE:.1f}."
                ),
            )

        # =========================================================================
        # BASELINE
        # =========================================================================

        baseline_exchange = getattr(
            context,
            "baseline",
            None,
        )

        baseline_response = None

        if baseline_exchange is not None:

            baseline_response = getattr(
                baseline_exchange,
                "response",
                None,
            )

            if baseline_response is None:
                baseline_response = baseline_exchange

        baseline_status = self._status(
            baseline_response
        )

        baseline_body = self._body(
            baseline_response
        )

        # =========================================================================
        # DETECTOR MARKER ANALYSIS
        # =========================================================================

        markers = list(
            dict.fromkeys(
                marker
                for marker in (
                    evidence,
                    indicator,
                )
                if marker
            )
        )

        marker_details = []

        direct_attack_match = False
        baseline_match = False
        introduced_evidence = False

        for marker in markers:

            attack_contains = self._contains(
                attack_body,
                marker,
            )

            baseline_contains = self._contains(
                baseline_body,
                marker,
            )

            introduced = bool(
                attack_contains
                and not baseline_contains
            )

            direct_attack_match = bool(
                direct_attack_match
                or attack_contains
            )

            baseline_match = bool(
                baseline_match
                or baseline_contains
            )

            introduced_evidence = bool(
                introduced_evidence
                or introduced
            )

            marker_details.append(
                {
                    "marker": marker,
                    "attack_contains": attack_contains,
                    "baseline_contains": baseline_contains,
                    "introduced_by_attack": introduced,
                }
            )

        # =========================================================================
        # PAYLOAD REFLECTION CHECK
        # =========================================================================

        payload_reflected = bool(
            payload
            and self._contains(
                attack_body,
                payload,
            )
        )

        # =========================================================================
        # RESPONSE CORROBORATION
        # =========================================================================

        response_changed = self._response_changed(
            baseline_exchange,
            attack_response,
        )

        # =========================================================================
        # REGISTRY
        # =========================================================================
        #
        # Registry validators are supporting evidence only.
        # They NEVER confirm a vulnerability by themselves.
        # =========================================================================

        registry_success, registry_validator = (
            self._registry_success(
                context
            )
        )

        # =========================================================================
        # FINAL SECURITY DECISION
        # =========================================================================

        verified = False
        confidence = 0.0

        reason = (
            "Required vulnerability evidence gates were not satisfied."
        )

        concrete_attack_evidence = bool(
            direct_attack_match
            and not payload_reflected
        )

        # =========================================================================
        # EVIDENCE STRENGTH
        # =========================================================================
        #
        # AttackResult.success is NOT used as a confirmation gate.
        #
        # The SQLi detector intentionally returns success=False because it reports
        # candidate evidence rather than claiming final vulnerability confirmation.
        #
        # Verification therefore evaluates the actual evidence obtained from the
        # real attack response and its attribution to the attack.
        #
        # A detector confidence value is supporting evidence only.
        # The final decision is made below from the complete evidence chain.
        # =========================================================================
        
        strong_detector = bool(
            detector_confidence
            >= self.STRONG_DETECTOR_CONFIDENCE
        )
        
        medium_detector = bool(
            detector_confidence
            >= self.MEDIUM_DETECTOR_CONFIDENCE
        )

        # ---------------------------------------------------------------------
        # NEVER allow registry_success to confirm.
        # ---------------------------------------------------------------------

        # Registry results are supporting evidence only.
        # They MUST NEVER independently confirm a vulnerability.
        #
        # Confirmation requires the actual attack response to contain
        # vulnerability-specific evidence produced by the attack.
        #
        # Therefore registry_success is intentionally NOT a confirmation path.

        # ---------------------------------------------------------------------
        # REGISTRY IS SUPPORTING EVIDENCE ONLY
        # ---------------------------------------------------------------------
        #
        # Registry success is NEVER required for confirmation.
        # Registry success is NEVER sufficient for confirmation.
        #
        # The final security decision is based on the real attack evidence
        # collected above.
        # ---------------------------------------------------------------------
        
        if registry_success:
            print(
                "[VERIFICATION] Registry validator passed, "
                "but registry success alone cannot confirm.",
                flush=True,
            )
        
        # =========================================================================
        # FINAL SECURITY DECISION
        # =========================================================================
        #
        # Every candidate is evaluated independently.
        #
        # There is NO fixed confirmed count.
        #
        # A candidate is confirmed only when the actual attack proves:
        #
        #   real execution
        #       AND
        #   request sent
        #       AND
        #   response received
        #       AND
        #   payload transmitted through the real HTTP request
        #       AND
        #   vulnerability-specific evidence
        #       AND
        #   evidence introduced by attack
        #       AND
        #   evidence absent from baseline
        #       AND
        #   evidence is not merely reflection
        #       AND
        #   material response change
        #       AND
        #   sufficient detector confidence
        #
        # Registry success is deliberately NOT part of this gate.
        # =========================================================================
        print(
            "[VERIFICATION-GATE-INPUT] "
            f"real_http_execution={real_http_execution} "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"payload_executed={payload_executed} "
            f"direct_attack_match={direct_attack_match} "
            f"introduced_evidence={introduced_evidence} "
            f"baseline_match={baseline_match} "
            f"payload_reflected={payload_reflected} "
            f"response_changed={response_changed} "
            f"detector_confidence={detector_confidence!r} "
            f"medium_threshold={self.MEDIUM_DETECTOR_CONFIDENCE!r} "
            f"confidence_check="
            f"{detector_confidence >= self.MEDIUM_DETECTOR_CONFIDENCE}",
            flush=True,
        )
        
        # =========================================================================
        # FINAL SECURITY EVIDENCE GATE
        # =========================================================================
        #
        # REAL HTTP EXECUTION proves that the attack actually reached the target.
        #
        # Vulnerability confirmation is then based on vulnerability-specific
        # evidence produced by the detector and verified against the baseline.
        #
        # IMPORTANT:
        # `payload_executed` is NOT used as a universal gate because the generic
        # AttackExecutor cannot determine application-level interpretation of every
        # vulnerability class.
        #
        # The detector-specific evidence is the application-level proof.
        # =========================================================================
        
        # =========================================================================
        # FINAL SECURITY DECISION
        # =========================================================================
        #
        # Generic HTTP execution is mandatory.
        #
        # Generic "payload_executed" is NOT a universal confirmation gate.
        # Different vulnerability classes prove application-level effects in
        # different ways:
        #
        #   SQLi  -> SQL-specific response evidence
        #   LFI   -> controlled file-content evidence
        #   XSS   -> appropriate reflection/DOM execution evidence
        #   etc.
        #
        # The attack-specific validator/detector is therefore responsible for
        # establishing vulnerability-specific application evidence.
        #
        # Confirmation remains evidence-based and candidate-independent.
        # There is NO fixed number of confirmations.
        # =========================================================================
        
        verification_evidence_gate = bool(
            real_http_execution
            and request_sent
            and response_received
            and direct_attack_match
            and introduced_evidence
            and not baseline_match
            and not payload_reflected
            and response_changed
            and (
                detector_confidence
                >= self.MEDIUM_DETECTOR_CONFIDENCE
            )
        )
        
        print(
            "[VERIFICATION-DECISION] "
            f"confirmed={verification_evidence_gate} "
            f"real_http_execution={real_http_execution} "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"payload_executed={payload_executed} "
            f"direct_attack_match={direct_attack_match} "
            f"introduced_evidence={introduced_evidence} "
            f"baseline_match={baseline_match} "
            f"payload_reflected={payload_reflected} "
            f"response_changed={response_changed} "
            f"detector_confidence={detector_confidence:.2f}",
            flush=True,
        )
           
        
        if verification_evidence_gate:
        
            verified = True
        
            confidence = detector_confidence
        
            reason = (
                "Verification passed: real HTTP execution, vulnerability-specific "
                "attack-response evidence, attack attribution, baseline exclusion, "
                "non-reflection, response corroboration, and sufficient detector "
                "confidence were established."
            )
        
        elif baseline_match:
        
            reason = (
                "Verification rejected: detector evidence already existed "
                "in the baseline response."
            )
        
        elif payload_reflected:
        
            reason = (
                "Verification rejected: detector evidence was only reflected "
                "by the payload."
            )
        
        elif not direct_attack_match:
        
            reason = (
                "Verification rejected: vulnerability-specific evidence "
                "was not found in the actual attack response."
            )
        
        elif not introduced_evidence:
        
            reason = (
                "Verification rejected: vulnerability-specific evidence "
                "was not introduced by the attack."
            )
        
        elif not response_changed:
        
            reason = (
                "Verification rejected: the attack did not produce the "
                "required material response change."
            )
        
        elif detector_confidence < self.MEDIUM_DETECTOR_CONFIDENCE:
        
            reason = (
                f"Verification rejected: evidence confidence "
                f"{detector_confidence:.1f} is below the required "
                f"threshold {self.MEDIUM_DETECTOR_CONFIDENCE:.1f}."
            )
        
        else:
        
            reason = (
                "Verification rejected: required vulnerability evidence "
                "gates were not satisfied."
            )
        # =========================================================================
        # FULL TRACE
        # =========================================================================

        print(
            "[VERIFICATION-TRACE] "
            f"attack={attack_name or 'unknown'} "
            f"attack_status={attack_status} "
            f"baseline_status={baseline_status} "
            f"real_http_execution={real_http_execution} "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"payload_executed={payload_executed} "
            f"detector_success={detector_success} "
            f"detector_confidence={detector_confidence:.1f} "
            f"strong_detector={strong_detector} "
            f"medium_detector={medium_detector} "
            f"direct_attack_match={direct_attack_match} "
            f"baseline_match={baseline_match} "
            f"introduced_evidence={introduced_evidence} "
            f"payload_reflected={payload_reflected} "
            f"response_changed={response_changed} "
            f"registry_success={registry_success} "
            f"registry_validator={registry_validator or 'NONE'} "
            f"verified={verified} "
            f"final_confidence={confidence:.1f} "
            f"reason={reason}",
            flush=True,
        )

        # =========================================================================
        # METADATA
        # =========================================================================

        verification_metadata = {
            "verified": bool(verified),
            "verified_indicators": 1 if verified else 0,

            "real_http_execution": real_http_execution,
            "request_sent": request_sent,
            "response_received": response_received,
            "payload_executed": payload_executed,

            "attack_status": attack_status,
            "baseline_status": baseline_status,

            "detector_success": detector_success,
            "detector_confidence": detector_confidence,

            "strong_detector": strong_detector,
            "medium_detector": medium_detector,

            "direct_attack_match": direct_attack_match,
            "baseline_match": baseline_match,
            "introduced_evidence": introduced_evidence,

            "payload_reflected": payload_reflected,
            "response_changed": response_changed,

            "registry_success": registry_success,
            "registry_validator": registry_validator,

            "markers": marker_details,
            "reason": reason,
        }

        context.metadata[
            "verification"
        ] = verification_metadata

        return self._finish(
            context,
            verified,
            confidence,
            (
                "Verification passed: "
                f"{reason}"
                if verified
                else
                "Verification failed: "
                f"{reason}"
            ),
        )

    # =========================================================================
    # ATTACK RESPONSE
    # =========================================================================

    @staticmethod
    def _get_attack_response(
        context,
        attack_result,
    ):

        cache = (
            getattr(
                context,
                "cache",
                {},
            )
            or {}
        )

        response = cache.get(
            "attack_response"
        )

        if response is not None:
            return response

        metadata = (
            getattr(
                attack_result,
                "metadata",
                {},
            )
            or {}
        )

        response = metadata.get(
            "response"
        )

        if response is not None:
            return response

        return getattr(
            attack_result,
            "response",
            None,
        )

    # =========================================================================
    # HTTP STATUS
    # =========================================================================

    @staticmethod
    def _status(
        response,
    ) -> int:

        if response is None:
            return 0

        value = getattr(
            response,
            "status",
            None,
        )

        if value is None:
            value = getattr(
                response,
                "status_code",
                0,
            )

        try:
            return int(
                value or 0
            )
        except Exception:
            return 0

    # =========================================================================
    # RESPONSE BODY
    # =========================================================================

    @staticmethod
    def _body(
        response,
    ) -> str:

        if response is None:
            return ""

        body = getattr(
            response,
            "body",
            None,
        )

        if body is None:
            body = getattr(
                response,
                "text",
                "",
            )

        return str(
            body or ""
        )

    # =========================================================================
    # TEXT MATCH
    # =========================================================================

    @classmethod
    def _contains(
        cls,
        body,
        marker,
    ) -> bool:

        marker = cls._text(
            marker
        )

        if not marker:
            return False

        return (
            marker.lower()
            in str(
                body or ""
            ).lower()
        )

    # =========================================================================
    # RESPONSE DIFFERENCE
    # =========================================================================

    @classmethod
    def _response_changed(
        cls,
        baseline_exchange,
        attack_response,
    ) -> bool:

        if baseline_exchange is None:
            return False

        baseline_response = getattr(
            baseline_exchange,
            "response",
            None,
        )

        if baseline_response is None:
            return False

        if attack_response is None:
            return False

        baseline_status = cls._status(
            baseline_response
        )

        attack_status = cls._status(
            attack_response
        )

        if baseline_status != attack_status:
            return True

        baseline_body = cls._body(
            baseline_response
        )

        attack_body = cls._body(
            attack_response
        )

        if baseline_body == attack_body:
            return False

        # Exact body difference is already meaningful.
        #
        # We deliberately do not treat a tiny arbitrary change as proof.
        # A 10% length change alone is not sufficient security evidence.
        #
        # Require a substantial structural/content difference.
        baseline_len = len(
            baseline_body
        )

        attack_len = len(
            attack_body
        )

        if baseline_len == 0:
            return attack_len > 0

        length_ratio = (
            abs(
                attack_len
                - baseline_len
            )
            / baseline_len
        )

        if length_ratio >= 0.10:
            return True

        # Small responses can change significantly in content while keeping
        # nearly identical length. Compare normalized bodies.
        normalized_baseline = (
            " ".join(
                baseline_body.split()
            )
        )

        normalized_attack = (
            " ".join(
                attack_body.split()
            )
        )

        return (
            normalized_baseline
            != normalized_attack
        )

    # =========================================================================
    # REGISTRY
    # =========================================================================

    @classmethod
    def _registry_success(
        cls,
        context: ValidationContext,
    ) -> tuple[bool, str]:

        results = (
            getattr(
                context,
                "results",
                {},
            )
            or {}
        )

        for name, result in results.items():

            validator_name = cls._text(
                getattr(
                    result,
                    "validator",
                    name,
                )
            )

            if (
                validator_name.lower()
                in {
                    item.lower()
                    for item in cls.GENERIC_VALIDATORS
                }
            ):
                continue

            if not bool(
                getattr(
                    result,
                    "success",
                    False,
                )
            ):
                continue

            result_indicators = getattr(
                result,
                "indicators",
                None,
            )

            result_metadata = (
                getattr(
                    result,
                    "metadata",
                    {},
                )
                or {}
            )

            has_evidence = bool(
                result_indicators
            ) or bool(
                result_metadata.get(
                    "verified"
                )
            ) or bool(
                result_metadata.get(
                    "evidence"
                )
            )

            if not has_evidence:
                print(
                    "[VERIFICATION-REGISTRY] "
                    f"ignored validator={validator_name!r} "
                    "because success was reported without evidence.",
                    flush=True,
                )
                continue

            print(
                "[VERIFICATION-REGISTRY] "
                f"supporting validator={validator_name!r} "
                "reported evidence; it cannot independently confirm.",
                flush=True,
            )

            return True, validator_name

        return False, ""

    # =========================================================================
    # TEXT
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

    # =========================================================================
    # CONFIDENCE
    # =========================================================================

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

        if (
            0.0 < value <= 1.0
        ):
            value *= 100.0

        return max(
            0.0,
            min(
                100.0,
                value,
            ),
        )

    # =========================================================================
    # RESULT
    # =========================================================================

    @staticmethod
    def _finish(
        context,
        success,
        confidence,
        summary,
    ) -> ValidationResult:

        verified_count = (
            1
            if success
            else 0
        )

        context.metadata[
            "verified_indicators"
        ] = verified_count

        context.metadata[
            "verification_reason"
        ] = summary

        result = ValidationResult(
            validator="Verification",
            success=bool(
                success
            ),
            confidence=float(
                confidence
            ),
            summary=summary,
            indicators=list(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
            metadata={
                "verified": bool(
                    success
                ),
                "verified_indicators": verified_count,
                "reason": summary,
            },
        )

        context.add_result(
            result
        )

        return result
