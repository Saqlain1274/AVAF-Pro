
"""
AVAF Pro - SQL Injection Detector

The detector is an evidence extractor.

IMPORTANT:
    This module NEVER confirms SQL Injection.

A database error is only a candidate signal.
Final confirmation belongs to the validation pipeline.

The detector is responsible for:

    1. Inspecting the REAL HTTP response.
    2. Finding SQL/database-specific error evidence.
    3. Comparing that evidence with the baseline response.
    4. Returning an AttackResult containing candidate evidence.

It must NOT decide that SQL Injection is confirmed.
"""

from __future__ import annotations

from typing import Any, Optional

from phase2_refinement_validation.attacks.sqli.indicators import (
    DATABASE_ERRORS,
)
from phase2_refinement_validation.models.attack_result import (
    AttackResult,
)


class SQLiDetector:
    """
    Extract SQLi-related evidence from an HTTP response.

    Detection != confirmation.

    A returned AttackResult means:

        "Interesting SQL-specific evidence was observed."

    It does NOT mean:

        "SQL Injection is confirmed."
    """

    def detect(
        self,
        vector,
        payload: str,
        response: Any,
        baseline_response: Optional[Any] = None,
    ) -> Optional[AttackResult]:
        """
        Detect SQL/database error evidence in a real HTTP response.
    
        This method is a DETECTION stage only.
    
        It does not confirm a vulnerability. It returns a candidate
        AttackResult when SQL-specific evidence is found in the attack
        response and that same evidence was not already present in the
        baseline response.
    
        Final vulnerability confirmation must be performed by the
        downstream validation/verification pipeline.
        """
    
        # ==============================================================
        # 1. Extract attack response body
        # ==============================================================
    
        body = self._body(response)
    
        if not body:
            return None
    
        body_lower = body.lower()
    
        # ==============================================================
        # 2. Detect SQL/database-specific error evidence
        # ==============================================================
    
        matched_dbms: Optional[str] = None
        matched_indicator: Optional[str] = None
    
        for dbms, indicators in DATABASE_ERRORS.items():
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    matched_dbms = dbms
                    matched_indicator = indicator
                    break
    
            if matched_indicator is not None:
                break
    
        # No SQL-specific evidence was found.
        if matched_indicator is None:
            return None
    
        # ==============================================================
        # 3. Compare attack response with baseline
        # ==============================================================
    
        baseline_body = self._body(baseline_response)
    
        baseline_contains_same_error = bool(
            baseline_body
            and matched_indicator.lower() in baseline_body.lower()
        )
    
        # If the same SQL error already existed before the attack,
        # the error cannot safely be attributed to this payload.
        if baseline_contains_same_error:
            return None
    
        # ==============================================================
        # 4. Determine whether the response changed
        # ==============================================================
    
        status = self._status(response)
        baseline_status = self._status(baseline_response)
    
        baseline_changed = False
    
        if baseline_response is not None:
            baseline_changed = (
                status != baseline_status
                or len(body) != len(baseline_body)
            )
    
        # ==============================================================
        # 5. Build detector candidate
        # ==============================================================
    
        return AttackResult(
            attack="sqli",
            vector=vector,
    
            # This is intentionally FALSE.
            #
            # The detector has discovered evidence, but it has NOT
            # independently confirmed a vulnerability.
            #
            # The verification/validation layer remains responsible
            # for final confirmation.
            success=False,
    
            payload=payload,
    
            # Actual SQL/database evidence found in the response.
            evidence=matched_indicator,
    
            # Normalized indicator consumed by downstream validation.
            indicator="database_error",
    
            # Strong candidate evidence, but not final confirmation.
            confidence=0.70,
    
            metadata={
                # ------------------------------------------------------
                # Detection identity
                # ------------------------------------------------------
                "dbms": matched_dbms,
                "detector_type": "database_error",
                "detector_success": True,
                "detector_confirmed": False,
    
                # ------------------------------------------------------
                # Evidence provenance
                # ------------------------------------------------------
                "evidence_source": "attack_response",
                "matched_indicator": matched_indicator,
    
                # ------------------------------------------------------
                # Baseline information
                # ------------------------------------------------------
                "baseline_available": (
                    baseline_response is not None
                ),
                "baseline_changed": baseline_changed,
                "baseline_contains_same_error": (
                    baseline_contains_same_error
                ),
    
                # ------------------------------------------------------
                # Verification contract
                # ------------------------------------------------------
                #
                # These fields explicitly tell the downstream
                # verification stage that this is a detector candidate,
                # not a confirmed vulnerability.
                #
                "evidence_detected": True,
                "confirmation_required": True,
                "confirmation_authority": "validation_pipeline",
            },
        )
    


    # ==================================================================
    # RESPONSE BODY
    # ==================================================================

    @staticmethod
    def _body(response: Any) -> str:
        """
        Extract a response body from supported HTTP response objects.
        """

        if response is None:
            return ""

        if hasattr(response, "body"):
            value = response.body

        elif hasattr(response, "text"):
            value = response.text

        elif isinstance(response, str):
            value = response

        else:
            value = ""

        if isinstance(value, bytes):
            return value.decode(
                "utf-8",
                errors="replace",
            )

        return str(value or "")

    # ==================================================================
    # HTTP STATUS
    # ==================================================================

    @staticmethod
    def _status(response: Any) -> Optional[int]:
        """
        Extract HTTP status code from a supported response object.
        """

        if response is None:
            return None

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
            return (
                int(value)
                if value is not None
                else None
            )

        except (TypeError, ValueError):
            return None
