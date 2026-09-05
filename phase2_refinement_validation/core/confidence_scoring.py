"""
===============================================================================
AVAF Pro

Confidence Scoring Engine

Purpose
-------
Transforms validated evidence into a normalized security score.

Consumes:
    Evidence

Produces:
    Severity
    Confidence
    Proof count

Used By
-------
✔ Finding Builder
✔ GUI
✔ Phase-3 Reporting
✔ Dashboard

Important
---------
AttackResult.attack values are normalized before looking them up in BASE.

For example:
    "ssrf"             -> "SSRF"
    "idor"             -> "IDOR"
    "ldap_injection"   -> "LDAP_INJECTION"

This prevents valid attack results from falling through to the
default confidence score simply because their names use lowercase.
===============================================================================
"""

from __future__ import annotations


class ConfidenceScoring:

    # ==========================================================
    # BASE SCORES
    # ==========================================================

    BASE = {

        "SQLI": 82,

        "XSS": 65,

        "LFI": 78,

        "RCE": 96,

        "SSRF": 80,

        "XXE": 90,

        "IDOR": 72,

        "SSTI": 92,

        "OPEN_REDIRECT": 42,

        "COMMAND_INJECTION": 98,

        "LDAP_INJECTION": 80,

        "NOSQL_INJECTION": 80,

        "RFI": 80,

        "FILE_UPLOAD": 80,
    }

    # ==========================================================
    # INDICATOR WEIGHTS
    # ==========================================================

    INDICATORS = {

        "SQL_ERROR": 8,

        "TIME_DELAY": 10,

        "BODY_CHANGED": 5,

        "STATUS_CHANGED": 5,

        "CONTENT_CHANGED": 5,

        "BOOLEAN_TRUE": 8,

        "BOOLEAN_FALSE": 8,

        "DOM_CHANGED": 6,

        "OOB_CALLBACK": 15,
    }

    # ==========================================================
    # MAIN
    # ==========================================================

    def calculate(
        self,
        evidence,
    ):
        """
        Calculate confidence from actual validation evidence.

        Important
        ---------
        Vulnerability type alone NEVER creates confirmation confidence.

        The score starts from the strongest confidence already produced
        by the attack/verification pipeline. Additional points are added
        only for concrete, explicitly recorded corroborating indicators.

        This keeps confirmation dynamic:
            real evidence -> higher confidence
            weak/no evidence -> lower confidence

        A SQLi finding is NOT automatically assigned 82 simply because
        its vulnerability name is "SQLI".
        """

        # ------------------------------------------------------
        # 1. Normalize vulnerability name
        # ------------------------------------------------------

        vulnerability = self._normalize_name(
            getattr(
                evidence,
                "vulnerability",
                "",
            )
        )

        # ------------------------------------------------------
        # 2. Obtain confidence already established by the
        #    attack / verification pipeline.
        #
        #    DO NOT use BASE[vulnerability] as confirmation
        #    confidence.
        # ------------------------------------------------------

        score = 0.0

        evidence_confidence = getattr(
            evidence,
            "confidence",
            0.0,
        )

        try:
            score = float(
                evidence_confidence or 0.0
            )
        except (TypeError, ValueError):
            score = 0.0

        # Support accidental 0..1 confidence values.
        if 0.0 < score <= 1.0:
            score *= 100.0

        # ------------------------------------------------------
        # 3. Read attack results
        # ------------------------------------------------------

        attacks = getattr(
            evidence,
            "attacks",
            [],
        ) or []

        proofs = 0
        seen_indicators = set()

        # ------------------------------------------------------
        # 4. Add ONLY real corroborating indicators
        # ------------------------------------------------------

        for attack in attacks:

            # --------------------------------------------------
            # Singular indicator
            # --------------------------------------------------

            indicator = self._normalize_name(
                getattr(
                    attack,
                    "indicator",
                    "",
                )
            )

            if indicator:

                # Prevent the same indicator from being counted
                # repeatedly for the same evidence object.
                if indicator not in seen_indicators:

                    weight = float(
                        self.INDICATORS.get(
                            indicator,
                            0,
                        )
                    )

                    if weight > 0.0:

                        score += weight
                        proofs += 1
                        seen_indicators.add(
                            indicator
                        )

            # --------------------------------------------------
            # Multiple indicators
            # --------------------------------------------------

            indicators = getattr(
                attack,
                "indicators",
                None,
            )

            if indicators:

                for item in indicators:

                    normalized = self._normalize_name(
                        item
                    )

                    if not normalized:
                        continue

                    if normalized in seen_indicators:
                        continue

                    weight = float(
                        self.INDICATORS.get(
                            normalized,
                            0,
                        )
                    )

                    if weight <= 0.0:
                        continue

                    score += weight
                    proofs += 1
                    seen_indicators.add(
                        normalized
                    )

        # ------------------------------------------------------
        # 5. Never allow scoring to manufacture confirmation.
        #
        #    Evidence confidence + corroboration can increase
        #    confidence, but vulnerability name alone cannot.
        # ------------------------------------------------------

        score = max(
            0.0,
            min(
                100.0,
                score,
            ),
        )

        # ------------------------------------------------------
        # 6. Return scoring result
        # ------------------------------------------------------

        return {
            "confidence": score,
            "severity": self._severity(score),
            "proofs": proofs,
        }

    # ==========================================================
    # NAME NORMALIZATION
    # ==========================================================

    @staticmethod
    def _normalize_name(
        value,
    ):
        """
        Convert attack/vulnerability/indicator names into the
        canonical format used by the scoring tables.

        Examples
        --------
        ssrf
            -> SSRF

        ldap_injection
            -> LDAP_INJECTION

        SQL Error
            -> SQL_ERROR
        """

        return str(
            value
            or ""
        ).strip().upper().replace(
            " ",
            "_",
        ).replace(
            "-",
            "_",
        )

    # ==========================================================
    # SEVERITY
    # ==========================================================

    @staticmethod
    def _severity(
        score,
    ):

        if score >= 90:
            return "Critical"

        if score >= 75:
            return "High"

        if score >= 60:
            return "Medium"

        if score >= 40:
            return "Low"

        return "Info"