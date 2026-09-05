"""
===============================================================================
AVAF Pro - Finding Builder
===============================================================================

Converts VERIFIED validation evidence into final Finding objects.

This module does not discover vulnerabilities.
It does not manufacture confirmation.
It only converts evidence that has already passed Phase-2 verification.
===============================================================================
"""

from __future__ import annotations

from ..models.finding import Finding


class FindingBuilder:

    CWE = {
        "SQLI": "CWE-89",
        "XSS": "CWE-79",
        "LFI": "CWE-98",
        "SSRF": "CWE-918",
        "XXE": "CWE-611",
        "RCE": "CWE-78",
    }

    OWASP = {
        "SQLI": "A03:2021 Injection",
        "XSS": "A03:2021 Injection",
        "LFI": "A05:2021 Security Misconfiguration",
        "SSRF": "A10:2021 SSRF",
        "XXE": "A05:2021 Security Misconfiguration",
        "RCE": "A03:2021 Injection",
    }

    def __init__(self, scorer):
        self.scorer = scorer

    def build(self, evidences):

        findings = []

        for evidence in evidences:

            # --------------------------------------------------------------
            # IMPORTANT:
            # FindingBuilder accepts evidence only after the validation
            # pipeline has decided that it is verified.
            # --------------------------------------------------------------

            verified = bool(
                getattr(
                    evidence,
                    "verified",
                    False,
                )
            )

            if not verified:
                continue

            score = self.scorer.calculate(
                evidence
            )

            vulnerability = str(
                getattr(
                    evidence,
                    "vulnerability",
                    "",
                )
                or getattr(
                    evidence,
                    "attack",
                    "",
                )
                or "Unknown"
            )

            url = str(
                getattr(
                    evidence,
                    "url",
                    "",
                )
                or ""
            )

            parameter = str(
                getattr(
                    evidence,
                    "parameter",
                    "",
                )
                or ""
            )

            method = str(
                getattr(
                    evidence,
                    "method",
                    "GET",
                )
                or "GET"
            ).upper()

            payload = getattr(
                evidence,
                "payload",
                None,
            )

            evidence_text = str(
                getattr(
                    evidence,
                    "evidence",
                    "",
                )
                or getattr(
                    evidence,
                    "indicator",
                    "",
                )
                or ""
            )

            findings.append(
                Finding(
                    attack=vulnerability,
                    title=(
                        f"Confirmed {vulnerability} vulnerability"
                    ),
                    severity=score["severity"],
                    confidence=score["confidence"],
                    url=url,
                    method=method,
                    parameter=parameter,
                    payload=payload,
                    evidence=evidence_text,
                    request=getattr(
                        evidence,
                        "request",
                        None,
                    ),
                    response=getattr(
                        evidence,
                        "attack_response",
                        None,
                    ),
                    cwe=self.CWE.get(
                        vulnerability,
                        "Unknown",
                    ),
                    owasp=self.OWASP.get(
                        vulnerability,
                        "Unknown",
                    ),
                    metadata={
                        "verified": True,
                    },
                )
            )

        return findings