"""
===============================================================================

AVAF Pro

Response Fingerprinting Engine

Purpose
-------
Generate stable fingerprints from HTTP responses by removing dynamic
elements before comparison.

This algorithm reduces false positives caused by timestamps, session IDs,
CSRF tokens, UUIDs and other volatile values.

===============================================================================
"""

from __future__ import annotations

import hashlib
import re


class ResponseFingerprintAnalyzer:

    def fingerprint(
        self,
        response,
    ) -> dict:
    
        body = getattr(response, "body", "")
    
        if body is None:
            body = ""
    
        normalized = self._normalize(body)
    
        return {
    
            "sha256": hashlib.sha256(
                normalized.encode("utf-8")
            ).hexdigest(),
    
            "length": len(normalized),
    
            "normalized_body": normalized,
    
        }

    def compare(
        self,
        baseline,
        replay,
    ) -> dict:

        base_fp = self.fingerprint(baseline)

        replay_fp = self.fingerprint(replay)

        return {

            "identical":
                base_fp["sha256"] == replay_fp["sha256"],
        
            "changed":
                base_fp["sha256"] != replay_fp["sha256"],
        
            "baseline_hash":
                base_fp["sha256"],
        
            "replay_hash":
                replay_fp["sha256"],
        
            "length_delta":
                abs(
                    base_fp["length"]
                    -
                    replay_fp["length"]
                )
        
        }

    # ==========================================================
    # PRIVATE
    # ==========================================================

    def _normalize(
        self,
        text: str,
    ) -> str:

        text = text.lower()

        patterns = [

            # UUID
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

            # Hex tokens
            r"\b[a-f0-9]{32,128}\b",

            # Numbers
            r"\b\d+\b",

            # Dates
            r"\d{4}-\d{2}-\d{2}",

            # Times
            r"\d{2}:\d{2}:\d{2}",

            # Emails
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",

        ]

        for pattern in patterns:

            text = re.sub(
                pattern,
                "<dynamic>",
                text,
            )

        text = re.sub(
            r"\s+",
            " ",
            text,
        )

        return text.strip()