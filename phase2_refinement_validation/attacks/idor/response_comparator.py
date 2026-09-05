"""
===============================================================================
IDOR Response Comparator

Compares the original and modified responses after an identifier change.

Responsibilities
----------------
✔ Compare status codes
✔ Compare response sizes
✔ Compare response similarity
✔ Record meaningful differences

This module DOES NOT decide whether an IDOR exists.
===============================================================================
"""

from __future__ import annotations

from difflib import SequenceMatcher

from .models import ResponseComparison


class ResponseComparator:

    def compare(
        self,
        original_response,
        modified_response,
    ) -> ResponseComparison:

        original_body = self._body(original_response)
        modified_body = self._body(modified_response)

        similarity = SequenceMatcher(
            None,
            original_body,
            modified_body,
        ).ratio()

        differences = []

        if getattr(original_response, "status_code", None) != getattr(modified_response, "status_code", None):
            differences.append("status_code")

        if len(original_body) != len(modified_body):
            differences.append("content_length")

        if similarity < 0.95:
            differences.append("response_content")

        return ResponseComparison(
            original_status=getattr(original_response, "status_code", 0),
            modified_status=getattr(modified_response, "status_code", 0),
            similarity=similarity,
            original_length=len(original_body),
            modified_length=len(modified_body),
            significant_change=similarity < 0.95,
            differences=differences,
        )

    @staticmethod
    def _body(response) -> str:

        if response is None:
            return ""

        if hasattr(response, "body"):
            return response.body or ""

        if hasattr(response, "text"):
            return response.text or ""
        
        if isinstance(response, str):
            return response

        return str(response)