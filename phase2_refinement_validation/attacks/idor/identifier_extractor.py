"""
===============================================================================
IDOR Identifier Extractor

Discovers possible object identifiers from an AttackVector.

Sources
-------
- URL path
- Query parameters
- Form parameters
- JSON body
===============================================================================
"""

from __future__ import annotations

import re

from .models import IdentifierCandidate


COMMON_IDENTIFIER_NAMES = {

    "id",
    "user_id",
    "userid",
    "uid",
    "account",
    "account_id",
    "order",
    "order_id",
    "invoice_id",
    "customer_id",
    "profile_id",
    "document_id",
    "file_id",
    "post_id",
    "comment_id",
    "product_id",
}


class IdentifierExtractor:

    ID_PATTERN = re.compile(r"\b\d+\b")

    def extract(self, vector):

        candidates = []

        candidates.extend(
            self._extract_query_parameters(vector)
        )

        candidates.extend(
            self._extract_form_parameters(vector)
        )

        candidates.extend(
            self._extract_json_parameters(vector)
        )

        candidates.extend(
            self._extract_url_identifiers(vector)
        )

        return candidates

    def _extract_query_parameters(self, vector):

        candidates = []

        query = getattr(vector, "params", {}) or {}

        for name, value in query.items():

            if self._looks_like_identifier(name, value):

                candidates.append(
                    IdentifierCandidate(
                        source="query",
                        name=name,
                        original_value=str(value),
                        replacement_value=self._next_value(value),
                    )
                )

        return candidates

    def _extract_form_parameters(self, vector):

        candidates = []

        form = getattr(vector, "data", {}) or {}

        for name, value in form.items():

            if self._looks_like_identifier(name, value):

                candidates.append(
                    IdentifierCandidate(
                        source="form",
                        name=name,
                        original_value=str(value),
                        replacement_value=self._next_value(value),
                    )
                )

        return candidates

    def _extract_json_parameters(self, vector):

        candidates = []

        body = getattr(vector, "json", {}) or {}

        if not isinstance(body, dict):
            return candidates

        for name, value in body.items():

            if self._looks_like_identifier(name, value):

                candidates.append(
                    IdentifierCandidate(
                        source="json",
                        name=name,
                        original_value=str(value),
                        replacement_value=self._next_value(value),
                    )
                )
        
        return candidates
        
    def _extract_url_identifiers(self, vector):
    
        candidates = []
    
        from urllib.parse import urlparse
    
        url = str(getattr(vector, "url", "") or "")
        if not url:
            return candidates
    
        parsed = urlparse(url)
    
        # ONLY inspect URL PATH.
        # Never inspect hostname, port, query string,
        # fragment, socket.io parameters, etc.
        path = parsed.path or ""
    
        for index, segment in enumerate(path.split("/")):
    
            segment = segment.strip()
    
            if not segment:
                continue
    
            # Only a complete numeric path segment is an ID.
            if not segment.isdigit():
                continue
    
            candidates.append(
                IdentifierCandidate(
                    source="url",
                    name=f"path_id_{index}",
                    original_value=segment,
                    replacement_value=self._next_value(segment),
                )
            )
    
        return candidates
    
    def _looks_like_identifier(self, name, value):

        if str(name).lower() in COMMON_IDENTIFIER_NAMES:
            return True

        return str(value).isdigit()

    def _next_value(self, value):

        try:
            return str(int(value) + 1)
        except Exception:
            return str(value)