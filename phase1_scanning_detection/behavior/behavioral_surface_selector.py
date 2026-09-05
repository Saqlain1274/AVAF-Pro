"""
AVAF PRO
Phase-1 Behavioral Surface Selector

Only ranks surfaces that were already observed in the rendered browser DOM.

This component never:
    - generates URLs
    - generates routes
    - generates parameters
    - scans wordlists
    - generates endpoints
    - creates attack payloads
"""

from __future__ import annotations

from typing import Any


class BehavioralSurfaceSelector:
    """Prioritize genuinely browser-observed interactive surfaces."""

    _LOW_VALUE_ROLES = {
        "presentation",
        "img",
        "none",
    }

    _SAFE_INTERACTIVE_TAGS = {
        "a",
        "area",
        "button",
        "summary",
    }

    def score(self, surface: dict[str, Any]) -> int:
        if not isinstance(surface, dict):
            return 0

        identity = surface.get("identity")
        if not isinstance(identity, dict):
            identity = {}

        tag = str(identity.get("tag", "")).strip().lower()
        role = str(identity.get("role", "")).strip().lower()
        element_type = str(identity.get("type", "")).strip().lower()

        if role in self._LOW_VALUE_ROLES:
            return 0

        if element_type in {"submit", "reset", "image"}:
            return 0

        score = 10

        if tag in self._SAFE_INTERACTIVE_TAGS:
            score += 20

        if role in {
            "button",
            "link",
            "tab",
            "menuitem",
            "option",
            "switch",
            "checkbox",
            "radio",
        }:
            score += 25

        if identity.get("href"):
            score += 10

        if identity.get("aria-controls"):
            score += 8

        if identity.get("aria-expanded") is not None:
            score += 8

        if identity.get("aria-haspopup"):
            score += 8

        if identity.get("title"):
            score += 3

        if identity.get("text"):
            score += 3

        if identity.get("visible") is False:
            return 0

        if identity.get("enabled") is False:
            return 0

        return min(100, max(1, score))


SURFACE_SELECTOR = BehavioralSurfaceSelector()
