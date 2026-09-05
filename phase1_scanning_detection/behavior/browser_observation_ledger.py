"""
AVAF PRO
Phase-1 Browser Observation Ledger

Records real browser-observed application states and transitions.

A browser document and an application state are intentionally different:

    document
        = actual browser document/navigation

    state
        = rendered application state observed inside that document

This allows SPAs to be represented correctly without pretending that
every state is another HTML page.

This component never creates crawl targets.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class BrowserObservationLedger:

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}
        self._state_order: list[str] = []
        self._transitions: list[dict[str, Any]] = []

    @staticmethod
    def fingerprint(snapshot: dict[str, Any]) -> str:
        """
        Produce a deterministic fingerprint from browser-observed state.

        This is an observation identity only.
        It is never converted into a URL or crawl target.
        """

        if not isinstance(snapshot, dict):
            return ""

        material = {
            "url": snapshot.get("url", ""),
            "title": snapshot.get("title", ""),
            "body_text": str(
                snapshot.get("body_text", "")
            )[:8000],
            "surfaces": snapshot.get("surfaces", []),
            "controls": snapshot.get("controls", []),
            "forms": snapshot.get("forms", []),
            "dialogs": snapshot.get("dialogs", []),
            "viewport": snapshot.get("viewport", {}),
        }

        try:
            encoded = json.dumps(
                material,
                sort_keys=True,
                ensure_ascii=False,
                default=str,
                separators=(",", ":"),
            )
        except Exception:
            encoded = repr(material)

        return hashlib.sha256(
            encoded.encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()

    def record_state(
        self,
        snapshot: dict[str, Any],
        *,
        caused_by: dict[str, Any] | None = None,
    ) -> tuple[str, bool]:
        """
        Record a browser-observed rendered state.

        Returns:
            (fingerprint, is_new)
        """

        fingerprint = self.fingerprint(snapshot)

        if not fingerprint:
            return "", False

        if fingerprint in self._states:
            return fingerprint, False

        record = {
            "state": fingerprint,
            "url": str(
                snapshot.get("url", "")
                or ""
            ),
            "title": str(
                snapshot.get("title", "")
                or ""
            ),
            "surface_count": len(
                snapshot.get("surfaces") or []
            ),
            "control_count": len(
                snapshot.get("controls") or []
            ),
            "form_count": len(
                snapshot.get("forms") or []
            ),
            "script_count": len(
                snapshot.get("scripts") or []
            ),
            "resource_count": len(
                snapshot.get("resources") or []
            ),
            "viewport": snapshot.get(
                "viewport",
                {},
            ),
        }

        if caused_by:
            record["caused_by"] = caused_by

        self._states[fingerprint] = record
        self._state_order.append(fingerprint)

        return fingerprint, True

    def record_transition(
        self,
        before_state: str,
        after_state: str,
        *,
        action: dict[str, Any] | None = None,
        navigation: dict[str, Any] | None = None,
        network_delta: dict[str, Any] | None = None,
    ) -> None:

        if not before_state or not after_state:
            return

        self._transitions.append(
            {
                "from": before_state,
                "to": after_state,
                "action": action or {},
                "navigation": navigation or {},
                "network_delta": network_delta or {},
            }
        )

    def export(self) -> dict[str, Any]:
        return {
            "states": [
                self._states[state]
                for state in self._state_order
            ],
            "transitions": list(
                self._transitions
            ),
            "state_count": len(
                self._states
            ),
            "transition_count": len(
                self._transitions
            ),
        }
