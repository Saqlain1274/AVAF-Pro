"""
AVAF PRO

Mutation Engine

Consumes runtime DOM mutation events exported by the
AVAF Runtime Hooks.

Responsibilities
----------------
✓ Read runtime events
✓ Extract DOM mutations
✓ Normalize mutations
✓ Remove duplicates
✓ Preserve useful runtime metadata
✓ Export normalized mutations

Never
-----
✘ Discover URLs
✘ Execute interactions
✘ Modify the page
✘ Inject payloads
✘ Validate vulnerabilities
"""

from __future__ import annotations

import hashlib
import json

from typing import Any, Dict, List

from phase1_scanning_detection.discovery.logger import logger


class MutationEngine:
    """
    Normalizes DOM mutation events produced by AVAF runtime hooks.

    This component deliberately remains passive.

    Runtime interaction discovery belongs to:
        RuntimeDiscoveryCoordinator
        InteractionEngine

    Page orchestration belongs to:
        PlaywrightCrawler
    """

    def __init__(self):

        # Persistent across collection rounds.
        self._seen: set[str] = set()

        self.statistics = {
            "events": 0,
            "dom_events": 0,
            "mutations": 0,
            "duplicates": 0,
        }

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    async def collect(
        self,
        page,
    ) -> List[Dict[str, Any]]:
        """
        Read the current runtime export from Playwright
        and normalize DOM mutation events.
        """

        runtime = await self._read_runtime(
            page
        )

        return self.process(
            runtime
        )

    # ==========================================================
    # PROCESS
    # ==========================================================

    def process(
        self,
        runtime: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Normalize DOM mutation events.

        The existing mutation history is intentionally preserved.
        This prevents the same mutation from returning on every
        interaction round.
        """

        if not isinstance(
            runtime,
            dict,
        ):
            return []

        events = runtime.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):
            return []

        self.statistics[
            "events"
        ] += len(events)

        mutations = []

        for event in events:

            if not isinstance(
                event,
                dict,
            ):
                continue

            if event.get(
                "type"
            ) != "dom":

                continue

            self.statistics[
                "dom_events"
            ] += 1

            mutation = self._extract_mutation(
                event
            )

            if not mutation:
                continue

            normalized = self._normalize(
                mutation
            )

            if not normalized:
                continue

            if self._is_duplicate(
                normalized
            ):

                self.statistics[
                    "duplicates"
                ] += 1

                continue

            mutations.append(
                normalized
            )

            self.statistics[
                "mutations"
            ] += 1

        logger.info(
            "MUTATION",
            (
                f"DOM events={self.statistics['dom_events']} "
                f"new={len(mutations)} "
                f"duplicates={self.statistics['duplicates']}"
            ),
        )

        return mutations

    # ==========================================================
    # COMPATIBILITY EXPORT
    # ==========================================================

    def export(
        self,
        runtime: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Compatibility wrapper used by existing coordinators.
        """

        return self.process(
            runtime
        )

    # ==========================================================
    # RESET
    # ==========================================================

    def reset(
        self,
        clear_history: bool = True,
    ):
        """
        Reset mutation state.

        clear_history=True:
            start a completely new page/session.

        clear_history=False:
            keep previously discovered mutations.
        """

        if clear_history:

            self._seen.clear()

        self.statistics = {
            "events": 0,
            "dom_events": 0,
            "mutations": 0,
            "duplicates": 0,
        }

    # ==========================================================
    # PLAYWRIGHT RUNTIME
    # ==========================================================

    async def _read_runtime(
        self,
        page,
    ) -> Dict[str, Any]:

        if page is None:
            return {}

        try:

            if page.is_closed():
                return {}

        except Exception:

            return {}

        try:

            runtime = await page.evaluate(
                """
                () => {

                    if (!window.__AVAF__) {
                        return {};
                    }

                    if (
                        typeof window.__AVAF__.export ===
                        "function"
                    ) {
                        return window.__AVAF__.export();
                    }

                    return window.__AVAF__;

                }
                """
            )

            if isinstance(
                runtime,
                dict,
            ):
                return runtime

            return {}

        except Exception as exc:

            logger.error(
                "MUTATION",
                f"Runtime export failed: {exc}",
            )

            return {}

    # ==========================================================
    # EXTRACTION
    # ==========================================================

    def _extract_mutation(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any] | None:

        if event.get(
            "type"
        ) != "dom":

            return None

        data = event.get(
            "data"
        )

        if not isinstance(
            data,
            dict,
        ):
            return None

        return data

    # ==========================================================
    # NORMALIZATION
    # ==========================================================

    def _normalize(
        self,
        mutation: Dict[str, Any],
    ) -> Dict[str, Any]:

        """
        Keep the mutation model generic.

        We don't assume that the runtime hook uses one
        particular DOM schema.
        """

        normalized = dict(
            mutation
        )

        # Normalize common string fields.
        for key in (
            "tag",
            "id",
            "text",
            "role",
            "name",
            "type",
            "class",
        ):

            value = normalized.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                normalized[key] = value.strip()

        return normalized

    # ==========================================================
    # DEDUPLICATION
    # ==========================================================

    def _mutation_key(
        self,
        mutation: Dict[str, Any],
    ) -> str:

        """
        Build a stable fingerprint from the actual mutation data.

        Using the complete normalized mutation prevents unrelated
        DOM elements that happen to share tag/id/text from being
        collapsed together.
        """

        try:

            payload = json.dumps(
                mutation,
                sort_keys=True,
                default=str,
                separators=(
                    ",",
                    ":",
                ),
            )

        except Exception:

            payload = repr(
                mutation
            )

        return hashlib.sha256(
            payload.encode(
                "utf-8"
            )
        ).hexdigest()

    def _is_duplicate(
        self,
        mutation: Dict[str, Any],
    ) -> bool:

        key = self._mutation_key(
            mutation
        )

        if key in self._seen:

            return True

        self._seen.add(
            key
        )

        return False

    # ==========================================================
    # STATISTICS
    # ==========================================================

    def get_statistics(
        self,
    ) -> Dict[str, int]:

        return dict(
            self.statistics
        )

    # ==========================================================
    # HISTORY
    # ==========================================================

    def seen_count(
        self,
    ) -> int:

        return len(
            self._seen
        )