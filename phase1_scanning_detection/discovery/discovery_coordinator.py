"""
===============================================================================
AVAF PRO

Discovery Coordinator
===============================================================================

Browser-behavior-driven Phase-1 discovery coordinator.

The coordinator observes the REAL browser state.

Pipeline:

    rendered DOM
        ↓
    runtime
        ↓
    behavior
        ↓
    real browser interaction
        ↓
    post-interaction DOM
        ↓
    post-interaction runtime
        ↓
    network
        ↓
    DiscoveryResult

This module performs discovery only.

It does NOT:

    - generate vulnerability payloads
    - fuzz parameters
    - validate vulnerabilities
    - exploit targets
    - guess URLs
    - use wordlists
    - crawl arbitrary paths
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phase1_scanning_detection.discovery.logger import logger

from phase1_scanning_detection.discovery.static_dom import (
    StaticDOMExtractor,
)

from phase1_scanning_detection.runtime_behavior_processor import (
    RuntimeBehaviorProcessor,
)

from phase1_scanning_detection.interaction.interactionEngine import (
    InteractionEngine,
)


# =============================================================================
# RESULT
# =============================================================================

@dataclass(slots=True)
class DiscoveryResult:

    static: object

    runtime: object

    network: object

    behavior: object

    interaction: object


# =============================================================================
# COORDINATOR
# =============================================================================

class DiscoveryCoordinator:

    def __init__(self, queue):

        self.queue = queue

        self.behavior = RuntimeBehaviorProcessor()

        self.interaction = InteractionEngine(
            queue=queue,
        )

    # =========================================================================
    # MAIN PIPELINE
    # =========================================================================

    async def collect(
        self,
        session,
        url,
        decision_engine,
    ) -> DiscoveryResult:

        page = session.page

        logger.info(
            "DISCOVERY",
            f"Starting browser-driven discovery: {url}",
        )

        # ------------------------------------------------------------------
        # IMPORTANT
        #
        # Network capture MUST remain active during the entire behavioral
        # exploration.
        #
        # Do NOT stop network capture before InteractionEngine.
        # ------------------------------------------------------------------

        # ==================================================================
        # 1. INITIAL DOM
        # ==================================================================

        logger.info(
            "STATIC",
            f"Observing initial rendered DOM: {url}",
        )

        static = await self._collect_static(
            page=page,
            url=url,
        )

        # ==================================================================
        # 2. INITIAL RUNTIME
        # ==================================================================

        logger.info(
            "RUNTIME",
            "Collecting initial runtime behaviour...",
        )

        runtime = await self._collect_runtime(
            session,
        )

        # ==================================================================
        # 3. REAL BROWSER INTERACTION
        # ==================================================================

        # ==================================================================
        # 4. REAL BROWSER INTERACTION
        # ==================================================================
        #
        # InteractionEngine is now the active behavioral discovery stage.
        #
        # It operates on what Playwright actually sees:
        #
        #   buttons
        #   links
        #   forms
        #   controls
        #   dialogs
        #   menus
        #   tabs
        #   SPA controls
        #
        # No guessed routes.
        # No wordlists.
        # No payloads.
        # ==================================================================

        logger.info(
            "INTERACTION",
            f"Exploring real browser state: {page.url or url}",
        )

        interaction = await self._collect_interaction(
            page=page,
            decision_engine=decision_engine,
        )

        # ==================================================================
        # 5. POST-INTERACTION DOM
        # ==================================================================
        #
        # This is critical for dynamic applications.
        #
        # Example:
        #
        #   click menu
        #       ↓
        #   DOM changes
        #       ↓
        #   new controls/routes/forms appear
        #
        # We observe the new DOM instead of assuming what exists.
        # ==================================================================

        logger.info(
            "STATIC",
            f"Re-observing rendered DOM after interaction: "
            f"{page.url or url}",
        )

        static_after = await self._collect_static(
            page=page,
            url=page.url or url,
        )

        static = self._merge_static_results(
            static,
            static_after,
        )        

        # ==================================================================
        # 6. POST-INTERACTION RUNTIME
        # ==================================================================

        logger.info(
            "RUNTIME",
            "Collecting post-interaction runtime behaviour...",
        )

        runtime_after = await self._collect_runtime(
            session,
        )

        runtime = self._merge_runtime_results(
            runtime,
            runtime_after,
        )

        # ==================================================================
        # FINAL BEHAVIOR PROCESSING
        # ==================================================================
        #
        # Behavior processing happens AFTER interaction so it can consume
        # the runtime evidence produced by actual browser behavior.
        #

        behavior = await self._collect_behavior(
            page=page,
            runtime=runtime,
        )
        # ==================================================================
        # 7. NETWORK
        # ==================================================================
        #
        # ONLY NOW is browser network capture finalized.
        #
        # Therefore requests generated by:
        #
        #   page load
        #   JavaScript
        #   clicks
        #   forms
        #   SPA transitions
        #   controls
        #
        # remain available.
        # ==================================================================

        network = await self._collect_network(
            session,
        )

        # ==================================================================
        # 8. FINAL OBSERVATION LOG
        # ==================================================================

        self._log_summary(
            url=url,
            static=static,
            runtime=runtime,
            network=network,
            behavior=behavior,
            interaction=interaction,
        )

        return DiscoveryResult(
            static=static,
            runtime=runtime,
            network=network,
            behavior=behavior,
            interaction=interaction,
        )

    # =========================================================================
    # STATIC
    # =========================================================================

    async def _collect_static(
        self,
        page,
        url,
    ):

        extractor = StaticDOMExtractor()

        await extractor.attach(
            page,
        )

        try:

            await extractor.extract(
                url,
            )

        except Exception as exc:

            logger.warning(
                "STATIC",
                (
                    "Rendered DOM extraction failed; "
                    f"continuing browser discovery: {exc}"
                ),
            )

        return extractor.build_result()

    # =========================================================================
    # RUNTIME
    # =========================================================================

    async def _collect_runtime(
        self,
        session,
    ):

        try:

            await session.runtime.collect_runtime()

            return session.runtime.build_result()

        except Exception as exc:

            logger.warning(
                "RUNTIME",
                f"Runtime collection failed: {exc}",
            )

            return None

    # =========================================================================
    # BEHAVIOR
    # =========================================================================

    async def _collect_behavior(
        self,
        page,
        runtime,
    ):

        runtime_data = {}

        if runtime is not None:

            runtime_data = getattr(
                runtime,
                "runtime_data",
                {},
            )

        if not isinstance(
            runtime_data,
            dict,
        ):
            runtime_data = {}

        try:

            return await self.behavior.process(
                page=page,
                runtime_data=runtime_data,
            )

        except Exception as exc:

            logger.warning(
                "BEHAVIOR",
                f"Runtime behaviour processing failed: {exc}",
            )

            return None

    # =========================================================================
    # INTERACTION
    # =========================================================================

    async def _collect_interaction(
        self,
        page,
        decision_engine,
    ):

        try:

            result = await self.interaction.explore(
                page=page,
                decision_engine=decision_engine,
            )

            if result is None:

                logger.warning(
                    "INTERACTION",
                    "InteractionEngine returned None.",
                )

                return {
                    "events": [],
                    "navigations": [],
                    "routes": [],
                    "controls": [],
                    "forms": [],
                    "surfaces": [],
                    "stats": {},
                }

            if not isinstance(
                result,
                dict,
            ):

                logger.warning(
                    "INTERACTION",
                    (
                        "InteractionEngine returned "
                        f"{type(result).__name__}; "
                        "normalizing."
                    ),
                )

                return {
                    "events": [],
                    "navigations": [],
                    "routes": [],
                    "controls": [],
                    "forms": [],
                    "surfaces": [],
                    "stats": {},
                }

            return result

        except Exception as exc:

            logger.error(
                "INTERACTION",
                (
                    f"InteractionEngine failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            raise

    # =========================================================================
    # NETWORK
    # =========================================================================

    async def _collect_network(
        self,
        session,
    ):

        try:

            # Network capture is stopped ONLY after interaction.
            await session.network.stop_capture()

        except Exception as exc:

            logger.warning(
                "NETWORK",
                f"Network capture stop failed: {exc}",
            )

        try:

            return session.network.build_result()

        except Exception as exc:

            logger.warning(
                "NETWORK",
                f"Network result construction failed: {exc}",
            )

            return None

    # =========================================================================
    # STATIC MERGE
    # =========================================================================

    def _merge_static_results(
        self,
        first,
        second,
    ):

        if first is None:
            return second

        if second is None:
            return first

        # ---------------------------------------------------------------
        # Dataclass/object merge
        # ---------------------------------------------------------------

        for attribute in (
            "links",
            "forms",
            "meta",
            "scripts",
            "comments",
            "endpoints",
            "technologies",
        ):

            first_value = getattr(
                first,
                attribute,
                None,
            )

            second_value = getattr(
                second,
                attribute,
                None,
            )

            if first_value is None or second_value is None:
                continue

            first_items = getattr(
                first_value,
                "items",
                None,
            )

            second_items = getattr(
                second_value,
                "items",
                None,
            )

            if isinstance(first_items, list) and isinstance(
                second_items,
                list,
            ):

                seen = {
                    repr(item)
                    for item in first_items
                }

                for item in second_items:

                    marker = repr(item)

                    if marker not in seen:

                        first_items.append(item)

                        seen.add(marker)

        # ---------------------------------------------------------------
        # Keep largest observed HTML size.
        # ---------------------------------------------------------------

        try:

            first.html_size = max(
                int(getattr(first, "html_size", 0)),
                int(getattr(second, "html_size", 0)),
            )

        except Exception:
            pass

        return first

    # =========================================================================
    # RUNTIME MERGE
    # =========================================================================

    def _merge_runtime_results(
        self,
        first,
        second,
    ):

        if first is None:
            return second

        if second is None:
            return first

        # ---------------------------------------------------------------
        # Events
        # ---------------------------------------------------------------

        first_events = getattr(
            first,
            "events",
            None,
        )

        second_events = getattr(
            second,
            "events",
            None,
        )

        if isinstance(first_events, list) and isinstance(
            second_events,
            list,
        ):

            first_events.extend(
                event
                for event in second_events
                if event not in first_events
            )

        # ---------------------------------------------------------------
        # Runtime artifacts
        # ---------------------------------------------------------------

        first_data = getattr(
            first,
            "runtime_data",
            {},
        )

        second_data = getattr(
            second,
            "runtime_data",
            {},
        )

        if isinstance(first_data, dict) and isinstance(
            second_data,
            dict,
        ):

            first_data["events"] = first_events or []

            artifacts = second_data.get(
                "artifacts",
                {},
            )

            if artifacts:
                first_data["artifacts"] = artifacts

            first_data["url"] = (
                second_data.get(
                    "url"
                )
                or first_data.get(
                    "url"
                )
            )

            first_data["title"] = (
                second_data.get(
                    "title"
                )
                or first_data.get(
                    "title"
                )
            )

        return first

    # =========================================================================
    # SUMMARY
    # =========================================================================

    def _log_summary(
        self,
        *,
        url,
        static,
        runtime,
        network,
        behavior,
        interaction,
    ):

        def count_items(value):

            if value is None:
                return 0

            items = getattr(
                value,
                "items",
                None,
            )

            if isinstance(
                items,
                (list, tuple, set),
            ):
                return len(items)

            return 0

        links = count_items(
            getattr(static, "links", None)
        )

        forms = count_items(
            getattr(static, "forms", None)
        )

        scripts = count_items(
            getattr(static, "scripts", None)
        )

        endpoints = count_items(
            getattr(static, "endpoints", None)
        )

        events = len(
            getattr(
                runtime,
                "events",
                [],
            )
            or []
        )

        interaction_stats = {}

        if isinstance(
            interaction,
            dict,
        ):

            interaction_stats = (
                interaction.get(
                    "stats",
                    {}
                )
                or {}
            )

        logger.info(
            "DISCOVERY",
            (
                f"Completed {url} | "
                f"DOM links={links} "
                f"forms={forms} "
                f"scripts={scripts} "
                f"endpoints={endpoints} | "
                f"runtime_events={events} | "
                f"interaction_actions="
                f"{interaction_stats.get('actions', 0)} | "
                f"interaction_clicks="
                f"{interaction_stats.get('clicks', 0)}"
            ),
        )