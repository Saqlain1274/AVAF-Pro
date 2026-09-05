"""
===============================================================================
AVAF PRO

Runtime Behavior Processor

Purpose
-------
Transforms raw runtime events exported by the browser instrumentation
into normalized runtime attack-surface artifacts.

Responsibilities
----------------
✓ Parse runtime eventsa
✓ Normalize runtime artifacts
✓ Remove duplicates
✓ Produce AttackSurface objects

Never
-----
✘ Validate vulnerabilities
✘ Correlate findings
✘ Modify browser state
✘ Execute JavaScript

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from playwright.async_api import Page

from phase1_scanning_detection.discovery.logger import logger


# ============================================================================
# ATTACK SURFACE
# ============================================================================

@dataclass(slots=True)
class AttackSurface:

    category: str
    subtype: str
    source: str
    value: str

    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# RUNTIME PROCESSOR
# ============================================================================

class RuntimeBehaviorProcessor:

    def __init__(self):

        self.reset()

        self.handlers = {

            "network": self._network,

            "navigation": self._navigation,

            "form": self._form,

            "input": self._input,

            "upload": self._upload,

            "storage": self._storage,

            "worker": self._worker,

            "message": self._message,

            "security": self._security,

            "iframe": self._iframe,

        }
        
    async def collect(
        self,
        page: Page,
        runtime: dict,
    ):
        """
        Convert browser-observed runtime information into normalized
        Phase-1 attack-surface observations.

        IMPORTANT:
            This method consumes observations only.

        It does NOT:
            - guess routes
            - generate URLs
            - generate parameters
            - execute payloads
            - validate vulnerabilities
            - crawl
            - modify browser state

        Runtime sources accepted here are limited to information actually
        exported/observed by the browser runtime:

            events
            DOM runtime artifacts
            runtime forms
            runtime navigation
            runtime XHR/fetch/GraphQL
            WebSockets
            JavaScript events
            DOM mutations
        """

        logger.info(
            "RUNTIME",
            "Processing runtime behaviour..."
        )

        self.reset()

        if not isinstance(runtime, dict):
            logger.warning(
                "RUNTIME",
                "Runtime export is not a dictionary."
            )
            runtime = {}

        # ==============================================================
        # 1. PROCESS ACTUAL RUNTIME EVENTS
        # ==============================================================

        events = runtime.get(
            "events",
            []
        )

        if not isinstance(events, list):
            events = []

        logger.info(
            "RUNTIME",
            f"Runtime events received: {len(events)}"
        )

        processed = 0

        for event in events:

            if not isinstance(event, dict):
                continue

            category = (
                event.get("category")
                or event.get("type")
                or ""
            )

            category = str(
                category
            ).lower().strip()

            aliases = {
                "xhr": "network",
                "fetch": "network",
                "request": "network",
                "api": "network",

                "route": "navigation",
                "navigation": "navigation",

                "forms": "form",
                "inputs": "input",

                "file_upload": "upload",
                "fileupload": "upload",

                "local_storage": "storage",
                "session_storage": "storage",

                "workers": "worker",
                "messaging": "message",
                "iframes": "iframe",
            }

            category = aliases.get(
                category,
                category,
            )

            handler = self.handlers.get(
                category
            )

            if handler is None:
                logger.debug(
                    "RUNTIME",
                    (
                        "Ignoring unsupported observed "
                        f"runtime event: {category}"
                    ),
                )
                continue

            try:

                handler(event)
                processed += 1

            except Exception as exc:

                logger.error(
                    "RUNTIME",
                    (
                        "Runtime handler failed "
                        f"category={category}: {exc}"
                    ),
                )

        # ==============================================================
        # 2. PROCESS BROWSER-OBSERVED ARTIFACTS
        # ==============================================================

        artifacts = runtime.get(
            "artifacts",
            {}
        )

        if not isinstance(
            artifacts,
            dict,
        ):
            artifacts = {}

        # --------------------------------------------------------------
        # Live DOM export
        # --------------------------------------------------------------

        dom = artifacts.get(
            "dom",
            {}
        )

        if isinstance(
            dom,
            dict,
        ):

            self._consume_live_dom(
                dom
            )

        # --------------------------------------------------------------
        # Runtime-produced network observations
        # --------------------------------------------------------------

        self._consume_observed_collection(
            runtime.get("xhr"),
            category="api",
            subtype="xhr",
            source="runtime-xhr",
        )

        self._consume_observed_collection(
            runtime.get("fetch"),
            category="api",
            subtype="fetch",
            source="runtime-fetch",
        )

        self._consume_observed_collection(
            runtime.get("graphql"),
            category="api",
            subtype="graphql",
            source="runtime-graphql",
        )

        self._consume_observed_collection(
            runtime.get("websockets"),
            category="websocket",
            subtype="connection",
            source="runtime-websocket",
        )

        # Some runtime implementations place these under artifacts
        # instead of the root runtime export.
        self._consume_observed_collection(
            artifacts.get("xhr"),
            category="api",
            subtype="xhr",
            source="runtime-artifacts",
        )

        self._consume_observed_collection(
            artifacts.get("fetch"),
            category="api",
            subtype="fetch",
            source="runtime-artifacts",
        )

        self._consume_observed_collection(
            artifacts.get("graphql"),
            category="api",
            subtype="graphql",
            source="runtime-artifacts",
        )

        self._consume_observed_collection(
            artifacts.get("websockets"),
            category="websocket",
            subtype="connection",
            source="runtime-artifacts",
        )

        # ==============================================================
        # 3. PAGE METADATA
        # ==============================================================

        title = ""

        try:

            title = await page.title()

        except Exception as exc:

            logger.debug(
                "RUNTIME",
                f"Unable to read page title: {exc}"
            )

        logger.info(
            "RUNTIME",
            f"Runtime events processed: {processed}"
        )

        logger.info(
            "RUNTIME",
            (
                "Runtime artifacts discovered: "
                f"{len(self.artifacts)}"
            ),
        )

        # ==============================================================
        # 4. RETURN CANONICAL RUNTIME OBSERVATIONS
        # ==============================================================

        return {
            "url": page.url,

            "title": title,

            "statistics": runtime.get(
                "statistics",
                {},
            ),

            "artifacts": self.artifacts,
            
        }
        
        
    def _consume_live_dom(
        self,
        dom: dict,
    ) -> None:
        """
        Consume only observations from the currently rendered browser DOM.

        These values are evidence that existed in the browser at observation
        time. They are never converted into guessed routes or vulnerabilities.
        """

        routes = dom.get(
            "routes",
            []
        )

        if isinstance(
            routes,
            list,
        ):

            for route in routes:

                if not isinstance(
                    route,
                    str,
                ):
                    continue

                route = route.strip()

                if not route:
                    continue

                self.add(
                    "route",
                    "rendered-dom",
                    route,
                    source="rendered-dom",
                    observed=True,
                )

        forms = dom.get(
            "forms",
            []
        )

        if isinstance(
            forms,
            list,
        ):

            for form in forms:

                if not isinstance(
                    form,
                    dict,
                ):
                    continue

                action = str(
                    form.get("action")
                    or ""
                ).strip()

                if not action:
                    continue

                self.add(
                    "form",
                    "rendered-dom",
                    action,
                    source="rendered-dom",
                    observed=True,
                    method=form.get(
                        "method",
                        "GET",
                    ),
                )

        parameters = dom.get(
            "parameters",
            []
        )

        if isinstance(
            parameters,
            list,
        ):

            for parameter in parameters:

                if not isinstance(
                    parameter,
                    dict,
                ):
                    continue

                name = str(
                    parameter.get("parameter")
                    or ""
                ).strip()

                if not name:
                    continue

                location = str(
                    parameter.get("location")
                    or ""
                ).strip()

                url = str(
                    parameter.get("url")
                    or ""
                ).strip()

                # Parameter observations are only retained when the browser
                # actually supplied a parameter location.
                if not location:
                    continue

                self.add(
                    "parameter",
                    location,
                    name,
                    source="rendered-dom",
                    observed=True,
                    url=url,
                    location=location,
                )

        mutations = dom.get(
            "mutations",
            []
        )

        if isinstance(
            mutations,
            list,
        ):

            for mutation in mutations:

                if not isinstance(
                    mutation,
                    dict,
                ):
                    continue

                target = str(
                    mutation.get("target")
                    or ""
                ).strip()

                if not target:
                    continue

                self.add(
                    "dom",
                    "mutation",
                    target,
                    source="runtime-dom",
                    observed=True,
                    metadata=mutation,
                )

        javascript_events = dom.get(
            "events",
            []
        )

        if isinstance(
            javascript_events,
            list,
        ):

            for event in javascript_events:

                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                target = str(
                    event.get("target")
                    or event.get("value")
                    or ""
                ).strip()

                if not target:
                    continue

                self.add(
                    "javascript",
                    str(
                        event.get(
                            "type",
                            "event",
                        )
                    ),
                    target,
                    source="runtime-dom",
                    observed=True,
                    metadata=event,
                )


    def _consume_observed_collection(
        self,
        collection,
        *,
        category: str,
        subtype: str,
        source: str,
    ) -> None:
        """
        Normalize a runtime collection without inventing anything.

        Supported values may be strings or dictionaries exported by the
        browser instrumentation.
        """

        if not isinstance(
            collection,
            list,
        ):
            return

        for item in collection:

            if isinstance(
                item,
                str,
            ):

                value = item.strip()

                if not value:
                    continue

                self.add(
                    category,
                    subtype,
                    value,
                    source=source,
                    observed=True,
                )

                continue

            if not isinstance(
                item,
                dict,
            ):
                continue

            value = str(
                item.get("url")
                or item.get("target")
                or item.get("value")
                or ""
            ).strip()

            if not value:
                continue

            metadata = dict(
                item
            )

            self.add(
                category,
                subtype,
                value,
                source=source,
                observed=True,
                metadata=metadata,
            )
            
            
    # ------------------------------------------------------------------------

    def reset(self):

        self.artifacts: List[AttackSurface] = []

        self._seen = set()

    # ------------------------------------------------------------------------

    def add(

        self,

        category,

        subtype,

        value,

        **metadata

    ):

        if not value:
            return

        key = (

            category,

            subtype,

            value

        )

        if key in self._seen:
            return

        self._seen.add(key)

        self.artifacts.append(

            AttackSurface(

                category=category,

                subtype=subtype,

                source="runtime",

                value=value,

                metadata=metadata

            )

        )

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================

    async def process(

        self,

        page: Page,

        runtime_data: dict,

    ):
        logger.info(
            "RUNTIME",
            "Processing runtime behaviour..."
        )

        self.reset()

        logger.info(

            "RUNTIME",

            "Processing runtime events..."

        )

        events = runtime_data.get(

            "events",

            []

        )

        for event in events:

            handler = self.handlers.get(

                event.get("category")

            )

            if handler:

                handler(event)

        logger.info(

            "RUNTIME",

            f"Artifacts: {len(self.artifacts)}"

        )

        title = ""

        try:

            title = await page.title()

        except Exception:

            pass
        logger.info(
            "RUNTIME",
            f"Artifacts discovered: {len(self.artifacts)}"
        )

        return {

            "url": page.url,

            "title": title,

            "statistics": runtime_data.get(

                "statistics",

                {}

            ),

            "artifacts": self.artifacts,

        }

    # =========================================================================
    # HANDLERS
    # =========================================================================

    def _network(self, event):

        self.add(

            "api",

            event.get("subtype", "network"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _navigation(self, event):

        self.add(

            "route",

            event.get("subtype", "navigation"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _form(self, event):

        self.add(

            "form",

            event.get("subtype", "runtime"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _input(self, event):

        self.add(

            "input",

            event.get("subtype", "text"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _upload(self, event):

        self.add(

            "upload",

            event.get("subtype", "file"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _storage(self, event):

        self.add(

            "storage",

            event.get("subtype"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _worker(self, event):

        self.add(

            "worker",

            event.get("subtype"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _message(self, event):

        self.add(

            "message",

            event.get("subtype"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _security(self, event):

        self.add(

            "security",

            event.get("subtype"),

            event.get("target"),

            **event.get("metadata", {})

        )

    # -------------------------------------------------------------------------

    def _iframe(self, event):

        self.add(

            "iframe",

            event.get("subtype"),

            event.get("target"),

            **event.get("metadata", {})

        )
