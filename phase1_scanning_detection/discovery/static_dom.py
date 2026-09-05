"""
===============================================================================
AVAF Pro

Static DOM Observation / Discovery Coordinator

Purpose
-------
Coordinates passive discovery extractors over the CURRENT browser-rendered DOM.

Responsibilities
----------------
✓ Observe the live Playwright DOM
✓ Extract links visible in the rendered page
✓ Extract rendered forms
✓ Extract script information
✓ Extract metadata
✓ Extract comments from the observed DOM
✓ Detect endpoints from observed DOM content
✓ Detect technologies
✓ Provide StaticDOMResult to Phase-1

Design
------
This component observes what the browser has actually rendered.

It does NOT:
✘ Fetch arbitrary URLs
✘ Generate wordlist URLs
✘ Invent routes
✘ Invent parameters
✘ Perform vulnerability testing
✘ Inject attack payloads
✘ Control browser lifecycle
✘ Manage crawl queues

Browser interaction and navigation remain the responsibility of the crawler /
interaction layer.

Phase-1 can therefore use this component as a passive observation layer while
the browser behaves normally.
===============================================================================
"""

from __future__ import annotations

from typing import Any

from playwright.async_api import Page

from phase1_scanning_detection.discovery.logger import logger
from phase1_scanning_detection.discovery.model import StaticDOMResult

from phase1_scanning_detection.discovery.extractors.link_extractor import (
    LinkExtractor,
)

from phase1_scanning_detection.discovery.extractors.form_extractor import (
    FormExtractor,
)

from phase1_scanning_detection.discovery.extractors.meta_extractor import (
    MetaExtractor,
)

from phase1_scanning_detection.discovery.extractors.script_extractor import (
    ScriptExtractor,
)

from phase1_scanning_detection.discovery.extractors.comment_extractor import (
    CommentExtractor,
)

from phase1_scanning_detection.discovery.extractors.endpoint_detector import (
    EndpointDetector,
)

from phase1_scanning_detection.discovery.extractors.technology_detector import (
    TechnologyDetector,
)


class StaticDOMExtractor:
    """
    Passive coordinator for discovery extractors.

    The extractor always works against the currently rendered Playwright page.
    It never performs navigation itself.
    """

    # =========================================================================
    # INITIALIZATION
    # =========================================================================

    def __init__(self) -> None:

        self.page: Page | None = None

        self.result = StaticDOMResult()

        # Specialized passive extractors.
        self.links = LinkExtractor()
        self.forms = FormExtractor()
        self.meta = MetaExtractor()
        self.scripts = ScriptExtractor()
        self.comments = CommentExtractor()
        self.endpoints = EndpointDetector()
        self.technologies = TechnologyDetector()

    # =========================================================================
    # ATTACH
    # =========================================================================

    async def attach(
        self,
        page: Page,
    ) -> None:
        """
        Attach the extractor to an existing browser page.

        Browser creation/lifecycle remains outside this class.
        """

        self.page = page

    # =========================================================================
    # RESET
    # =========================================================================

    def reset(self) -> None:
        """
        Reset observations for the next page observation.
        """

        self.result = StaticDOMResult()

    # =========================================================================
    # PAGE VALIDATION
    # =========================================================================

    def _page_available(self) -> bool:
        """
        Return True when a usable Playwright page is attached.
        """

        return (
            self.page is not None
            and not self.page.is_closed()
        )

    # =========================================================================
    # RENDERED DOM
    # =========================================================================

    async def _get_rendered_html(
        self,
        url: str,
    ) -> str:
        """
        Safely obtain the CURRENT browser-rendered DOM.

        Why this exists
        ----------------
        Playwright can raise:

            Page.content:
            Unable to retrieve content because the page is navigating
            and changing the content.

        This happens frequently with:
        - redirects
        - SPA navigation
        - Angular/React/Vue rendering
        - dynamically replacing document content
        - browser-triggered navigation
        - pages that continue changing immediately after load

        We therefore:
        1. Try page.content()
        2. Retry after a short browser-side wait
        3. Try the live <html>.outerHTML
        4. Retry once more
        5. Return empty only if the browser DOM genuinely cannot be read

        No URL is fetched by this method.
        """

        if not self._page_available():
            logger.warning(
                "STATIC",
                f"Cannot read rendered DOM; page unavailable: {url}",
            )
            return ""

        assert self.page is not None

        # A bounded retry sequence.
        #
        # We deliberately do NOT use networkidle here.
        #
        # Modern applications can maintain:
        # - WebSockets
        # - polling
        # - analytics
        # - background API requests
        #
        # Waiting for networkidle would unnecessarily stall discovery.
        delays_ms = (
            0,
            150,
            350,
            700,
        )

        for attempt, delay_ms in enumerate(delays_ms, start=1):

            if not self._page_available():
                return ""

            if delay_ms:
                try:
                    await self.page.wait_for_timeout(
                        delay_ms
                    )
                except Exception as exc:

                    logger.debug(
                        "STATIC",
                        (
                            "DOM settle wait failed "
                            f"(attempt={attempt}): {exc}"
                        ),
                    )

            # -------------------------------------------------------------
            # PRIMARY METHOD
            # -------------------------------------------------------------

            try:

                html = await self.page.content()

                if html:
                    return html

            except Exception as exc:

                logger.debug(
                    "STATIC",
                    (
                        "page.content() failed "
                        f"(attempt={attempt}): {exc}"
                    ),
                )

            # -------------------------------------------------------------
            # LIVE DOM FALLBACK
            # -------------------------------------------------------------

            try:

                html = await self.page.locator(
                    "html"
                ).evaluate(
                    """
                    (element) => element.outerHTML
                    """
                )

                if html:
                    return html

            except Exception as exc:

                logger.debug(
                    "STATIC",
                    (
                        "live html.outerHTML failed "
                        f"(attempt={attempt}): {exc}"
                    ),
                )

        logger.warning(
            "STATIC",
            f"Unable to obtain rendered DOM for {url}",
        )

        return ""

    # =========================================================================
    # DOM STABILITY
    # =========================================================================

    async def _wait_for_dom_observation(
        self,
        url: str,
    ) -> None:
        """
        Give the browser a bounded opportunity to finish DOM initialization.

        This is intentionally lightweight.

        We do not wait for networkidle because dynamic applications may never
        become network-idle.
        """

        if not self._page_available():
            return

        assert self.page is not None

        try:

            await self.page.wait_for_load_state(
                "domcontentloaded",
                timeout=8000,
            )

        except Exception as exc:

            logger.debug(
                "STATIC",
                (
                    f"DOMContentLoaded wait ended for {url}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    # =========================================================================
    # SAFE EXTRACTOR EXECUTION
    # =========================================================================

    async def _run_async_extractor(
        self,
        label: str,
        extractor: Any,
        *args: Any,
    ) -> Any:
        """
        Execute an asynchronous extractor without allowing one broken
        extractor to destroy the entire page observation.
        """

        try:

            return await extractor.extract(
                *args
            )

        except Exception as exc:

            logger.warning(
                "STATIC",
                (
                    f"{label} failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            return None

    # =========================================================================
    # MAIN EXTRACTION
    # =========================================================================

    async def extract(
        self,
        url: str,
    ) -> None:
        """
        Observe the current rendered page and populate StaticDOMResult.

        Important:
        ----------
        This method does not navigate.

        The crawler has already opened the URL in the real browser.
        """

        if self.page is None:

            raise RuntimeError(
                "StaticDOMExtractor.attach() must be called first."
            )

        if self.page.is_closed():

            raise RuntimeError(
                "Cannot observe a closed Playwright page."
            )

        self.reset()

        logger.info(
            "STATIC",
            f"Observing rendered DOM: {url}",
        )

        # ---------------------------------------------------------------------
        # Give browser-rendered DOM a bounded opportunity to initialize.
        # ---------------------------------------------------------------------

        await self._wait_for_dom_observation(
            url
        )

        if not self._page_available():

            logger.warning(
                "STATIC",
                f"Page closed before DOM observation: {url}",
            )

            return

        # ---------------------------------------------------------------------
        # CURRENT RENDERED DOM
        # ---------------------------------------------------------------------

        html = await self._get_rendered_html(
            url
        )

        if not html:

            logger.warning(
                "STATIC",
                f"Rendered DOM unavailable for {url}",
            )

            return

        self.result.html_size = len(
            html
        )

        # ---------------------------------------------------------------------
        # LINKS
        # ---------------------------------------------------------------------

        value = await self._run_async_extractor(
            "LinkExtractor",
            self.links,
            self.page,
        )

        if value is not None:

            self.result.links = value

        # ---------------------------------------------------------------------
        # FORMS
        # ---------------------------------------------------------------------

        value = await self._run_async_extractor(
            "FormExtractor",
            self.forms,
            self.page,
        )

        if value is not None:

            self.result.forms = value

        # ---------------------------------------------------------------------
        # META
        # ---------------------------------------------------------------------

        value = await self._run_async_extractor(
            "MetaExtractor",
            self.meta,
            self.page,
        )

        if value is not None:

            self.result.meta = value

        # ---------------------------------------------------------------------
        # SCRIPTS
        # ---------------------------------------------------------------------

        value = await self._run_async_extractor(
            "ScriptExtractor",
            self.scripts,
            self.page,
        )

        if value is not None:

            self.result.scripts = value

        # ---------------------------------------------------------------------
        # COMMENTS
        #
        # CommentExtractor works against the already-observed DOM.
        # ---------------------------------------------------------------------

        try:

            self.result.comments = self.comments.extract(
                html
            )

        except Exception as exc:

            logger.warning(
                "STATIC",
                (
                    "CommentExtractor failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

                # ---------------------------------------------------------------------
        # ENDPOINTS
        #
        # IMPORTANT:
        #
        # Do NOT regex-scan the rendered HTML for arbitrary URL-looking
        # strings.
        #
        # That can manufacture candidates from:
        #
        #     - JavaScript source text
        #     - comments
        #     - examples
        #     - documentation
        #     - unrelated markup
        #     - static resources
        #
        # Real application endpoints are discovered through:
        #
        #     - rendered DOM navigation
        #     - rendered forms
        #     - browser navigation
        #     - fetch
        #     - XHR
        #     - runtime routes
        #     - actual browser network traffic
        #     - interaction-generated application requests
        #
        # Therefore static HTML endpoint regex discovery is disabled.
        # ---------------------------------------------------------------------

        self.result.endpoints.items.clear()

        self.result.endpoints.statistics.total = 0

        self.result.endpoints.statistics.discovered = 0

        # ---------------------------------------------------------------------
        # TECHNOLOGIES
        # ---------------------------------------------------------------------

        try:

            self.result.technologies = (
                self.technologies.extract(
                    html,
                    self.result.meta.items,
                    self.result.scripts.items,
                )
            )

        except Exception as exc:

            logger.warning(
                "STATIC",
                (
                    "TechnologyDetector failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        # ---------------------------------------------------------------------
        # SUMMARY
        # ---------------------------------------------------------------------

        logger.info(
            "STATIC",
            (
                f"DOM observed | "
                f"HTML={self.result.html_size} bytes | "
                f"Links={len(self.result.links.items)} | "
                f"Forms={len(self.result.forms.items)} | "
                f"Scripts={len(self.result.scripts.items)} | "
                f"Endpoints={len(self.result.endpoints.items)}"
            ),
        )

    # =========================================================================
    # RESULT
    # =========================================================================

    def build_result(
        self,
    ) -> StaticDOMResult:
        """
        Return the observations collected during the latest extraction.

        This method is required by DiscoveryCoordinator / crawler_playwright.py.
        """

        return self.result