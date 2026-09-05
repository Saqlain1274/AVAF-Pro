"""
AVAF PRO
Browser Manager

Purpose
-------
Centralized Playwright lifecycle manager.

Responsibilities
----------------
✓ Start Playwright
✓ Launch Chromium
✓ Manage Browser Context
✓ Create Browser Pages
✓ Configure Browser Pages
✓ Register page initialization hooks
✓ Install AVAF runtime instrumentation
✓ Close Browser Pages
✓ Shutdown Browser

Never
-----
✘ Crawling
✘ Runtime Analysis
✘ Interaction Logic
✘ DOM Extraction
✘ Vulnerability Detection
"""

from __future__ import annotations

from typing import Awaitable, Callable

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from phase1_scanning_detection.discovery.logger import logger
from phase1_scanning_detection.runtime_hooks import HOOK_SCRIPT


# =====================================================================
# PAGE HOOK TYPE
# =====================================================================

PageHook = Callable[[Page], Awaitable[None]]


# =====================================================================
# BROWSER MANAGER
# =====================================================================

class BrowserManager:

    # =================================================================
    # CONFIGURATION
    # =================================================================

    DEFAULT_VIEWPORT = {
        "width": 1600,
        "height": 900,
    }

    DEFAULT_TIMEOUT = 30_000

    DEFAULT_NAVIGATION_TIMEOUT = 45_000

    # =================================================================
    # INITIALIZATION
    # =================================================================

    def __init__(
        self,
        headless: bool = True,
        slow_mo: int = 0,
    ):

        self.headless = headless
        self.slow_mo = slow_mo

        self.playwright: Playwright | None = None

        self.browser: Browser | None = None

        self.context: BrowserContext | None = None

        self.pages: set[Page] = set()

        self.started = False

        self.page_counter = 0

        self._page_hooks: list[PageHook] = []

        # -------------------------------------------------------------
        # AVAF runtime hook is registered once.
        #
        # Every page created through new_page() will receive it.
        # -------------------------------------------------------------

        self.register_page_hook(
            self._install_runtime_hooks
        )

    # =================================================================
    # PUBLIC API
    # =================================================================

    def register_page_hook(
        self,
        hook: PageHook,
    ) -> None:
        """
        Register an asynchronous page initialization hook.

        The hook is executed for every page created by this manager.

        Hooks run before the page is navigated, allowing runtime
        instrumentation to be installed before application JavaScript
        begins executing.
        """

        if not callable(hook):

            raise TypeError(
                "Page hook must be callable."
            )

        if hook not in self._page_hooks:

            self._page_hooks.append(
                hook
            )

    # =================================================================
    # AVAF RUNTIME INITIALIZATION
    # =================================================================

    async def _install_runtime_hooks(
        self,
        page: Page,
    ) -> None:
        """
        Install the complete AVAF runtime instrumentation into a page.

        This is intentionally handled by BrowserManager rather than
        crawler_playwright.py.

        The runtime is installed before navigation so AVAF can observe
        application JavaScript from the beginning of the page lifecycle.
        """

        page_id = getattr(
            page,
            "_avaf_id",
            "?",
        )

        logger.info(
            "HOOKS",
            f"Installing AVAF runtime hooks on Page #{page_id}..."
        )

        await page.add_init_script(
            HOOK_SCRIPT
        )

        # -------------------------------------------------------------
        # JavaScript errors
        # -------------------------------------------------------------

        page.on(
            "pageerror",
            lambda exc: logger.error(
                "HOOKS",
                (
                    f"Page #{page_id} JavaScript "
                    f"error: {exc}"
                ),
            ),
        )

        # -------------------------------------------------------------
        # Browser console
        # -------------------------------------------------------------

        page.on(
            "console",
            lambda msg: logger.info(
                "JS",
                (
                    f"Page #{page_id} "
                    f"[{msg.type}] {msg.text}"
                ),
            ),
        )

        logger.info(
            "HOOKS",
            (
                f"AVAF runtime hooks installed on "
                f"Page #{page_id} "
                f"(size={len(HOOK_SCRIPT)})"
            ),
        )

    # =================================================================
    # START
    # =================================================================

    async def start(
        self,
    ) -> BrowserContext:
        """
        Start Playwright, launch Chromium and create the browser
        context.

        Returns
        -------
        BrowserContext
            Active Playwright browser context.
        """

        # -------------------------------------------------------------
        # Already started
        # -------------------------------------------------------------

        if self.context is not None:

            return self.context

        logger.info(
            "BROWSER",
            "Starting Playwright..."
        )

        self.playwright = (
            await async_playwright().start()
        )

        logger.info(
            "BROWSER",
            "Launching Chromium..."
        )

        self.browser = (
            await self.playwright.chromium.launch(
                headless=self.headless,
                slow_mo=self.slow_mo,

                args=[
                    "--start-maximized",
                
                    "--disable-blink-features=AutomationControlled",
                
                    "--disable-dev-shm-usage",
                
                    "--disable-popup-blocking",
                ],
            )
        )

        logger.info(
            "BROWSER",
            "Creating Browser Context..."
        )

        self.context = (
            await self.browser.new_context(

                viewport=self.DEFAULT_VIEWPORT,

                ignore_https_errors=True,

                java_script_enabled=True,

                service_workers="allow",

                bypass_csp=True,

                locale="en-US",

                user_agent=(
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/137.0 Safari/537.36"
                ),
            )
        )

        self.started = True

        logger.info(
            "BROWSER",
            (
                "Browser Ready "
                f"(Chromium {self.browser.version})"
            ),
        )

        return self.context

    # =================================================================
    # CREATE PAGE
    # =================================================================

    async def new_page(
        self,
    ) -> Page:
        """
        Create and configure a new Playwright page.

        Runtime hooks are installed automatically through the registered
        page-hook system.

        crawler_playwright.py therefore does NOT need to call:

            page.add_init_script(HOOK_SCRIPT)

        """

        if (
            not self.started
            or self.context is None
        ):

            raise RuntimeError(
                "Browser has not been started."
            )

        # -------------------------------------------------------------
        # Create page
        # -------------------------------------------------------------

        page = await self.context.new_page()

        # -------------------------------------------------------------
        # Assign AVAF page ID BEFORE executing hooks.
        #
        # _install_runtime_hooks() uses this ID for logging.
        # -------------------------------------------------------------

        self.page_counter += 1

        setattr(
            page,
            "_avaf_id",
            self.page_counter,
        )

        self.pages.add(page)

        # -------------------------------------------------------------
        # Page timeouts
        # -------------------------------------------------------------

        page.set_default_timeout(
            self.DEFAULT_TIMEOUT
        )

        page.set_default_navigation_timeout(
            self.DEFAULT_NAVIGATION_TIMEOUT
        )

        # -------------------------------------------------------------
        # Page close tracking
        # -------------------------------------------------------------

        page.on(
            "close",
            lambda: self.pages.discard(page),
        )

        # -------------------------------------------------------------
        # Page crash tracking
        # -------------------------------------------------------------

        page.on(
            "crash",
            lambda: logger.error(
                "PAGE",
                (
                    f"Page #{page._avaf_id} "
                    "crashed."
                ),
            ),
        )

        # -------------------------------------------------------------
        # Execute registered page hooks.
        #
        # IMPORTANT:
        # This is the ONLY place where page initialization hooks
        # are executed.
        # -------------------------------------------------------------

        for hook in self._page_hooks:

            try:

                await hook(page)

            except Exception as exc:

                logger.error(
                    "HOOKS",
                    (
                        f"Page #{page._avaf_id} "
                        f"hook failed: {exc}"
                    ),
                )

                raise

        logger.info(
            "BROWSER",
            (
                f"Page #{page._avaf_id} created "
                f"({len(self.pages)} active)"
            ),
        )

        return page

    # =================================================================
    # CLOSE PAGE
    # =================================================================

    async def close_page(
        self,
        page: Page | None,
    ) -> None:
        """
        Safely close a single Playwright page.
        """

        if page is None:

            return

        page_id = getattr(
            page,
            "_avaf_id",
            "?",
        )

        try:

            if not page.is_closed():

                await page.close()

        except Exception as exc:

            logger.error(
                "BROWSER",
                (
                    f"Page #{page_id} "
                    f"close failed: {exc}"
                ),
            )

        finally:

            self.pages.discard(
                page
            )

    # =================================================================
    # STOP
    # =================================================================

    async def stop(
        self,
    ) -> None:
        """
        Shut down all pages, the browser context, Chromium and
        Playwright.
        """

        logger.info(
            "BROWSER",
            "Stopping Browser..."
        )

        # -------------------------------------------------------------
        # Close pages
        # -------------------------------------------------------------

        for page in list(self.pages):

            await self.close_page(
                page
            )

        # -------------------------------------------------------------
        # Close context
        # -------------------------------------------------------------

        if self.context is not None:

            try:

                await self.context.close()

            except Exception as exc:

                logger.error(
                    "BROWSER",
                    (
                        "Context close "
                        f"failed: {exc}"
                    ),
                )

        # -------------------------------------------------------------
        # Close browser
        # -------------------------------------------------------------

        if self.browser is not None:

            try:

                await self.browser.close()

            except Exception as exc:

                logger.error(
                    "BROWSER",
                    (
                        "Browser close "
                        f"failed: {exc}"
                    ),
                )

        # -------------------------------------------------------------
        # Stop Playwright
        # -------------------------------------------------------------

        if self.playwright is not None:

            try:

                await self.playwright.stop()

            except Exception as exc:

                logger.error(
                    "BROWSER",
                    (
                        "Playwright stop "
                        f"failed: {exc}"
                    ),
                )

        # -------------------------------------------------------------
        # Reset manager state
        # -------------------------------------------------------------

        self.started = False

        self.context = None

        self.browser = None

        self.playwright = None

        self.pages.clear()

        self.page_counter = 0

        logger.info(
            "BROWSER",
            "Browser shutdown complete."
        )