"""
===============================================================================
AVAF PRO

Page Session

Purpose
-------
Represents a single browser page during Phase-1 discovery.

Responsibilities
----------------
✓ Own Playwright Page
✓ Own RuntimeCollector
✓ Own NetworkCollector
✓ Attach collectors
✓ Start collectors
✓ Stop collectors
✓ Cleanup

Never
-----
✘ Navigate
✘ Analyze runtime
✘ Build models
✘ Queue URLs
===============================================================================
"""

from __future__ import annotations

from playwright.async_api import Page

from phase1_scanning_detection.browser.browser import BrowserManager

from phase1_scanning_detection.discovery.collector.runtime_collector import (
    RuntimeCollector,
)

from phase1_scanning_detection.discovery.collector.network_collector import (
    NetworkCollector,
)


class PageSession:

    def __init__(

        self,

        page: Page,

    ):

        self.page = page

        self.runtime = RuntimeCollector()

        self.network = NetworkCollector()

    # ======================================================
    # Factory
    # ======================================================

    @classmethod
    async def create(
        cls,
        browser: BrowserManager,
    ):
    
        page = await browser.new_page()
    
        session = cls(page)
    
        await session.runtime.attach(page)
    
        await session.network.attach(page)
    
        await session.network.start_capture()
    
        return session

    # ======================================================
    # Cleanup
    # ======================================================

    async def close(

        self,

        browser,

    ):

        try:

            await self.network.stop_capture()

        except Exception:

            pass

        await browser.close_page(

            self.page,

        )