"""
AVAF PRO

Element Collector

Purpose
-------
Collect every interesting runtime DOM element once.

Responsibilities
----------------
✓ Visible forms
✓ Inputs
✓ Buttons
✓ Links
✓ Selects
✓ Textareas
✓ Contenteditable
✓ Iframes
✓ Custom elements
✓ Shadow DOM hosts
✓ ARIA widgets

Never
-----
✘ Score elements
✘ Build tasks
✘ Execute interactions
"""

from __future__ import annotations

from playwright.async_api import Page


class ElementCollector:

    def __init__(self, page: Page):

        self.page = page

    # =====================================================
    # Public API
    # =====================================================

    async def collect(self) -> dict:

        return {

            "forms": await self.forms(),

            "inputs": await self.inputs(),

            "buttons": await self.buttons(),

            "links": await self.links(),

            "selects": await self.selects(),

            "textareas": await self.textareas(),

            "iframes": await self.iframes(),

            "contenteditable": await self.contenteditable(),

            "custom": await self.custom_elements(),

            "shadow": await self.shadow_hosts(),

            "aria": await self.aria(),

        }

    # =====================================================
    # Collectors
    # =====================================================

    async def forms(self):

        return await self.page.query_selector_all("form")

    async def inputs(self):

        return await self.page.query_selector_all("input")

    async def buttons(self):

        return await self.page.query_selector_all(

            "button,input[type=submit],input[type=button],[role=button]"

        )

    async def links(self):

        return await self.page.query_selector_all("a[href]")

    async def selects(self):

        return await self.page.query_selector_all("select")

    async def textareas(self):

        return await self.page.query_selector_all("textarea")

    async def iframes(self):

        return await self.page.query_selector_all("iframe")

    async def contenteditable(self):

        return await self.page.query_selector_all(

            "[contenteditable]"

        )

    async def aria(self):

        return await self.page.query_selector_all(

            "[role]"

        )

    async def custom_elements(self):

        return await self.page.evaluate_handle(
            """
            () => {

                return [...document.querySelectorAll("*")]

                    .filter(

                        e => e.tagName.includes("-")

                    );

            }
            """
        )

    async def shadow_hosts(self):

        return await self.page.evaluate_handle(
            """
            () => {

                return [...document.querySelectorAll("*")]

                    .filter(

                        e => e.shadowRoot

                    );

            }
            """
        )