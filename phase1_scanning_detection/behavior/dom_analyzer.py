"""
===============================================================================
AVAF Pro

DOM Analyzer
===============================================================================

Phase-1 responsibility:

    Analyze the DOM that the browser actually rendered.

This component observes application-facing DOM elements.

It does NOT:

    - crawl arbitrary URLs
    - generate URLs
    - use wordlists
    - guess endpoints
    - assume /login, /admin, /search, etc.
    - attack parameters
    - validate vulnerabilities
    - assign vulnerability confidence
    - treat static resources as application vectors

The browser/runtime observation pipeline is responsible for discovering
network and runtime behavior.

This component only extracts useful DOM evidence that actually exists in
the rendered page.
===============================================================================
"""

from __future__ import annotations

from typing import Any

from playwright.async_api import ElementHandle


class DOMAnalyzer:
    """
    Analyze browser-rendered DOM evidence.

    The analyzer is deliberately passive.

    Interaction/clicking belongs to the interaction engine.
    Network observation belongs to the runtime/network collectors.
    """

    def __init__(
        self,
        page=None,
    ) -> None:

        self.page = page

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    async def analyze(
        self,
        elements: dict[str, list[ElementHandle]],
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Analyze already-collected DOM elements.

        No URL discovery is performed here.
        """

        return {
            "forms": await self.forms(
                elements.get("forms", [])
            ),

            "inputs": await self.inputs(
                elements.get("inputs", [])
            ),

            "buttons": await self.buttons(
                elements.get("buttons", [])
            ),

            "links": await self.links(
                elements.get("links", [])
            ),

            "selects": await self.selects(
                elements.get("selects", [])
            ),

            "textareas": await self.textareas(
                elements.get("textareas", [])
            ),

            "iframes": await self.iframes(
                elements.get("iframes", [])
            ),

            "contenteditable": await self.contenteditable(
                elements.get("contenteditable", [])
            ),

            "custom": await self.custom(
                elements.get("custom", [])
            ),

            "shadow": await self.shadow(
                elements.get("shadow", [])
            ),

            "aria": await self.aria(
                elements.get("aria", [])
            ),
        }

    # =========================================================================
    # FORMS
    # =========================================================================

    async def forms(
        self,
        forms: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for form in forms:

            try:

                if not await form.is_visible():
                    continue

                action = (
                    await form.get_attribute("action")
                ) or ""

                method = (
                    await form.get_attribute("method")
                ) or "GET"

                enctype = (
                    await form.get_attribute("enctype")
                ) or ""

                inputs = await form.query_selector_all(
                    "input, textarea, select"
                )

                input_names = []

                for element in inputs:

                    name = (
                        await element.get_attribute("name")
                    ) or ""

                    if name:
                        input_names.append(name)

                discovered.append(
                    {
                        "element": form,
                        "action": action,
                        "method": method.upper(),
                        "enctype": enctype,
                        "inputs": input_names,
                        "input_count": len(inputs),
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # INPUTS
    # =========================================================================

    async def inputs(
        self,
        inputs: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in inputs:

            try:

                if not await element.is_visible():
                    continue

                input_type = (
                    await element.get_attribute("type")
                ) or "text"

                name = (
                    await element.get_attribute("name")
                ) or ""

                placeholder = (
                    await element.get_attribute("placeholder")
                ) or ""

                value = (
                    await element.get_attribute("value")
                ) or ""

                discovered.append(
                    {
                        "element": element,
                        "name": name,
                        "type": input_type.lower(),
                        "placeholder": placeholder,
                        "has_value": bool(value),
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # BUTTONS
    # =========================================================================

    async def buttons(
        self,
        buttons: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in buttons:

            try:

                if not await element.is_visible():
                    continue

                text = ""

                try:
                    text = (
                        await element.inner_text()
                    ).strip()
                except Exception:
                    pass

                role = (
                    await element.get_attribute("role")
                ) or ""

                input_type = (
                    await element.get_attribute("type")
                ) or ""

                discovered.append(
                    {
                        "element": element,
                        "text": text,
                        "role": role,
                        "type": input_type.lower(),
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # LINKS
    # =========================================================================

    async def links(
        self,
        links: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in links:

            try:

                if not await element.is_visible():
                    continue

                href = (
                    await element.get_attribute("href")
                ) or ""

                if not href:
                    continue

                # Non-navigation browser schemes are not application
                # HTTP endpoints.
                if href.lower().startswith(
                    (
                        "javascript:",
                        "mailto:",
                        "tel:",
                        "data:",
                    )
                ):
                    continue

                text = ""

                try:
                    text = (
                        await element.inner_text()
                    ).strip()
                except Exception:
                    pass

                discovered.append(
                    {
                        "element": element,
                        "href": href,
                        "text": text,
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # SELECTS
    # =========================================================================

    async def selects(
        self,
        selects: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in selects:

            try:

                if not await element.is_visible():
                    continue

                discovered.append(
                    {
                        "element": element,
                        "name": (
                            await element.get_attribute("name")
                        ) or "",
                        "value": (
                            await element.get_attribute("value")
                        ) or "",
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # TEXTAREAS
    # =========================================================================

    async def textareas(
        self,
        textareas: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in textareas:

            try:

                if not await element.is_visible():
                    continue

                discovered.append(
                    {
                        "element": element,
                        "name": (
                            await element.get_attribute("name")
                        ) or "",
                        "placeholder": (
                            await element.get_attribute("placeholder")
                        ) or "",
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # IFRAMES
    # =========================================================================

    async def iframes(
        self,
        iframes: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in iframes:

            try:

                discovered.append(
                    {
                        "element": element,
                        "src": (
                            await element.get_attribute("src")
                        ) or "",
                        "name": (
                            await element.get_attribute("name")
                        ) or "",
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # CONTENTEDITABLE
    # =========================================================================

    async def contenteditable(
        self,
        elements: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in elements:

            try:

                if not await element.is_visible():
                    continue

                editable = (
                    await element.get_attribute(
                        "contenteditable"
                    )
                )

                if editable is None:
                    continue

                discovered.append(
                    {
                        "element": element,
                        "contenteditable": editable,
                        "text": (
                            await element.inner_text()
                        ).strip(),
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # CUSTOM COMPONENTS
    # =========================================================================

    async def custom(
        self,
        elements: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in elements:

            try:

                tag_name = await element.evaluate(
                    "element => element.tagName.toLowerCase()"
                )

                # Native HTML elements are handled by their dedicated
                # collectors. Custom elements contain a hyphen according
                # to the Web Components custom-element naming convention.
                if "-" not in tag_name:
                    continue

                if not await element.is_visible():
                    continue

                discovered.append(
                    {
                        "element": element,
                        "tag": tag_name,
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # SHADOW DOM
    # =========================================================================

    async def shadow(
        self,
        elements: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in elements:

            try:

                has_shadow = await element.evaluate(
                    """
                    element =>
                        Boolean(element.shadowRoot)
                    """
                )

                if not has_shadow:
                    continue

                tag_name = await element.evaluate(
                    "element => element.tagName.toLowerCase()"
                )

                discovered.append(
                    {
                        "element": element,
                        "tag": tag_name,
                        "shadow_root": True,
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # ARIA
    # =========================================================================

    async def aria(
        self,
        elements: list[ElementHandle],
    ) -> list[dict[str, Any]]:

        discovered = []

        for element in elements:

            try:

                role = (
                    await element.get_attribute("role")
                ) or ""

                aria_label = (
                    await element.get_attribute("aria-label")
                ) or ""

                aria_controls = (
                    await element.get_attribute(
                        "aria-controls"
                    )
                ) or ""

                aria_expanded = (
                    await element.get_attribute(
                        "aria-expanded"
                    )
                ) or ""

                if not any(
                    (
                        role,
                        aria_label,
                        aria_controls,
                        aria_expanded,
                    )
                ):
                    continue

                discovered.append(
                    {
                        "element": element,
                        "role": role,
                        "aria_label": aria_label,
                        "aria_controls": aria_controls,
                        "aria_expanded": aria_expanded,
                    }
                )

            except Exception:
                continue

        return discovered

    # =========================================================================
    # BROWSER DOM COLLECTION
    # =========================================================================

    async def collect_elements(
        self,
    ) -> dict[str, list[ElementHandle]]:

        if self.page is None:
            return {
                "forms": [],
                "inputs": [],
                "buttons": [],
                "links": [],
                "selects": [],
                "textareas": [],
                "iframes": [],
                "contenteditable": [],
                "custom": [],
                "shadow": [],
                "aria": [],
            }

        return {
            "forms": await self.page.query_selector_all(
                "form"
            ),

            "inputs": await self.page.query_selector_all(
                "input"
            ),

            "buttons": await self.page.query_selector_all(
                "button, input[type='submit'], "
                "input[type='button'], input[type='image'], "
                "[role='button']"
            ),

            "links": await self.page.query_selector_all(
                "a"
            ),

            "selects": await self.page.query_selector_all(
                "select"
            ),

            "textareas": await self.page.query_selector_all(
                "textarea"
            ),

            "iframes": await self.page.query_selector_all(
                "iframe"
            ),

            "contenteditable": await self.page.query_selector_all(
                "[contenteditable]"
            ),

            "custom": await self.page.query_selector_all(
                "*"
            ),

            "shadow": await self.page.query_selector_all(
                "*"
            ),

            "aria": await self.page.query_selector_all(
                "[role], [aria-label], [aria-controls], "
                "[aria-expanded]"
            ),
        }