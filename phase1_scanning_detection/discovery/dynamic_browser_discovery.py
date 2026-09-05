"""
===============================================================================
AVAF PRO

Dynamic Browser Discovery

Collects observations from the CURRENT live browser state.

Important:
    This component does not generate URLs from wordlists.
    It does not guess routes.
    It does not perform vulnerability testing.

It only records things actually exposed by the rendered browser.
===============================================================================
"""

from __future__ import annotations

from urllib.parse import urljoin

from playwright.async_api import Page

from phase1_scanning_detection.discovery.logger import logger


class DynamicBrowserDiscovery:

    async def collect(
        self,
        page: Page,
    ) -> dict:

        result = {
            "url": page.url,
            "links": [],
            "forms": [],
            "inputs": [],
            "buttons": [],
            "event_handlers": [],
            "history": [],
            "resources": [],
        }

        # ==========================================================
        # CURRENT DOM
        # ==========================================================

        try:

            dom_data = await page.evaluate(
                """
                () => {

                    const links = [];
                    const forms = [];
                    const inputs = [];
                    const buttons = [];
                    const eventHandlers = [];

                    for (const element of
                         document.querySelectorAll("a[href]")) {

                        links.push({
                            tag: element.tagName,
                            href: element.href,
                            text: (element.innerText || "").trim()
                        });
                    }

                    for (const form of
                         document.querySelectorAll("form")) {

                        forms.push({
                            action: form.action || "",
                            method: form.method || "get"
                        });
                    }

                    for (const input of
                         document.querySelectorAll(
                             "input, textarea, select"
                         )) {

                        inputs.push({
                            tag: input.tagName,
                            name: input.name || "",
                            type: input.type || "",
                            id: input.id || ""
                        });
                    }

                    for (const button of
                         document.querySelectorAll(
                             "button, [role='button']"
                         )) {

                        buttons.push({
                            tag: button.tagName,
                            text: (button.innerText || "").trim()
                        });
                    }

                    for (const element of
                         document.querySelectorAll("*")) {

                        for (const attribute of element.attributes) {

                            if (
                                attribute.name.startsWith("on")
                            ) {

                                eventHandlers.push({
                                    tag: element.tagName,
                                    event: attribute.name,
                                    value: attribute.value
                                });
                            }
                        }
                    }

                    return {
                        links,
                        forms,
                        inputs,
                        buttons,
                        eventHandlers
                    };
                }
                """
            )

            result.update(
                dom_data or {}
            )

        except Exception as exc:

            logger.warning(
                "DYNAMIC",
                f"Live DOM collection failed: {exc}"
            )

        # ==========================================================
        # PERFORMANCE RESOURCE OBSERVATION
        # ==========================================================

        try:

            result["resources"] = await page.evaluate(
                """
                () => performance
                    .getEntriesByType("resource")
                    .map(entry => entry.name)
                    .filter(Boolean)
                """
            )

        except Exception as exc:

            logger.warning(
                "DYNAMIC",
                f"Resource collection failed: {exc}"
            )

        # ==========================================================
        # HISTORY STATE
        # ==========================================================

        try:

            history_state = await page.evaluate(
                """
                () => ({
                    href: location.href,
                    pathname: location.pathname,
                    search: location.search,
                    hash: location.hash
                })
                """
            )

            result["history"].append(
                history_state
            )

        except Exception:
            pass

        logger.info(
            "DYNAMIC",
            (
                f"Live DOM: "
                f"links={len(result['links'])} "
                f"forms={len(result['forms'])} "
                f"inputs={len(result['inputs'])} "
                f"buttons={len(result['buttons'])} "
                f"events={len(result['event_handlers'])} "
                f"resources={len(result['resources'])}"
            )
        )

        return result