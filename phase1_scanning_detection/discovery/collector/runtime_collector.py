"""
===============================================================================
AVAF PRO

Runtime Collector

Collects runtime information exported by the injected
AVAF JavaScript runtime engine.

Responsibilities
----------------
✓ Read runtime export
✓ Fingerprint DOM
✓ Collect runtime artifacts
✓ Collect runtime statistics
✓ Build RuntimeResult

Never
-----
✘ Analyze behaviour
✘ Detect vulnerabilities
✘ Modify browser state
===============================================================================
"""

from __future__ import annotations

import hashlib

from playwright.async_api import Page

from phase1_scanning_detection.discovery.logger import logger
from phase1_scanning_detection.discovery.model import RuntimeResult


class RuntimeCollector:

    def __init__(self):

        self.page: Page | None = None
        self.reset()

    # ==================================================================
    # RESET
    # ==================================================================

    def reset(self):

        self.result = RuntimeResult()

    # ==================================================================
    # ATTACH
    # ==================================================================

    async def attach(
        self,
        page: Page,
    ):

        self.page = page

    # ==================================================================
    # MAIN
    # ==================================================================

    async def collect_runtime(self):

        if self.page is None:
            raise RuntimeError(
                "RuntimeCollector.attach() must be called first."
            )

        logger.info(
            "RUNTIME",
            "Collecting runtime information..."
        )

        
        # ==========================================================
        # 1. JS RUNTIME EXPORT
        # ==========================================================

        runtime = await self._export_runtime()

        if not isinstance(runtime, dict):
            runtime = {}

        self.result.runtime_data = runtime
        
        # Peserve every browser runtime observation.
        # Do not discard the previous observation when an interaction
        # causes another runtime collection.
        self.result.observations.append(
            {
                "url": runtime.get(
                    "url",
                    self.page.url,
                ),
                "title": runtime.get(
                    "title",
                    "",
                ),
                "runtime_data": runtime,
            }
        )

        # ==========================================================
        # 2. LIVE JS DOM
        # ==========================================================

        live_dom = await self._collect_live_dom()

        artifacts = self.result.runtime_data.setdefault(
            "artifacts",
            {}
        )

        if not isinstance(artifacts, dict):
            artifacts = {}
            self.result.runtime_data["artifacts"] = artifacts

        artifacts["dom"] = live_dom

        # ==========================================================
        # 3. COPY RUNTIME INFORMATION
        # ==========================================================

        self.result.events = self.result.runtime_data.get(
            "events",
            []
        )

        if not isinstance(self.result.events, list):
            self.result.events = []

        self.result.statistics = self.result.runtime_data.get(
            "statistics",
            {}
        )

        if not isinstance(self.result.statistics, dict):
            self.result.statistics = {}

        self.result.url = self.result.runtime_data.get(
            "url",
            self.page.url,
        )

        self.result.title = self.result.runtime_data.get(
            "title",
            "",
        )

        # ==========================================================
        # 4. CANONICAL LIVE-DOM FIELDS
        # ==========================================================

        if isinstance(live_dom, dict):

            self.result.runtime_forms = (
                live_dom.get("forms", [])
                if isinstance(
                    live_dom.get("forms", []),
                    list
                )
                else []
            )

            self.result.dynamic_routes = (
                live_dom.get("routes", [])
                if isinstance(
                    live_dom.get("routes", []),
                    list
                )
                else []
            )

            self.result.dom_mutations = (
                live_dom.get("mutations", [])
                if isinstance(
                    live_dom.get("mutations", []),
                    list
                )
                else []
            )

            self.result.javascript_events = (
                live_dom.get("events", [])
                if isinstance(
                    live_dom.get("events", []),
                    list
                )
                else []
            )

        # ==========================================================
        # 5. DIAGNOSTICS
        # ==========================================================

        logger.info(
            "RUNTIME",
            f"Version : {self.result.runtime_data.get('version', 'Unknown')}"
        )

        logger.info(
            "RUNTIME",
            f"Events : {len(self.result.events)}"
        )

        logger.info(
            "DOM",
            (
                "Live JS DOM | "
                f"Links={len(live_dom.get('links', []))} | "
                f"Forms={len(live_dom.get('forms', []))} | "
                f"Controls={len(live_dom.get('controls', []))} | "
                f"Routes={len(live_dom.get('routes', []))} | "
                f"Parameters={len(live_dom.get('parameters', []))}"
            )
        )
        
    async def _collect_live_dom(self) -> dict:
        """
        Observe the CURRENT browser-rendered DOM through JavaScript.

        This is the only DOM extraction source for Phase-1.

        Rules:
            - browser DOM only
            - visible application elements only
            - no wordlists
            - no guessed URLs
            - no guessed parameters
            - no vulnerability payloads
            - static resources are not page targets
        """

        if self.page is None or self.page.is_closed():
            return {
                "url": "",
                "title": "",
                "links": [],
                "forms": [],
                "controls": [],
                "routes": [],
                "parameters": [],
                "scripts": [],
                "mutations": [],
                "events": [],
            }

        try:

            data = await self.page.evaluate(
                """
                () => {

                    const visible = (el) => {

                        if (!el)
                            return false;

                        const style =
                            window.getComputedStyle(el);

                        if (
                            style.display === "none" ||
                            style.visibility === "hidden" ||
                            style.opacity === "0"
                        ) {
                            return false;
                        }

                        const rect =
                            el.getBoundingClientRect();

                        return (
                            rect.width > 0 &&
                            rect.height > 0
                        );
                    };


                    const absolute = (value) => {

                        if (!value)
                            return "";

                        try {
                            return new URL(
                                value,
                                location.href
                            ).href;
                        }

                        catch {
                            return "";
                        }
                    };


                    const isApplicationURL = (value) => {

                        if (!value)
                            return false;

                        try {

                            const u =
                                new URL(
                                    value,
                                    location.href
                                );

                            if (
                                u.origin !== location.origin
                            ) {
                                return false;
                            }

                            const path =
                                u.pathname.toLowerCase();

                            const staticExtensions = [
                                ".png",
                                ".jpg",
                                ".jpeg",
                                ".gif",
                                ".webp",
                                ".svg",
                                ".ico",
                                ".css",
                                ".woff",
                                ".woff2",
                                ".ttf",
                                ".mp3",
                                ".mp4",
                                ".webm",
                                ".zip",
                                ".rar",
                                ".7z"
                            ];

                            return !staticExtensions.some(
                                ext => path.endsWith(ext)
                            );

                        }

                        catch {
                            return false;
                        }
                    };


                    const links = [];

                    document
                        .querySelectorAll("a[href]")
                        .forEach((el) => {

                            if (!visible(el))
                                return;

                            const href =
                                absolute(
                                    el.getAttribute("href")
                                );

                            if (!isApplicationURL(href))
                                return;

                            links.push({
                                url: href,
                                text: (
                                    el.innerText ||
                                    el.textContent ||
                                    ""
                                ).trim().slice(0, 200),
                                rel:
                                    el.getAttribute("rel") || "",
                                target:
                                    el.getAttribute("target") || ""
                            });
                        });


                    const forms = [];

                    document
                        .querySelectorAll("form")
                        .forEach((form) => {

                            if (!visible(form))
                                return;

                            const action =
                                absolute(
                                    form.getAttribute("action")
                                ) ||
                                location.href;

                            const controls = [];

                            form
                                .querySelectorAll(
                                    "input,select,textarea,button"
                                )
                                .forEach((el) => {

                                    if (!visible(el))
                                        return;

                                    controls.push({
                                        tag:
                                            el.tagName.toLowerCase(),

                                        name:
                                            el.getAttribute("name") || "",

                                        type:
                                            el.getAttribute("type") || "",

                                        id:
                                            el.id || "",

                                        value:
                                            el.getAttribute("value") || ""
                                    });
                                });

                            forms.push({
                                action: action,
                                method:
                                    (
                                        form.getAttribute("method") ||
                                        "GET"
                                    ).toUpperCase(),
                                controls: controls
                            });
                        });


                    const controls = [];

                    document
                        .querySelectorAll(
                            "button," +
                            "input," +
                            "select," +
                            "textarea," +
                            "[role='button']," +
                            "[aria-expanded]"
                        )
                        .forEach((el) => {

                            if (!visible(el))
                                return;

                            controls.push({

                                tag:
                                    el.tagName.toLowerCase(),

                                id:
                                    el.id || "",

                                name:
                                    el.getAttribute("name") || "",

                                type:
                                    el.getAttribute("type") || "",

                                role:
                                    el.getAttribute("role") || "",

                                text: (
                                    el.innerText ||
                                    el.textContent ||
                                    ""
                                ).trim().slice(0, 200),

                                aria_expanded:
                                    el.getAttribute(
                                        "aria-expanded"
                                    ) || "",

                                locator_id:
                                    el.id
                                        ? "#" + CSS.escape(el.id)
                                        : ""
                            });
                        });


                    const routes = [];

                    links.forEach((item) => {

                        if (item.url)
                            routes.push(item.url);

                    });


                    const parameters = [];

                    const addParameter = (
                        name,
                        location,
                        url
                    ) => {

                        if (!name)
                            return;

                        parameters.push({
                            parameter: name,
                            location: location,
                            url: url || location.href,
                            observed: true
                        });
                    };


                    const current =
                        new URL(location.href);

                    current.searchParams.forEach(
                        (_, name) => {

                            addParameter(
                                name,
                                "query",
                                location.href
                            );

                        }
                    );


                    forms.forEach((form) => {

                        form.controls.forEach(
                            (control) => {

                                if (!control.name)
                                    return;

                                addParameter(
                                    control.name,
                                    "form",
                                    form.action
                                );

                            }
                        );

                    });


                    const scripts = [];
                    
                    document
                        .querySelectorAll("script[src]")
                        .forEach((script) => {
                    
                            /*
                             * Script elements are not visual UI elements.
                             *
                             * Do NOT apply the visual visibility filter here.
                             *
                             * The browser has actually loaded/observed this script
                             * resource through the rendered document.
                             *
                             * It is retained as application evidence only.
                             * It is NEVER promoted to a crawl target merely because
                             * it is a script.
                             */
                    
                            const src =
                                absolute(
                                    script.getAttribute("src")
                                );
                    
                            if (src)
                                scripts.push(src);
                        });


                    return {

                        url: location.href,

                        title: document.title || "",

                        links: links,

                        forms: forms,

                        controls: controls,

                        routes: [
                            ...new Set(routes)
                        ],

                        parameters: parameters,

                        scripts: [
                            ...new Set(scripts)
                        ],

                        mutations: [],

                        events: []
                    };
                }
                """
            )

            if not isinstance(data, dict):
                return {}

            return data

        except Exception as exc:

            logger.error(
                "DOM",
                f"Live JS DOM observation failed: {exc}"
            )

            return {}


    # ==================================================================
    # EXPORT
    # ==================================================================

    async def _export_runtime(self) -> dict:

        try:

            runtime = await self.page.evaluate(
                """
                () => {

                    if (!window.__AVAF__) {
                        return {
                            __avaf_missing__: true
                        };
                    }
                    
                    if (typeof window.__AVAF__.export === "function")
                        return window.__AVAF__.export();

                    return window.__AVAF__;

                }
                """
            )

            if isinstance(runtime, dict):

                if runtime.get("__avaf_missing__"):
                    logger.warning(
                        "RUNTIME",
                        "window.__AVAF__ is not present in the page."
                    )
                    return {}

                return runtime

            return {}

        except Exception as exc:

            logger.error(
                "RUNTIME",
                f"Runtime export failed: {exc}"
            )

            return {}

    # ==================================================================
    # DOM HASH
    # ==================================================================

    async def _fingerprint_dom(self):

        try:

            html = await self.page.content()

            return hashlib.sha256(
                html.encode("utf-8")
            ).hexdigest()

        except Exception as exc:

            logger.error(
                "RUNTIME",
                f"DOM fingerprint failed: {exc}"
            )

            return ""

    # ==================================================================
    # RESULT
    # ==================================================================

    def build_result(self):

        return self.result
