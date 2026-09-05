"""
AVAF Pro
Runtime Navigation Instrumentation

Safe, repeatable browser-runtime navigation instrumentation.

Responsibilities:
    - Capture client-side navigation
    - Discover links
    - Discover forms
    - Observe dynamically created links/forms
    - Capture history API navigation
    - Capture hash/popstate navigation
    - Capture window.open()
    - Capture form submissions
    - Capture downloads
    - Remain safe during very early document lifecycle

Important:
    This module must not assume that <html> already exists.

    Playwright can inject runtime code before the document has created
    document.documentElement. Therefore MutationObserver installation is
    deferred until a real DOM Node exists.
"""

NAVIGATION_HOOK = r"""
/* ==========================================================
 * AVAF NAVIGATION RUNTIME
 * ========================================================== */

(function () {

    "use strict";

    /* ======================================================
     * WAIT FOR AVAF CORE
     * ====================================================== */

    function AVAF_NAV_START() {

    /*
     * The AVAF runtime is canonically stored on
     * window.__AVAF__.
     *
     * window.AVAF is maintained as a compatibility
     * alias by the Event Bus.
     */
    if (
        typeof window === "undefined"
    ) {
        return false;
    }

    var runtime =
        window.__AVAF__ ||
        window.AVAF;

    if (!runtime) {

        console.info(
            "[AVAF]",
            "Navigation runtime waiting for AVAF core"
        );

        return false;
    }

    /*
     * Keep both runtime references synchronized.
     */
    window.__AVAF__ = runtime;
    window.AVAF = runtime;

    if (
        !runtime.navigation
    ) {
        runtime.navigation = {};
    }

    return true;
}

    /* ======================================================
     * WAIT FOR A REAL DOM NODE
     * ====================================================== */

    function AVAF_NAV_HAS_DOM_ROOT() {

        if (
            typeof document === "undefined"
        ) {
            return false;
        }

        var root = document.documentElement;

        return (
            root !== null &&
            typeof root === "object" &&
            typeof root.nodeType === "number" &&
            root.nodeType === 1
        );
    }


    /* ======================================================
     * SAFE RUNTIME INSTALLATION
     * ====================================================== */

    function AVAF_NAV_INSTALL() {

        if (!AVAF_NAV_START()) {
            return false;
        }

        /*
         * Do not install DOM-dependent instrumentation until
         * document.documentElement is a genuine DOM Node.
         */
        if (!AVAF_NAV_HAS_DOM_ROOT()) {

            console.info(
                "[AVAF]",
                "Navigation runtime waiting for DOM"
            );

            return false;
        }

        var AVAF =
        window.__AVAF__ ||
        window.AVAF;

        if (!AVAF) {
            return false;
        }
        
        window.__AVAF__ = AVAF;
        window.AVAF = AVAF;

        /* Prevent duplicate installation. */
        if (
            AVAF.__navigation_runtime_installed === true
        ) {
            return true;
        }

        AVAF.__navigation_runtime_installed = true;


        /* ==================================================
         * NAVIGATION OBJECT
         * ================================================== */

        if (!AVAF.navigation) {
            AVAF.navigation = {};
        }


        /* ==================================================
         * SAFE EMITTER
         * ================================================== */

        AVAF.navigation.emit = function (
            subtype,
            target,
            metadata
        ) {

            metadata = metadata || {};

            target = AVAF.normalize(
                target || location.href
            );

            AVAF.emit(
                "navigation",
                subtype,
                target,
                metadata
            );

            AVAF.addPage(
                location.href
            );

            AVAF.addRoute(
                target
            );
        };


        /* ==================================================
         * LINK DISCOVERY
         * ================================================== */

        AVAF.navigation.discoverLink = function (link) {

            if (!link) {
                return;
            }

            try {

                var normalized = AVAF.normalize(
                    link
                );

                if (!normalized) {
                    return;
                }

                AVAF.addLink(
                    normalized
                );

            } catch (error) {

                console.warn(
                    "[AVAF] Link discovery failed",
                    error
                );
            }
        };


        /* ==================================================
         * FORM DISCOVERY
         * ================================================== */

        AVAF.navigation.discoverForm = function (form) {

            if (!form) {
                return;
            }

            try {

                AVAF.addForm(
                    form.action || location.href
                );

            } catch (error) {

                console.warn(
                    "[AVAF] Form discovery failed",
                    error
                );
            }
        };


        /* ==================================================
         * INITIAL PAGE
         * ================================================== */

        try {

            AVAF.navigation.emit(
                "page_load",
                location.href,
                {
                    title: document.title || "",
                    referrer: document.referrer || ""
                }
            );

        } catch (error) {

            console.warn(
                "[AVAF] Initial navigation capture failed",
                error
            );
        }


        /* ==================================================
         * HISTORY API
         * ================================================== */

        if (
            !AVAF.navigation.__history_installed
        ) {

            AVAF.navigation.__history_installed = true;

            var originalPushState =
                history.pushState;

            var originalReplaceState =
                history.replaceState;


            history.pushState = function (
                state,
                title,
                url
            ) {

                try {

                    AVAF.navigation.emit(
                        "pushState",
                        url || location.href
                    );

                } catch (error) {

                    console.warn(
                        "[AVAF] pushState capture failed",
                        error
                    );
                }

                return originalPushState.apply(
                    history,
                    arguments
                );
            };


            history.replaceState = function (
                state,
                title,
                url
            ) {

                try {

                    AVAF.navigation.emit(
                        "replaceState",
                        url || location.href
                    );

                } catch (error) {

                    console.warn(
                        "[AVAF] replaceState capture failed",
                        error
                    );
                }

                return originalReplaceState.apply(
                    history,
                    arguments
                );
            };
        }


        /* ==================================================
         * HASH NAVIGATION
         * ================================================== */

        if (
            !AVAF.navigation.__hash_listener_installed
        ) {

            AVAF.navigation.__hash_listener_installed = true;

            window.addEventListener(
                "hashchange",
                function () {

                    AVAF.navigation.emit(
                        "hashchange",
                        location.href
                    );
                },
                true
            );
        }


        /* ==================================================
         * POPSTATE
         * ================================================== */

        if (
            !AVAF.navigation.__popstate_listener_installed
        ) {

            AVAF.navigation.__popstate_listener_installed = true;

            window.addEventListener(
                "popstate",
                function () {

                    AVAF.navigation.emit(
                        "popstate",
                        location.href
                    );
                },
                true
            );
        }


        /* ==================================================
         * WINDOW.OPEN
         * ================================================== */

        if (
            !AVAF.navigation.__window_open_installed
        ) {

            AVAF.navigation.__window_open_installed = true;

            var originalWindowOpen =
                window.open;

            AVAF.navigation.originalOpen =
                originalWindowOpen;


            window.open = function (
                url,
                name,
                specs
            ) {

                try {

                    AVAF.navigation.emit(
                        "window_open",
                        url || location.href,
                        {
                            name: name || "",
                            specs: specs || ""
                        }
                    );

                } catch (error) {

                    console.warn(
                        "[AVAF] window.open capture failed",
                        error
                    );
                }

                return originalWindowOpen.apply(
                    window,
                    arguments
                );
            };
        }


        /* ==================================================
         * ANCHOR CLICKS
         * ================================================== */

        if (
            !AVAF.navigation.__click_listener_installed
        ) {

            AVAF.navigation.__click_listener_installed = true;

            document.addEventListener(
                "click",
                function (event) {

                    try {

                        if (
                            !event ||
                            !event.target
                        ) {
                            return;
                        }

                        var target =
                            event.target;

                        if (
                            !target.closest
                        ) {
                            return;
                        }

                        var link =
                            target.closest(
                                "a[href]"
                            );

                        if (!link) {
                            return;
                        }

                        AVAF.navigation.discoverLink(
                            link.href
                        );

                        AVAF.navigation.emit(
                            "anchor",
                            link.href,
                            {
                                text:
                                    link.innerText || "",

                                target:
                                    link.target || ""
                            }
                        );

                    } catch (error) {

                        console.warn(
                            "[AVAF] Anchor capture failed",
                            error
                        );
                    }
                },
                true
            );
        }


        /* ==================================================
         * FORM SUBMISSION
         * ================================================== */

        if (
            !AVAF.navigation.__submit_listener_installed
        ) {

            AVAF.navigation.__submit_listener_installed = true;

            document.addEventListener(
                "submit",
                function (event) {

                    try {

                        var form =
                            event.target;

                        if (
                            !form ||
                            !(
                                form instanceof
                                HTMLFormElement
                            )
                        ) {
                            return;
                        }

                        AVAF.navigation.discoverForm(
                            form
                        );

                        AVAF.navigation.emit(
                            "form_submit",
                            form.action ||
                                location.href,
                            {
                                method:
                                    (
                                        form.method ||
                                        "GET"
                                    ).toUpperCase()
                            }
                        );

                    } catch (error) {

                        console.warn(
                            "[AVAF] Form capture failed",
                            error
                        );
                    }
                },
                true
            );
        }


        /* ==================================================
         * DOWNLOAD LINKS
         * ================================================== */

        if (
            !AVAF.navigation.__download_listener_installed
        ) {

            AVAF.navigation.__download_listener_installed = true;

            document.addEventListener(
                "click",
                function (event) {

                    try {

                        if (
                            !event ||
                            !event.target ||
                            !event.target.closest
                        ) {
                            return;
                        }

                        var download =
                            event.target.closest(
                                "a[download]"
                            );

                        if (!download) {
                            return;
                        }

                        AVAF.navigation.emit(
                            "download",
                            download.href
                        );

                    } catch (error) {

                        console.warn(
                            "[AVAF] Download capture failed",
                            error
                        );
                    }
                },
                true
            );
        }


        /* ==================================================
         * DYNAMIC LINK OBSERVER
         * ================================================== */

        if (
            !AVAF.navigation.__link_observer
        ) {

            var linkObserver =
                new MutationObserver(
                    function () {

                        try {

                            if (
                                !AVAF_NAV_HAS_DOM_ROOT()
                            ) {
                                return;
                            }

                            var links =
                                document.querySelectorAll(
                                    "a[href]"
                                );

                            links.forEach(
                                function (link) {

                                    AVAF.navigation
                                        .discoverLink(
                                            link.href
                                        );
                                }
                            );

                        } catch (error) {

                            console.warn(
                                "[AVAF] Link observer error",
                                error
                            );
                        }
                    }
                );


            /*
             * IMPORTANT:
             *
             * Pass the local verified Node directly.
             *
             * Do not call observe() with document,
             * documentElement before checking it,
             * or another potentially unavailable object.
             */
            var linkRoot =
                document.documentElement;


            if (
                linkRoot &&
                typeof linkRoot.nodeType === "number" &&
                linkRoot.nodeType === 1
            ) {

                linkObserver.observe(
                    linkRoot,
                    {
                        childList: true,
                        subtree: true
                    }
                );

                AVAF.navigation.__link_observer =
                    linkObserver;
            }
        }


        /* ==================================================
         * DYNAMIC FORM OBSERVER
         * ================================================== */

        if (
            !AVAF.navigation.__form_observer
        ) {

            var formObserver =
                new MutationObserver(
                    function () {

                        try {

                            if (
                                !AVAF_NAV_HAS_DOM_ROOT()
                            ) {
                                return;
                            }

                            var forms =
                                document.querySelectorAll(
                                    "form"
                                );

                            forms.forEach(
                                function (form) {

                                    AVAF.navigation
                                        .discoverForm(
                                            form
                                        );
                                }
                            );

                        } catch (error) {

                            console.warn(
                                "[AVAF] Form observer error",
                                error
                            );
                        }
                    }
                );


            var formRoot =
                document.documentElement;


            if (
                formRoot &&
                typeof formRoot.nodeType === "number" &&
                formRoot.nodeType === 1
            ) {

                formObserver.observe(
                    formRoot,
                    {
                        childList: true,
                        subtree: true
                    }
                );

                AVAF.navigation.__form_observer =
                    formObserver;
            }
        }


        /* ==================================================
         * VISIBILITY
         * ================================================== */

        if (
            !AVAF.navigation.__visibility_listener_installed
        ) {

            AVAF.navigation.__visibility_listener_installed =
                true;

            document.addEventListener(
                "visibilitychange",
                function () {

                    AVAF.navigation.emit(
                        "visibility",
                        location.href,
                        {
                            state:
                                document.visibilityState
                        }
                    );
                },
                true
            );
        }


        /* ==================================================
         * BEFORE UNLOAD
         * ================================================== */

        if (
            !AVAF.navigation.__beforeunload_installed
        ) {

            AVAF.navigation.__beforeunload_installed =
                true;

            window.addEventListener(
                "beforeunload",
                function () {

                    AVAF.navigation.emit(
                        "beforeunload",
                        location.href
                    );
                },
                true
            );
        }


        /* ==================================================
         * INITIAL LINK DISCOVERY
         * ================================================== */

        try {

            document
                .querySelectorAll("a[href]")
                .forEach(
                    function (link) {

                        AVAF.navigation
                            .discoverLink(
                                link.href
                            );
                    }
                );

        } catch (error) {

            console.warn(
                "[AVAF] Initial link discovery failed",
                error
            );
        }


        /* ==================================================
         * INITIAL FORM DISCOVERY
         * ================================================== */

        try {

            document
                .querySelectorAll("form")
                .forEach(
                    function (form) {

                        AVAF.navigation
                            .discoverForm(
                                form
                            );
                    }
                );

        } catch (error) {

            console.warn(
                "[AVAF] Initial form discovery failed",
                error
            );
        }


        console.info(
            "[AVAF]",
            "Navigation Hooks Ready"
        );

        return true;
    }


    /* ======================================================
     * STARTUP SCHEDULER
     * ====================================================== */

    function AVAF_NAV_BOOT() {

        if (AVAF_NAV_INSTALL()) {
            return;
        }

        /*
         * The runtime can execute before either AVAF or the DOM
         * exists. Retry asynchronously rather than calling
         * MutationObserver.observe() against an invalid target.
         */

        
        var attempts = 0;
        var maxAttempts = 40;


        function retry() {

            attempts++;

            if (
                AVAF_NAV_INSTALL()
            ) {
                return;
            }

            if (
                attempts >= maxAttempts
            ) {

                console.warn(
                    "[AVAF]",
                    "Navigation runtime could not initialize"
                );

                return;
            }

            setTimeout(
                retry,
                50
            );
        }


        setTimeout(
            retry,
            0
        );
    }


    /* ======================================================
     * BOOT
     * ====================================================== */

    AVAF_NAV_BOOT();

})();
"""
