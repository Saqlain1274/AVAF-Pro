"""
===============================================================================
AVAF PRO
Runtime Event Bus
===============================================================================

Central JavaScript runtime telemetry layer.

This module is intentionally exported as a JavaScript string because
runtime_hooks.py combines it with the other AVAF runtime modules.

IMPORTANT
---------
Only ONE AVAF runtime object is created.

If the page already contains AVAF, the existing object is reused.

This prevents:

    Identifier 'AVAF' has already been declared

===============================================================================
"""

EVENT_BUS = r"""
"use strict";

/*==========================================================*
 * AVAF RUNTIME CORE
 *==========================================================*/

/*
 * IMPORTANT:
 *
 * Do NOT use:
 *
 *     const AVAF = ...
 *
 * here.
 *
 * runtime hooks may be evaluated more than once during a browser
 * lifecycle. `var` is deliberately used because JavaScript allows
 * the same var declaration to be encountered again.
 *
 * The actual runtime object is stored on window.__AVAF__.
 */

var AVAF = window.__AVAF__ || window.AVAF;

if (!AVAF) {

    AVAF = {

        version: "6.1",

        started: Date.now(),

        nextId: 1,

        maxEvents: 50000,

        events: [],

        seen: new Set(),

        runtime: {

            forms: [],
            controls: [],
            parameters: []

        },

        artifacts: {

            pages: new Set(),

            routes: new Set(),

            links: new Set(),

            endpoints: new Set(),

            forms: new Set(),

            parameters: new Set(),

            uploads: new Set(),

            graphql: new Set(),

            websockets: new Set(),

            xhr: new Set(),

            fetch: new Set()

        },

        statistics: {

            network: 0,

            navigation: 0,

            ui: 0,

            storage: 0,

            worker: 0,

            message: 0,

            security: 0,

            upload: 0,

            iframe: 0,

            error: 0

        }

    };

    window.__AVAF__ = AVAF;
    window.AVAF = AVAF;

    console.info(
        "[AVAF]",
        "Runtime Core Initialized",
        AVAF.version
    );

}


/*==========================================================*
 * NORMALIZATION
 *==========================================================*/

AVAF.normalize = function(value) {

    if (
        value === undefined ||
        value === null
    ) {
        return "";
    }

    return String(value).trim();

};


/*==========================================================*
 * STATISTICS
 *==========================================================*/

AVAF.increment = function(category) {

    if (
        AVAF.statistics &&
        Object.prototype.hasOwnProperty.call(
            AVAF.statistics,
            category
        )
    ) {

        AVAF.statistics[category]++;

    }

};


/*==========================================================*
 * PRIORITY
 *==========================================================*/

AVAF.priority = function(category) {

    switch (category) {

        case "network":
        case "security":
        case "upload":
        case "form":

            return "HIGH";

        case "navigation":
        case "storage":
        case "worker":
        case "iframe":

            return "MEDIUM";

        default:

            return "LOW";

    }

};


/*==========================================================*
 * SEVERITY
 *==========================================================*/

AVAF.severity = function(category) {

    switch (category) {

        case "security":

            return "CRITICAL";

        case "network":
        case "upload":
        case "form":

            return "HIGH";

        case "navigation":
        case "storage":
        case "worker":

            return "MEDIUM";

        default:

            return "INFO";

    }

};


/*==========================================================*
 * DISCOVERY HELPERS
 *==========================================================*/

AVAF.addPage = function(url) {

    if (url) {

        AVAF.artifacts.pages.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addRoute = function(route) {

    if (route) {

        AVAF.artifacts.routes.add(
            AVAF.normalize(route)
        );

    }

};


AVAF.addLink = function(url) {

    if (url) {

        AVAF.artifacts.links.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addEndpoint = function(url) {

    if (url) {

        AVAF.artifacts.endpoints.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addForm = function(action) {

    if (action) {

        AVAF.artifacts.forms.add(
            AVAF.normalize(action)
        );

    }

};


AVAF.addUpload = function(url) {

    if (url) {

        AVAF.artifacts.uploads.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addGraphQL = function(url) {

    if (url) {

        AVAF.artifacts.graphql.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addWebSocket = function(url) {

    if (url) {

        AVAF.artifacts.websockets.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addXHR = function(url) {

    if (url) {

        AVAF.artifacts.xhr.add(
            AVAF.normalize(url)
        );

    }

};


AVAF.addFetch = function(url) {

    if (url) {

        AVAF.artifacts.fetch.add(
            AVAF.normalize(url)
        );

    }

};


/*==========================================================*
 * PARAMETER EXTRACTION
 *==========================================================*/

AVAF.addParameters = function(url) {

    if (!url) {

        return;

    }

    try {

        const parsed = new URL(
            url,
            location.href
        );

        parsed.searchParams.forEach(
            function(_, key) {

                if (key) {

                    AVAF.artifacts.parameters.add(
                        String(key)
                    );

                }

            }
        );

    }
    catch (error) {

        /* Ignore malformed runtime URLs. */

    }

};


/*==========================================================*
 * EVENT EMITTER
 *==========================================================*/

AVAF.emit = function(
    category,
    subtype,
    target,
    metadata
) {

    category = AVAF.normalize(category);

    subtype = AVAF.normalize(subtype);

    target = AVAF.normalize(target);

    metadata =
        metadata &&
        typeof metadata === "object"
            ? metadata
            : {};


    if (!category) {

        return;

    }


    /*
     * Deduplicate identical observations on the
     * same rendered page.
     */

    const key =
        location.href +
        "|" +
        category +
        "|" +
        subtype +
        "|" +
        target;


    if (AVAF.seen.has(key)) {

        return;

    }


    AVAF.seen.add(key);


    AVAF.increment(category);


    const event = {

        id: AVAF.nextId++,

        timestamp: Date.now(),

        relativeTime:
            Date.now() -
            AVAF.started,

        page:
            location.href,

        title:
            document.title || "",

        category:
            category,

        subtype:
            subtype,

        target:
            target,

        priority:
            AVAF.priority(category),

        severity:
            AVAF.severity(category),

        metadata:
            metadata

    };


    AVAF.events.push(event);


    /*
     * Keep runtime memory bounded.
     */

    if (
        AVAF.events.length >
        AVAF.maxEvents
    ) {

        AVAF.events.shift();

    }


    /*
     * Every observed page is an artifact.
     */

    AVAF.addPage(
        location.href
    );


    /*
     * Extract query parameters from
     * observed targets.
     */

    AVAF.addParameters(
        target
    );


    /*
     * Categorize discovered runtime surface.
     */

    switch (category) {

        case "network":

            AVAF.addEndpoint(target);

            break;


        case "navigation":

            AVAF.addRoute(target);

            break;


        case "form":

            AVAF.addForm(target);

            break;


        case "upload":

            AVAF.addUpload(target);

            break;


        default:

            break;

    }

};


/*==========================================================*
 * RUNTIME SUMMARY
 *==========================================================*/

AVAF.summary = function() {

    return {

        version:
            AVAF.version,

        url:
            location.href,

        title:
            document.title || "",

        started:
            AVAF.started,

        duration:
            Date.now() -
            AVAF.started,

        totalEvents:
            AVAF.events.length,

        statistics:
            {
                ...AVAF.statistics
            }

    };

};


/*==========================================================*
 * RUNTIME EXPORT
 *==========================================================*/

AVAF.export = function() {

    return {

        version:
            AVAF.version,

        url:
            location.href,

        title:
            document.title || "",

        started:
            AVAF.started,

        finished:
            Date.now(),

        duration:
            Date.now() -
            AVAF.started,

        statistics:
            {
                ...AVAF.statistics
            },

        totalEvents:
            AVAF.events.length,

        summary:
            AVAF.summary(),

        events:
            [
                ...AVAF.events
            ],

        runtime: {

            forms:
                [
                    ...(AVAF.runtime &&
                      Array.isArray(AVAF.runtime.forms)
                        ? AVAF.runtime.forms
                        : [])
                ],

            controls:
                [
                    ...(AVAF.runtime &&
                      Array.isArray(AVAF.runtime.controls)
                        ? AVAF.runtime.controls
                        : [])
                ],

            parameters:
                [
                    ...(AVAF.runtime &&
                      Array.isArray(AVAF.runtime.parameters)
                        ? AVAF.runtime.parameters
                        : [])
                ]

        },

        artifacts: {

            pages:
                [
                    ...AVAF.artifacts.pages
                ],

            routes:
                [
                    ...AVAF.artifacts.routes
                ],

            links:
                [
                    ...AVAF.artifacts.links
                ],

            endpoints:
                [
                    ...AVAF.artifacts.endpoints
                ],

            forms:
                [
                    ...AVAF.artifacts.forms
                ],

            parameters:
                [
                    ...AVAF.artifacts.parameters
                ],

            uploads:
                [
                    ...AVAF.artifacts.uploads
                ],

            graphql:
                [
                    ...AVAF.artifacts.graphql
                ],

            websockets:
                [
                    ...AVAF.artifacts.websockets
                ],

            xhr:
                [
                    ...AVAF.artifacts.xhr
                ],

            fetch:
                [
                    ...AVAF.artifacts.fetch
                ]

        }

    };

};


/*==========================================================*
 * RUNTIME STATISTICS
 *==========================================================*/

AVAF.stats = function() {

    return {

        totalEvents:
            AVAF.events.length,

        runtime:
            Date.now() -
            AVAF.started,

        statistics:
            {
                ...AVAF.statistics
            },

        pages:
            AVAF.artifacts.pages.size,

        routes:
            AVAF.artifacts.routes.size,

        links:
            AVAF.artifacts.links.size,

        endpoints:
            AVAF.artifacts.endpoints.size,

        forms:
            AVAF.artifacts.forms.size,

        parameters:
            AVAF.artifacts.parameters.size,

        uploads:
            AVAF.artifacts.uploads.size,

        graphql:
            AVAF.artifacts.graphql.size,

        websockets:
            AVAF.artifacts.websockets.size,

        xhr:
            AVAF.artifacts.xhr.size,

        fetch:
            AVAF.artifacts.fetch.size

    };

};


/*==========================================================*
 * RESET
 *==========================================================*/

AVAF.reset = function() {

    AVAF.events = [];

    AVAF.seen.clear();

    AVAF.nextId = 1;

    AVAF.started = Date.now();


    if (!AVAF.runtime) {
        AVAF.runtime = {};
    }

    AVAF.runtime.forms = [];
    AVAF.runtime.controls = [];
    AVAF.runtime.parameters = [];

    Object.keys(
        AVAF.statistics
    ).forEach(
        function(key) {

            AVAF.statistics[key] = 0;

        }
    );


    Object.values(
        AVAF.artifacts
    ).forEach(
        function(set) {

            set.clear();

        }
    );

};


/*==========================================================*
 * READY
 *==========================================================*/

console.info(
    "[AVAF]",
    "Runtime Event Bus Ready",
    AVAF.version
);

"""