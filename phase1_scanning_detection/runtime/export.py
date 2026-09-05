"""
===============================================================================
AVAF PRO

Runtime Export Module

Finalizes the runtime engine and exposes collected behavioural telemetry.

===============================================================================
"""

EXPORT_HOOK = r"""
/*=========================================================================*
* Final Runtime Validation
*=========================================================================*/

if (typeof AVAF.trim === "undefined") {

    AVAF.trim = function () {

        if (
            AVAF.events.length <=
            AVAF.maxEvents
        ) {
            return;
        }

        AVAF.events =
            AVAF.events.slice(
                AVAF.events.length -
                AVAF.maxEvents
            );
    };
}

/*=========================================================================*
* Runtime Ready
*=========================================================================*/

console.info(
    "[AVAF]",
    "Runtime Export Ready",
    AVAF.version
);
"""