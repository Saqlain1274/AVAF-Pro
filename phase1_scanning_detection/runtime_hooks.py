"""
AVAF Pro
Runtime Hooks Loader

Builds the complete browser runtime instrumentation payload.

The runtime is designed to be safe when Playwright evaluates the
initialization script more than once for the same page.
"""

from phase1_scanning_detection.runtime.event_bus import EVENT_BUS
from phase1_scanning_detection.runtime.network import NETWORK_HOOK
from phase1_scanning_detection.runtime.navigation import NAVIGATION_HOOK
from phase1_scanning_detection.runtime.ui import UI_HOOK
from phase1_scanning_detection.runtime.storage import STORAGE_HOOK
from phase1_scanning_detection.runtime.export import EXPORT_HOOK


# ==========================================================
# RUNTIME MODULE ORDER
# ==========================================================

RUNTIME_MODULES = [
    EVENT_BUS,
    NETWORK_HOOK,
    NAVIGATION_HOOK,
    UI_HOOK,
    STORAGE_HOOK,
    EXPORT_HOOK,
]


# ==========================================================
# BUILD RUNTIME SCRIPT
# ==========================================================

def build_hook_script() -> str:
    """
    Build the complete AVAF browser runtime.

    The guard is important because Playwright may evaluate
    initialization code more than once during a page lifecycle.

    The AVAF runtime itself is stored on window.__AVAF__.
    """

    modules = "\n\n".join(RUNTIME_MODULES)

    return f"""
(() => {{

    "use strict";

    /*
     * ======================================================
     * AVAF RUNTIME INSTALLATION GUARD
     * ======================================================
     *
     * If this page already has the AVAF runtime installed,
     * do not install the complete runtime a second time.
     *
     * This prevents duplicate observers, network hooks,
     * event listeners and runtime initialization.
     */

    if (
        window.__AVAF_RUNTIME_INSTALLED__ === true &&
        window.__AVAF__
    ) {{
        return;
    }}


    /*
     * ======================================================
     * AVAF RUNTIME MODULES
     * ======================================================
     */

{modules}


    /*
     * ======================================================
     * MARK RUNTIME AS INSTALLED
     * ======================================================
     */

    window.__AVAF_RUNTIME_INSTALLED__ = true;


}})();
"""


# ==========================================================
# FINAL HOOK SCRIPT
# ==========================================================

HOOK_SCRIPT = build_hook_script()


# ==========================================================
# VALIDATION
# ==========================================================

if not isinstance(HOOK_SCRIPT, str):
    raise TypeError(
        "AVAF HOOK_SCRIPT must be a string."
    )


if not HOOK_SCRIPT.strip():
    raise RuntimeError(
        "AVAF HOOK_SCRIPT is empty."
    )