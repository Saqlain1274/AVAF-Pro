"""
AVAF Pro
Phase-1 GUI Runner / Backend Bridge

Architecture
------------

GUI
 |
 v
gui_runner.py
 |
 +----> PlaywrightCrawler
 |
 +----> ParameterScanner
 |
 v
GUI stdout protocol


IMPORTANT
---------

This file is ONLY a bridge.

It does NOT:

    - calculate crawler progress
    - calculate scanner progress
    - crawl URLs
    - extract parameters
    - generate candidates
    - invent routes
    - perform attacks
    - implement discovery logic

Progress ownership:

    PlaywrightCrawler : 0 -> 69
    ParameterScanner  : 70 -> 100

The runner only forwards backend progress
through the GUI stdout protocol:

    [PROGRESS] PHASE1 <value>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys


# ==========================================================
# PROJECT PATH
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    BASE_DIR
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(
        0,
        PROJECT_ROOT,
    )


# ==========================================================
# PHASE-1 OUTPUT
# ==========================================================

PHASE1_OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "phase1_scanning_detection",
    "output",
)

DISCOVERY_FILE = os.path.join(
    PHASE1_OUTPUT_DIR,
    "url_scan.json",
)

PARAMETER_FILE = os.path.join(
    PHASE1_OUTPUT_DIR,
    "parameter_candidates.json",
)


# ==========================================================
# PHASE-1 BACKEND
# ==========================================================

from phase1_scanning_detection.crawler_playwright import (
    PlaywrightCrawler,
)

from phase1_scanning_detection.parameter_scanner import (
    ParameterScanner,
)


# ==========================================================
# GUI OUTPUT BRIDGE
# ==========================================================

def emit(message):
    """
    Forward normal backend messages to the GUI.

    No business logic is performed here.
    """

    print(
        str(message),
        flush=True,
    )


# ==========================================================
# PROGRESS BRIDGE
# ==========================================================

def emit_progress(value):
    """
    Forward backend-owned progress to the GUI.

    IMPORTANT:

    This function does NOT calculate progress.

    The backend decides the value.

        Crawler    -> 0..69
        Scanner    -> 70..100

    This function only serializes that value into
    the stdout protocol consumed by the GUI.
    """

    try:
        value = int(value)

    except (
        TypeError,
        ValueError,
    ):
        return

    # Safety boundary only.
    #
    # This is NOT progress calculation.
    value = max(
        0,
        min(
            100,
            value,
        ),
    )

    print(
        f"[PROGRESS] PHASE1 {value}",
        flush=True,
    )


# ==========================================================
# CANONICAL RESULT SERIALIZATION
# ==========================================================

def serialize_page(page):
    """
    Convert crawler PageResult / DiscoveryResult
    into a dictionary for ParameterScanner.

    This is data adaptation only.
    """

    if isinstance(
        page,
        dict,
    ):
        return page

    # ------------------------------------------------------
    # Canonical model conversion
    # ------------------------------------------------------

    if hasattr(
        page,
        "to_dict",
    ):

        try:

            result = page.to_dict()

            if isinstance(
                result,
                dict,
            ):
                return result

        except Exception:
            pass

    # ------------------------------------------------------
    # Dataclass / object compatibility
    # ------------------------------------------------------

    if hasattr(
        page,
        "__dict__",
    ):

        try:

            result = dict(
                page.__dict__
            )

            if isinstance(
                result,
                dict,
            ):
                return result

        except Exception:
            pass

    return None


# ==========================================================
# JSON OUTPUT
# ==========================================================

def save_json(
    path,
    data,
):
    """
    Persist Phase-1 canonical data.

    This function performs no discovery/scanning logic.
    """

    path = os.path.abspath(
        path
    )

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False,
        )


# ==========================================================
# MAIN
# ==========================================================

async def main():

    # ======================================================
    # ARGUMENTS
    # ======================================================

    parser = argparse.ArgumentParser(
        description=(
            "AVAF Pro Phase-1 GUI backend bridge"
        )
    )

    parser.add_argument(
        "--target",
        required=True,
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=2,
    )

    args = parser.parse_args()

    target = (
        args.target
        .strip()
    )

    depth = max(
        0,
        args.depth,
    )


    # ======================================================
    # GUI START
    # ======================================================

    emit(
        "[GUI] Phase-1 Started"
    )

    emit(
        f"[GUI] Target: {target}"
    )

    emit(
        f"[GUI] Depth : {depth}"
    )

    emit(
        "[INFO] Discovering attack surface..."
    )


    # ======================================================
    # CRAWLER
    # ======================================================

    crawler = PlaywrightCrawler(
        target=target,
        max_depth=depth,
        max_pages=60,
        workers=5,

        # --------------------------------------------------
        # IMPORTANT
        #
        # Crawler owns its own progress.
        # Runner only receives and forwards it.
        # --------------------------------------------------

        progress_callback=emit_progress,
    )


    # ======================================================
    # START REAL BROWSER DISCOVERY
    # ======================================================

    emit(
        "[INFO] Starting browser discovery..."
    )

    crawler_results = await crawler.start_scan()

    # --------------------------------------------------
    # CRAWLER -> SCANNER CONTRACT
    # --------------------------------------------------
    #
    # start_scan() is authoritative when it returns the
    # canonical PageResult collection.
    #
    # Fall back to crawler.results only for compatibility
    # with older crawler implementations.
    # --------------------------------------------------

    raw_results = (
        crawler_results
        if isinstance(crawler_results, list)
        else getattr(
            crawler,
            "results",
            [],
        )
    ) or []

    # ======================================================
    # REAL CRAWLER -> SCANNER HANDOFF GATE
    # ======================================================
    #
    # ParameterScanner must receive data only after the
    # browser-discovery lifecycle has completed normally.
    #
    # 70% is therefore a genuine handoff boundary.
    # ======================================================
    
    if not getattr(
        crawler,
        "discovery_completed",
        False,
    ):
    
        emit(
            "[ERROR] Browser discovery did not complete "
            "successfully; ParameterScanner will not run."
        )
    
        emit(
            "[INFO] Phase-1 stopped before parameter extraction."
        )
    
        return []
    
    
    # ======================================================
    # READ CRAWLER RESULTS
    # ======================================================

        # ======================================================
    # USE AUTHORITATIVE CRAWLER RESULT
    # ======================================================
    #
    # start_scan() is the primary source.
    # Only fall back to crawler.results when start_scan()
    # did not return a list.
    #

    pages = []

    for result in raw_results:

        page = serialize_page(
            result
        )

        if not isinstance(
            page,
            dict,
        ):
            continue

        pages.append(
            page
        )


    # ======================================================
    # DISCOVERY OUTPUT
    # ======================================================

    discovery_data = {
        "target": target,
        "pages_analyzed": pages,
    }

    save_json(
        DISCOVERY_FILE,
        discovery_data,
    )

    emit(
        "[INFO] Browser discovery complete: "
        f"{len(pages)} pages"
    )

    emit(
        f"[OUTPUT] Discovery: {DISCOVERY_FILE}"
    )


    # ======================================================
    # CRAWLER -> SCANNER HANDOFF
    # ======================================================

    emit(
        "[INFO] Handing canonical observations "
        "to ParameterScanner..."
    )


    # ======================================================
    # DEBUG OBSERVATION SUMMARY
    # ======================================================

    for index, page in enumerate(
        pages[:3],
        start=1,
    ):

        discovery = (
            page.get(
                "discovery",
                {},
            )
            or {}
        )

        static = (
            discovery.get(
                "static_dom",
                {},
            )
            or {}
        )

        runtime = (
            discovery.get(
                "runtime",
                {},
            )
            or {}
        )

        network = (
            discovery.get(
                "network",
                {},
            )
            or {}
        )

        emit(
            f"[DEBUG] Page {index}: "
            f"url={page.get('url', '')}"
        )

        emit(
            "[DEBUG]   static links="
            f"{len(static.get('links', []) or [])}"
        )

        emit(
            "[DEBUG]   forms="
            f"{len(static.get('forms', []) or [])}"
        )

        emit(
            "[DEBUG]   runtime events="
            f"{len(runtime.get('events', []) or [])}"
        )

        emit(
            "[DEBUG]   network endpoints="
            f"{len(network.get('endpoints', []) or [])}"
        )


    # ======================================================
    # PARAMETER SCANNER
    # ======================================================

    emit(
        "[INFO] Extracting attack vectors..."
    )

    emit(
        "[DEBUG] ParameterScanner execution started."
    )


    scanner = ParameterScanner(
        {
            "target": target,
            "pages_analyzed": pages,
        },

        # --------------------------------------------------
        # Scanner owns 70 -> 100.
        #
        # Runner only forwards the callback.
        # --------------------------------------------------

        progress=emit_progress,
    )


    # ======================================================
    # REAL PARAMETER EXTRACTION
    # ======================================================

    candidates = await scanner.extract_candidates(
        save_to=PARAMETER_FILE,
    )


    if candidates is None:
        candidates = []


    # ======================================================
    # FINAL OUTPUT
    # ======================================================

    emit(
        "[INFO] Pages collected: "
        f"{len(pages)}"
    )

    emit(
        "[INFO] Attack vectors discovered: "
        f"{len(candidates)}"
    )

    emit(
        f"[OUTPUT] Parameters: {PARAMETER_FILE}"
    )

    emit(
        "[DONE] Phase-1 Completed Successfully."
    )

    return candidates


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    try:

        asyncio.run(
            main()
        )

    except KeyboardInterrupt:

        emit(
            "[INFO] Phase-1 cancelled."
        )

    except Exception as exc:

        emit(
            "[ERROR] Phase-1 failed: "
            f"{type(exc).__name__}: {exc}"
        )

        raise