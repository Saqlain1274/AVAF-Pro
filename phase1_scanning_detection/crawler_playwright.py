"""
===============================================================================
AVAF PRO
Phase 1 - Browser-Observed Behavioral Discovery Engine
===============================================================================

PURPOSE
-------

Phase 1 observes the real application through a real Playwright browser.

The crawler does NOT manufacture application surface.

Everything promoted toward Phase 2 must originate from browser-observed
evidence:

    rendered DOM
    runtime DOM
    runtime JavaScript behaviour
    browser navigation
    browser interaction
    XHR
    fetch
    WebSocket observations
    browser requests/responses
    forms/controls actually rendered
    state transitions
    SPA route changes
    dynamically loaded application data

NO PREDEFINED APPLICATION ROUTES
---------------------------------

This file intentionally contains no:

    /login
    /admin
    /search
    /register
    /dashboard
    /products
    /chat
    /api
    /graphql
    /robots.txt
    /sitemap.xml

as discovery targets.

Those names have no special meaning to the crawler.

A route becomes a crawl target only when the browser actually observes
navigation to it.

NO WORDLISTS
------------

No directory wordlists.
No endpoint fuzzing.
No guessed routes.
No synthetic parameters.
No payload generation.

PHASE SEPARATION
----------------

Phase 1:

    OBSERVE
    CORRELATE
    DISCOVER
    NORMALIZE
    DEDUPLICATE

Phase 2:

    VALIDATE

Phase 3:

    REPORT

Phase 1 does NOT claim that an observation is vulnerable.
===============================================================================
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

from phase1_scanning_detection.runtime import network

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
except ImportError:
    from playwright.async_api import Error as PlaywrightTimeoutError


# -----------------------------------------------------------------------------
# Existing AVAF components
# -----------------------------------------------------------------------------

from phase1_scanning_detection.browser.browser import (
    BrowserManager,
)

from phase1_scanning_detection.QueueManager import (
    QueueManager,
)

from phase1_scanning_detection.deduplication import (
    Deduplicator,
)

from phase1_scanning_detection.decision_Engine import (
    DecisionEngine,
)

from phase1_scanning_detection.discovery.static_dom import (
    StaticDOMExtractor,
)

from phase1_scanning_detection.discovery.collector.runtime_collector import (
    RuntimeCollector,
)

from phase1_scanning_detection.discovery.collector.network_collector import (
    NetworkCollector,
)

from phase1_scanning_detection.discovery.logger import (
    logger,
)

from phase1_scanning_detection.runtime_behavior_processor import (
    RuntimeBehaviorProcessor,
)

from phase1_scanning_detection.workflow_graph import (
    WorkflowGraph,
)

from phase1_scanning_detection.builders.discovery_builder import (
    DiscoveryBuilder,
)

from phase1_scanning_detection.builders.page_builder import (
    PageBuilder,
)

from phase1_scanning_detection.interaction.interactionEngine import (
    InteractionEngine,
)

try:
    from phase1_scanning_detection.screenshot import (
        ScreenshotEngine,
    )
except Exception:
    ScreenshotEngine = None


# =============================================================================
# RESOURCE FILTERING
# =============================================================================
#
# These are presentation/binary resources.
#
# IMPORTANT:
#
# This is NOT endpoint discovery.
#
# It only prevents a PNG/CSS/font/video/etc. from becoming a browser page.
#
# JavaScript is deliberately NOT here.
# JSON is deliberately NOT here.
# API-looking paths are deliberately NOT here.
#
# A JavaScript resource can be important application evidence.
# =============================================================================

STATIC_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".avif",
    ".svg",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".wav",
    ".ogg",
    ".m4a",
    ".mp4",
    ".webm",
    ".mov",
    ".avi",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
}

NON_NAVIGATION_SCHEMES = (
    "javascript:",
    "mailto:",
    "tel:",
    "sms:",
    "data:",
    "blob:",
)


class PlaywrightCrawler:
    """
    AVAF PRO Phase-1 browser-driven discovery orchestrator.

    The crawler is intentionally evidence-first.

    It does not decide that an application has a vulnerability.

    It does not generate routes.

    It does not generate attack payloads.

    It does not perform Phase-2 validation.

    It coordinates the existing AVAF discovery architecture.
    """

    # Keep these public attributes because existing GUI/test code may inspect
    # them directly.

    STATIC_EXTENSIONS = STATIC_EXTENSIONS

    DEFAULT_INTERACTION = {
        "events": [],
        "navigations": [],
        "routes": [],
        "controls": [],
        "forms": [],
        "endpoints": [],
        "parameters": [],
    }

    # =========================================================================
    # CONSTRUCTOR
    # =========================================================================

    def __init__(
        self,
        target: str,
        max_depth: int = 3,
        max_pages: int = 200,
        workers: int = 1,
        headless: bool = True,
        proxy=None,
        progress_callback=None,
        screenshot_callback=None,
    ):
        """
        Prepare Phase-1 state.

        Browser startup is intentionally NOT performed here.
        """

        if not target:
            raise ValueError(
                "PlaywrightCrawler requires a target URL."
            )

        # _canonical_url() may need self.target when resolving
        # relative browser-observed URLs. During construction,
        # self.target does not exist yet, so provide an empty
        # bootstrap value first.
        self.target = ""

        self.target = self._canonical_url(
            target
        )

        if not self.target:
            raise ValueError(
                f"Invalid target URL: {target!r}"
            )

        self.max_depth = max(
            0,
            int(max_depth),
        )

        # ---------------------------------------------------------------------
        # Page-count compatibility
        #
        # Phase 1 has NO predefined page-count quota.
        #
        # The actual number of pages is determined by genuine browser-
        # observed application behavior and queue convergence.
        #
        # This attribute is retained only for compatibility with callers
        # that still pass max_pages.
        # ---------------------------------------------------------------------

        self.max_pages = None

        # ---------------------------------------------------------------------
        # Worker configuration
        #
        # Worker count controls concurrency only.
        # It is NOT a page-count limit.
        # ---------------------------------------------------------------------

        self.workers = max(
            1,
            int(workers),
        )

        self.headless = bool(
            headless
        )

        self.proxy = proxy

        self.progress_callback = (
            progress_callback
        )

        self.screenshot_callback = (
            screenshot_callback
        )
        
        # ---------------------------------------------------------------------
        # Phase-1 crawler output
        #
        # The crawler owns the browser-observed discovery output.
        # The GUI runner remains responsible only for passing the path to
        # ParameterScanner.
        # ---------------------------------------------------------------------
        
        self.output_dir = (
            Path(__file__).resolve().parent
            / "output"
        )
        
        self.discovery_output_file = (
            self.output_dir
            / "url_scan.json"
        )

        # ---------------------------------------------------------------------
        # Browser
        # ---------------------------------------------------------------------

        self.browser = BrowserManager(
            headless=self.headless,
        )

        # ---------------------------------------------------------------------
        # Core architecture
        # ---------------------------------------------------------------------

        self.queue = QueueManager()

        self.deduplicator = Deduplicator()

        # Compatibility alias used by older code.
        self.dedup = self.deduplicator

        self.decision_engine = DecisionEngine()

        self.interaction = self._create_interaction_engine()

        self.runtime_processor = (
            RuntimeBehaviorProcessor()
        )

        self.workflow_graph = (
            WorkflowGraph()
        )

        self.discovery_builder = (
            DiscoveryBuilder()
        )

        self.page_builder = (
            PageBuilder()
        )

        self.screenshot_engine = (
            ScreenshotEngine()
            if ScreenshotEngine is not None
            else None
        )

        # ---------------------------------------------------------------------
        # Crawl state
        # ---------------------------------------------------------------------

        self.running = False

        self.paused = False

        self.stop_requested = False

        # Browser lifecycle state.
        #
        # This is observation state only. It must reflect whether the
        # crawler's BrowserManager has actually been started.
        #
        # Progress calculations may run before browser startup (for example
        # while the initial target is being queued), so this MUST exist from
        # construction time.
        self.browser_started = False

        self.current_page = None
        
        self.current_url = self.target

        self.current_depth = 0

        self.pages_crawled = 0
        
        self.navigation_failures = 0

        self.pages_seen = set()

        self.visited = set()

        self.queued_urls = set()

        self.discovered = set()

        self.results = []

        # Compatibility aliases.
        self.pages = self.results

        # ---------------------------------------------------------------------
        # Real work accounting
        # ---------------------------------------------------------------------

        self._scheduled_work = 0

        self._completed_work = 0

        self._known_work = 0

        self._last_progress = 0

        # ---------------------------------------------------------------------
        # Observation accounting
        # ---------------------------------------------------------------------

        self.pages_discovered = 0

        self.routes_discovered = 0

        self.forms_discovered = 0

        self.controls_discovered = 0

        self.endpoints_discovered = 0

        # ---------------------------------------------------------------------
        # Browser-observed application surface
        # ---------------------------------------------------------------------

        self.observed_routes = set()

        self.observed_navigations = set()
        self.promoted_navigation_candidates = set()

        self.observed_endpoints = set()

        # Browser-observed request parameters.
        #
        # These are collected from actual network endpoint observations.
        # No parameter names are generated or guessed.
        self.observed_parameters = set()
                
        self.external_redirect_sources = set()

        self.interaction_routes = set()

        self.dom_routes = set()

        # Browser-state fingerprints used only to deduplicate screenshots.
        # A state is considered genuinely new when the rendered browser
        # state changes, not merely because InteractionEngine assigned a
        # different state number.
        # Browser-state fingerprints used only to deduplicate screenshots.
        # A state is considered genuinely new when the rendered browser
        # state changes, not because InteractionEngine assigned a number.
        self._captured_state_fingerprints = set()
        self._last_state_fingerprint = ""
        
        # Authoritative numbering for genuinely captured browser states.
        # This is independent from crawler page numbering and from
        # InteractionEngine's internal state numbering.
        self._state_screenshot_counter = 0

        self.forms = []

        self.controls = []

        self.attack_surfaces = []

        # Canonical Phase-1 evidence collection.
        #
        # Interaction evidence is appended here only when it was actually
        # observed by the browser. This is NOT a vulnerability result and
        # does not contain generated payloads or guessed targets.
        #
        # Compatibility alias retained because existing promotion code uses
        # the older attack_surface_candidates name.
        self.attack_surface_candidates = (
            self.attack_surfaces
        )

        # ---------------------------------------------------------------------
        # Runtime observation state
        # ---------------------------------------------------------------------

        self.runtime_events = []

        self.interaction_events = []
        
        self.runtime_artifacts = []
        
        self.network_observations = []

        # ---------------------------------------------------------------------
        # Run lifecycle
        # ---------------------------------------------------------------------

        self._worker_tasks = []

        self._scan_task = None

        self._queue_lock = asyncio.Lock()

        self._state_lock = asyncio.Lock()

        self._started_at = None

        self._finished_at = None

        self.target_reachable = False
        
        self.discovery_completed = False

        # ---------------------------------------------------------------------
        # Interaction callback
        # ---------------------------------------------------------------------

        self._configure_interaction_callback()

        logger.info(
            "CRAWLER",
            (
                "PlaywrightCrawler initialized | "
                f"target={self.target} | "
                f"max_depth={self.max_depth} | "
                f"page_count=browser_observed | "
                f"workers={self.workers}"
            ),
        )

    # =========================================================================
    # INTERACTION ENGINE COMPATIBILITY
    # =========================================================================

    def _create_interaction_engine(self):
            """
            Create the single InteractionEngine used by the active crawler path.
        
            The active InteractionEngine contract is:
                InteractionEngine(queue=None)
        
            No constructor fallbacks are used because they can hide
            incompatible/stale implementations.
            """
        
            try:
                engine = InteractionEngine(
                    queue=self.queue
                )
        
                if engine is None:
                    logger.error(
                        "INTERACTION",
                        "InteractionEngine construction returned None.",
                    )
                    return None
        
                logger.debug(
                    "INTERACTION",
                    (
                        "InteractionEngine created: "
                        f"{type(engine).__module__}."
                        f"{type(engine).__name__}"
                    ),
                )
        
                return engine
        
            except Exception as exc:
        
                logger.error(
                    "INTERACTION",
                    (
                        "Unable to construct InteractionEngine: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )
        
                logger.debug(
                    "INTERACTION",
                    traceback.format_exc(),
                )
        
                return None

    def _configure_interaction_callback(self):
        """
        Configure callbacks between InteractionEngine and crawler.
    
        The crawler remains the owner of:
          - crawl queue decisions
          - page identity
          - screenshot identity
    
        InteractionEngine only reports behavioral evidence.
        """
        if self.interaction is None:
            return
    
        if hasattr(self.interaction, "set_runtime_callback"):
            self.interaction.set_runtime_callback(
                self._interaction_feedback
            )
    
        if hasattr(self.interaction, "set_screenshot_callback"):
            self.interaction.set_screenshot_callback(
                self._interaction_state_screenshot
            )
            
    async def _interaction_feedback(self, event):
        """
        Accept navigation evidence produced during interaction.
    
        Only browser-observed, same-origin navigations are eligible
        for crawl promotion. External destinations are evidence only.
        """
    
        if not isinstance(event, dict):
            return
        
        # -----------------------------------------------------------------
        # EXTERNAL NAVIGATION
        #
        # InteractionEngine reports the real browser transition:
        #
        #     application redirect/source
        #             ->
        #     external destination
        #
        # The source URL must never be promoted as a crawl target.
        # The external destination remains evidence only.
        # -----------------------------------------------------------------
        
        if event.get("type") == "external-navigation":
        
            source_url = event.get(
                "source_url",
                "",
            )
        
            external_url = (
                event.get("url")
                or event.get("target_url")
                or event.get("navigation_url")
                or ""
            )
        
            if isinstance(source_url, str) and source_url.strip():
        
                source_normalized = self._canonical_url(
                    source_url
                )
        
                if source_normalized:
                    self.external_redirect_sources.add(
                        source_normalized
                    )
        
                    logger.info(
                        "DISCOVERY",
                        (
                            "External redirect source recorded; "
                            f"will not be crawled: {source_normalized}"
                        ),
                    )
        
            if isinstance(external_url, str) and external_url.strip():
        
                external_normalized = self._canonical_url(
                    external_url
                )
        
                if external_normalized:
                    self.interaction_routes.add(
                        external_normalized
                    )
        
                    logger.info(
                        "DISCOVERY",
                        (
                            "External browser destination observed; "
                            f"recorded as evidence only: "
                            f"{external_normalized}"
                        ),
                    )
        
            return
        
        observed_url = (
            event.get("url")
            or event.get("target_url")
            or event.get("navigation_url")
            or ""
        )
    
        if not observed_url:
            return
    
        try:
            normalized = self._canonical_url(observed_url)
        except Exception:
            return
    
        if not normalized:
            return
    
        # External browser destinations are evidence only.
        if not self._same_origin(normalized):
            logger.info(
                "DISCOVERY",
                f"External browser destination observed; "
                f"recorded as evidence only: {normalized}"
            )
            self.interaction_routes.add(normalized)
            return
    
        # Never promote static resources into the crawl queue.
        if self._is_static(normalized):
            return
    
        # Already visited.
        if normalized in self.visited:
            return
    
        # -------------------------------------------------------------
        # IMPORTANT:
        #
        # Do NOT enqueue interaction navigation immediately.
        #
        # A browser may transiently expose a same-origin redirect
        # source such as:
        #
        #     /redirect?to=https://external.example
        #
        # before the final external destination is reached.
        #
        # NetworkCollector must first observe the complete HTTP
        # exchange and determine whether this URL is an external
        # redirect source.
        #
        # Therefore interaction feedback records the observation only.
        # _discover_targets() performs the actual queue admission after
        # network evidence has been finalized.
        # -------------------------------------------------------------

        self.observed_navigations.add(
            normalized
        )

        self.interaction_routes.add(
            normalized
        )

        logger.debug(
            "DISCOVERY",
            (
                "Browser navigation recorded for "
                "post-network promotion: "
                f"{normalized}"
            ),
        )
        
    # =========================================================================
    # PUBLIC CONTROL
    # =========================================================================
    
    def start_scan(self):
        """
        Start the Phase-1 browser discovery task.
    
        The caller must invoke this method while an asyncio event
        loop is already running.
    
        This method does not discover URLs itself.
        It only starts the crawler lifecycle. The initial target
        and all later browser-observed targets are handled by _run()
        and the worker/queue pipeline.
        """
    
        if (
            self._scan_task is not None
            and not self._scan_task.done()
        ):
            logger.info(
                "CRAWLER",
                "Scan already running.",
            )
    
            return self._scan_task
    
        try:
            loop = asyncio.get_running_loop()
    
        except RuntimeError as exc:
    
            raise RuntimeError(
                "PlaywrightCrawler.start_scan() must be called "
                "from a running asyncio event loop."
            ) from exc
    
        # ----------------------------------------------------------
        # IMPORTANT
        #
        # Workers use:
        #
        #     while self.running and not self.stop_requested:
        #
        # Therefore running MUST be enabled before _run()
        # creates the workers.
        # ----------------------------------------------------------
    
        self.running = True
        self.stop_requested = False
        self.paused = False
    
        self._scan_task = loop.create_task(
            self._run()
        )
    
        return self._scan_task

    def pause(self):
        self.paused = True

        logger.info(
            "CRAWLER",
            "Pause requested.",
        )

    def resume(self):
        self.paused = False

        logger.info(
            "CRAWLER",
            "Resume requested.",
        )

    def stop(self):
        self.stop_requested = True

    logger.info(
        "CRAWLER",
        "Stop requested.",
    )

    # =========================================================================
    # SAVE DISCOVERY OUTPUT
    # =========================================================================

    def save_discovery_output(
        self,
        path=None,
    ):
        """
        Save the canonical browser-observed Phase-1 discovery output.

        Only real observations already stored in self.results are written.

        This method does NOT:
            - generate URLs
            - generate parameters
            - generate routes
            - create vulnerability findings
            - modify discovery data
        """

        output_path = Path(
            path
            if path is not None
            else self.discovery_output_file
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        pages = []

        for page_result in self.results:

            if page_result is None:
                continue

            if isinstance(
                page_result,
                dict,
            ):
                page_data = page_result

            elif hasattr(
                page_result,
                "to_dict",
            ):
                try:
                    page_data = page_result.to_dict()
                except Exception:
                    continue

            else:
                continue

            if isinstance(
                page_data,
                dict,
            ):
                pages.append(
                    page_data
                )

        payload = {
            "target": self.target,
            "pages_analyzed": pages,
            "pages_crawled": len(pages),
            "discovery_completed": bool(
                self.discovery_completed
            ),
        }

        output_path.write_text(
            json.dumps(
                payload,
                indent=4,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )

        logger.info(
            "OUTPUT",
            (
                "Phase-1 crawler discovery saved | "
                f"pages={len(pages)} | "
                f"path={output_path.resolve()}"
            ),
        )

        return str(
            output_path.resolve()
        )

    # =========================================================================
    # MAIN RUN
    # =========================================================================

    async def _run(self):
        """
        Main Phase-1 lifecycle.

        ONLY the user-supplied target is seeded.

        Every later crawl target must be browser-observed.
        """

        self._started_at = time.monotonic()

        try:

            self._reset_run_state()

           

            # -----------------------------------------------------------------
            # The initial target is the only externally supplied crawl target.
            # -----------------------------------------------------------------

            await self._enqueue_initial_target()

            await self.browser.start()

            self.browser_started = True
            
            self._update_progress()

            await self._worker_loop()

            # -------------------------------------------------------------
            # REAL PHASE-1 DISCOVERY COMPLETION
            #
            # Reaching this point means the worker loop actually returned
            # normally. The browser-observed discovery pipeline has
            # converged and crawler.results is now ready for handoff.
            # -------------------------------------------------------------

            self.discovery_completed = True

        except asyncio.CancelledError:

            logger.info(
                "CRAWLER",
                "Crawler task cancelled.",
            )

            raise

        except Exception as exc:

            logger.error(
                "CRAWLER",
                (
                    f"Fatal crawler error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "CRAWLER",
                traceback.format_exc(),
            )

        finally:

            self.running = False

            self._finished_at = time.monotonic()

            try:
                await self.browser.stop()
            except Exception as exc:
                logger.debug(
                    "BROWSER",
                    (
                        "Browser shutdown failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )
            self.browser_started = False

            summary = self._get_discovery_summary()

            logger.info(
                "CRAWLER",
                (
                    "\n"
                    "============================================================\n"
                    "              AVAF PRO — PHASE 1 SUMMARY\n"
                    "============================================================\n"
                    f"Pages discovered            : {summary['pages']}\n"
                    f"Routes observed             : {summary['routes']}\n"
                    f"Events observed             : {summary['events']}\n"
                    f"Parameters observed         : {summary['parameters']}\n"
                    f"Forms observed              : {summary['forms']}\n"
                    f"Controls observed           : {summary['controls']}\n"
                    f"Network endpoints observed  : {summary['endpoints']}\n"
                    f"Useful vectors observed     : {summary['useful_vectors']}\n"
                    "============================================================\n"
                    f"Scheduled work              : {self._scheduled_work}\n"
                    f"Completed work              : {self._completed_work}\n"
                    "============================================================"
                ),
            )
            
            logger.info(
                "CRAWLER",
                (
                    "Browser discovery complete | "
                    f"pages={len(self.results)} | "
                    f"scheduled={self._scheduled_work} | "
                    f"completed={self._completed_work} | "
                    f"routes={len(self.observed_routes)} | "
                    f"endpoints={self.endpoints_discovered}"
                ),
            )
            
            if self.discovery_completed:
                # 70 is the authoritative Phase-1 handoff boundary.
                # It is emitted only after the worker loop has genuinely
                # converged and browser cleanup has completed.
                self._progress(69)
                self._progress(70)

    def _reset_run_state(self):
        """
        Reset only per-run state.

        Component objects are retained unless their public reset API exists.
        """

        self.results.clear()

        self.pages_seen.clear()

        self.visited.clear()

        self.queued_urls.clear()

        self.discovered.clear()

        self.observed_routes.clear()

        self.observed_navigations.clear()

        self.observed_endpoints.clear()

        self.observed_parameters.clear()
        
        self.external_redirect_sources.clear()
        
        self.interaction_routes.clear()
        
        self.dom_routes.clear()

        self._captured_state_fingerprints.clear()
        self._last_state_fingerprint = ""
        
        # Authoritative numbering for genuinely captured browser states.
        # This is independent of InteractionEngine state labels and
        # has no predefined maximum.
        self._state_screenshot_counter = 0
        
        # State screenshot numbering is per scan run.
        # It is independent from page numbering.
        self._state_screenshot_counter = 0
        
        self.forms.clear()

        self.controls.clear()

        self.attack_surfaces.clear()

        self.runtime_events.clear()

        self.interaction_events.clear()
        
        self.runtime_artifacts.clear()
        
        self.network_observations.clear()

        self.pages_crawled = 0

        self.navigation_failures = 0
        
        self.pages_discovered = 0

        self.routes_discovered = 0

        self.forms_discovered = 0

        self.controls_discovered = 0

        self.endpoints_discovered = 0

        self._scheduled_work = 0

        self._completed_work = 0

        self._known_work = 0

        self._last_progress = 0

        self.target_reachable = False
        
        self.discovery_completed = False

        # Reset project components when supported.

        for component in (
            self.deduplicator,
            self.discovery_builder,
        ):

            reset = getattr(
                component,
                "reset",
                None,
            )

            if reset is None:
                continue

            try:
                reset()
            except Exception as exc:
                logger.debug(
                    "CRAWLER",
                    (
                        f"Component reset failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

    async def _enqueue_initial_target(self):
        """
        Seed exactly one target.

        No common-path expansion occurs here.
        """

        await self._queue_observed_navigation(
            self.target,
            depth=0,
            source="initial_target",
            priority=100,
        )

    # =========================================================================
    # QUEUE
    # =========================================================================

    async def _queue_observed_navigation(
        self,
        url: str,
        depth: int,
        source: str,
        priority: int = 80,
    ) -> bool:
        """
        Queue an application URL only after genuine browser/runtime
        navigation evidence has supplied it.
    
        Phase 1 has NO predefined page-count quota.
    
        A page becomes crawl work only when it is:
    
            browser-observed
            + same-origin
            + non-static/navigable
            + not already queued
            + not already visited
            + within the configured behavioral depth
    
        The number of discovered pages is therefore determined entirely
        by real application behavior.
        """
    
        if self.stop_requested:
            return False
    
        if depth > self.max_depth:
            return False
    
        canonical = self._canonical_url(
            url
        )
    
        if not canonical:
            return False
    
        if not self._same_origin(
            canonical
        ):
            return False
    
        if canonical in self.external_redirect_sources:
            logger.debug(
                "DISCOVERY",
                (
                    "Rejected external-redirect source from "
                    f"crawl queue: {canonical}"
                ),
            )
            return False
    
        if not self._is_navigable_document(
            canonical
        ):
            return False
    
        async with self._queue_lock:
    
            # -------------------------------------------------------------
            # Duplicate protection.
            #
            # These are identity checks only. They do not impose a page
            # quantity limit.
            # -------------------------------------------------------------
    
            if canonical in self.queued_urls:
                return False
    
            if canonical in self.visited:
                return False
    
            # -------------------------------------------------------------
            # Every accepted item represents one piece of REAL browser-
            # observed crawl work.
            # -------------------------------------------------------------
    
            self.queued_urls.add(
                canonical
            )
    
            self.discovered.add(
                canonical
            )
    
            self._scheduled_work += 1
    
            self._known_work = max(
                self._known_work,
                self._scheduled_work,
            )
    
            accepted = self._queue_manager_enqueue(
                canonical,
                depth,
                priority,
            )
    
            if not accepted:
    
                self.queued_urls.discard(
                    canonical
                )
    
                self.discovered.discard(
                    canonical
                )
    
                self._scheduled_work = max(
                    0,
                    self._scheduled_work - 1,
                )
    
                return False
    
        self.pages_discovered = len(
            self.discovered
        )
    
        logger.info(
            "QUEUE",
            (
                "Browser-observed target accepted | "
                f"source={source} | "
                f"url={canonical} | "
                f"depth={depth}"
            ),
        )
    
        self._update_progress()
    
        return True
    
    def _enqueue(
        self,
        url,
        depth,
        priority=0,
    ):
        """
        Synchronous compatibility wrapper.
    
        This method never creates discovery.
    
        If an older AVAF component supplies a URL here, the URL must
        still satisfy the same browser-observation admission rules.
    
        There is NO predefined page-count limit.
        """
    
        canonical = self._canonical_url(
            url
        )
    
        if not canonical:
            return False
    
        if depth > self.max_depth:
            return False
    
        if not self._same_origin(
            canonical
        ):
            return False
    
        if canonical in self.external_redirect_sources:
            return False
    
        if not self._is_navigable_document(
            canonical
        ):
            return False
    
        if canonical in self.queued_urls:
            return False
    
        if canonical in self.visited:
            return False
    
        self.queued_urls.add(
            canonical
        )
    
        self.discovered.add(
            canonical
        )
    
        self._scheduled_work += 1
    
        self._known_work = max(
            self._known_work,
            self._scheduled_work,
        )
    
        accepted = self._queue_manager_enqueue(
            canonical,
            depth,
            priority,
        )
    
        if not accepted:
    
            self.queued_urls.discard(
                canonical
            )
    
            self.discovered.discard(
                canonical
            )
    
            self._scheduled_work = max(
                0,
                self._scheduled_work - 1,
            )
    
            return False
    
        self.pages_discovered = len(
            self.discovered
        )
    
        return True
    
    
    def _queue_is_empty(self):
        """
        Return whether the crawler queue currently contains work.
        """
    
        try:
            return bool(self.queue.empty())
        except Exception:
            return True
    
    
    def _queue_task_done(self):
        """
        Mark the currently processed queue item as completed.
        """
    
        try:
            self.queue.task_done()
        except Exception:
            pass
    
    
    def _queue_manager_enqueue(
        self,
        url,
        depth,
        priority=0,
    ):
        """
        Enqueue only a URL that has already been observed by the
        browser/runtime discovery pipeline.
    
        No URL generation occurs here.
        """
    
        try:
            return self.queue.enqueue(
                url,
                depth,
                priority,
            )
    
        except Exception as exc:
    
            logger.exception(
                "QUEUE",
                (
                    "Queue enqueue failed | "
                    f"url={url} | "
                    f"depth={depth} | "
                    f"error={exc}"
                ),
            )
    
            return 
        
    async def _wait_if_paused(self):
        while self.paused and not self.stop_requested:
            await asyncio.sleep(0.1)
        
    # =========================================================================
    # WORKER LOOP
    # =========================================================================
    
    async def _worker_loop(self):
        """
        Run the browser-discovery workers until the real observed
        crawl work converges.

        There is deliberately NO fixed page-count termination.

        The loop terminates only when QueueManager reports that all
        currently accepted browser-observed work has been completed,
        and no new legitimate browser-observed work remains.
        """

        workers = []

        try:
            worker_count = max(
                1,
                int(self.workers),
            )

            for worker_id in range(
                worker_count
            ):
                workers.append(
                    asyncio.create_task(
                        self._worker(
                            worker_id
                        )
                    )
                )

            if not workers:
                return

            # ---------------------------------------------------------
            # QueueManager owns unfinished-work accounting.
            #
            # Waiting on queue.join() means:
            #
            #     accepted browser-observed work
            #              ↓
            #         actually processed
            #
            # It does NOT mean:
            #
            #     "process N pages".
            # ---------------------------------------------------------

            await self.queue.join()

        except asyncio.CancelledError:
            raise

        finally:

            for task in workers:

                if not task.done():
                    task.cancel()

            if workers:

                await asyncio.gather(
                    *workers,
                    return_exceptions=True,
                )
    
    async def _worker(self, worker_id: int):
        """
        Consume browser-observed crawl work until genuine discovery
        convergence.
    
        IMPORTANT:
    
            There is NO predefined page count.
    
        A page is counted only when _process() confirms that a real
        PageResult was successfully created and stored.
    
        Therefore:
    
            scheduled work != page count
    
        and:
    
            pages_crawled == successfully stored real pages
        """
    
        logger.debug(
            "WORKER",
            f"Worker {worker_id} started.",
        )
    
        while self.running and not self.stop_requested:
    
            await self._wait_if_paused()
    
            if self.stop_requested:
                break
    
            item = await self.queue.dequeue()
    
            if item is None:
                break
    
            url, depth = item
    
            canonical = None
            processed = False
    
            try:
    
                canonical = self._canonical_url(
                    url
                )
    
                if not canonical:
                    continue
    
                if depth > self.max_depth:
                    continue
    
                if not self._same_origin(
                    canonical
                ):
                    continue
    
                if canonical in self.external_redirect_sources:
                    logger.debug(
                        "DISCOVERY",
                        (
                            "Skipping external-redirect source: "
                            f"{canonical}"
                        ),
                    )
                    continue
    
                if not self._is_navigable_document(
                    canonical
                ):
                    continue
    
                # ---------------------------------------------------------
                # Duplicate protection.
                #
                # This does not limit the number of pages.
                # It only prevents processing the same observed page twice.
                # ---------------------------------------------------------
    
                if canonical in self.pages_seen:
                    continue
    
                self.current_url = canonical
                self.current_depth = depth
    
                logger.info(
                    "CRAWLER",
                    (
                        "Processing browser-observed page | "
                        f"depth={depth} | {canonical}"
                    ),
                )
    
                # ---------------------------------------------------------
                # _process() MUST explicitly confirm successful PageResult
                # creation/storage.
                # ---------------------------------------------------------
    
                                # ---------------------------------------------------------
                # _process() is authoritative for page success.
                #
                # True means:
                #
                #     browser session succeeded
                #     +
                #     observations were collected
                #     +
                #     DiscoveryResult/PageResult was created
                #     +
                #     PageResult was committed to self.results
                #
                # False means the target was not successfully processed.
                #
                # A failed/empty _process() must NEVER become a discovered
                # page merely because no exception was raised.
                # ---------------------------------------------------------

                processed = bool(
                    await self._process(
                        canonical,
                        depth,
                    )
                )

                if processed:
                    logger.debug(
                        "WORKER",
                        (
                            "Browser-observed page successfully "
                            f"processed: {canonical}"
                        ),
                    )
                else:
                    logger.warning(
                        "WORKER",
                        (
                            "Browser-observed target failed "
                            f"processing and was not committed: "
                            f"{canonical}"
                        ),
                    )
    
            except asyncio.CancelledError:
                raise
    
            except Exception as exc:
    
                self.navigation_failures += 1
    
                logger.error(
                    "WORKER",
                    (
                        f"Page processing failed for "
                        f"{canonical or url}: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )
    
                logger.debug(
                    "WORKER",
                    traceback.format_exc(),
                )
    
            finally:

                # Every queue item that has been dequeued and reached this
                # finally block is completed work from the queue's perspective.
                #
                # "Completed" does NOT mean that a PageResult was successfully
                # created. Invalid, duplicate, external, or non-navigable work
                # can be intentionally discarded after dequeueing, and that
                # queue item is still finished.
                self._completed_work += 1
            
                self._update_progress()
            
                try:
                    self.queue.task_done()
                except Exception:
                    pass
    
                self.current_url = None
    
        logger.debug(
            "WORKER",
            f"Worker {worker_id} stopped.",
        )

    @staticmethod
    def _decode_queue_item(
        item,
    ):
        """
        Normalize QueueManager's possible item formats.

        This function only interprets queue metadata.
        """

        if item is None:
            return None, None

        if isinstance(
            item,
            dict,
        ):

            url = (
                item.get("url")
                or item.get("target")
            )

            depth = item.get(
                "depth",
                0,
            )

            return url, int(depth)

        if isinstance(
            item,
            (tuple, list),
        ):

            if not item:
                return None, None

            url = item[0]

            depth = (
                item[1]
                if len(item) > 1
                else 0
            )

            return url, int(depth)

        url = getattr(
            item,
            "url",
            None,
        )

        depth = getattr(
            item,
            "depth",
            0,
        )

        return url, int(depth)

    # =========================================================================
    # PAGE PROCESSING
    # =========================================================================

    async def _process(
        self,
        url: str,
        depth: int,
    ):
        """
        Process one browser-observed application target.

        Order:

            Browser
              ↓
            Network capture
              ↓
            Navigation
              ↓
            Rendered DOM
              ↓
            Runtime
              ↓
            Behavior
              ↓
            Interaction
              ↓
            Post-interaction DOM/runtime
              ↓
            Network
              ↓
            Discovery model
              ↓
            PageResult
              ↓
            Browser-observed target promotion
        """

        self.current_url = url

        self.current_depth = depth

        page = None

        network = None

        session = None

        initial_static = None

        final_static = None

        initial_runtime = None

        final_runtime = None

        behavior = self._empty_interaction()

        interaction = self._empty_interaction()

        network_result = None

        response = None

        page_result = None

        try:

            logger.info(
                "CRAWLER",
                (
                    f"[depth={depth}] "
                    f"Opening real browser page: {url}"
                ),
            )

            # =================================================================
            # 1. REAL BROWSER SESSION
            # =================================================================

            session = await self._create_page_session()

            if not session:
                logger.error(
                    "BROWSER",
                    "Unable to create browser session.",
                )
                return False

            page = session.get(
                "page"
            )

            network = session.get(
                "network"
            )
            
            # -----------------------------------------------------------------
            # NETWORK APPLICATION-ORIGIN BOUNDARY
            #
            # NetworkCollector must know which origin belongs to the target
            # application before browser navigation begins.
            #
            # External-origin traffic (GitHub, CDNs, third-party APIs, etc.)
            # may occur because the browser follows a real application action,
            # but that traffic must never become Phase-1 application evidence.
            # -----------------------------------------------------------------
            
            if network is not None:
                set_origin = getattr(network, "set_application_origin", None)
            
                if set_origin is not None:
                    try:
                        set_origin(url)
                    except Exception as exc:
                        logger.debug(
                            "NETWORK",
                            f"Failed to set application origin: {exc}",
                        )

            if page is None:

                logger.error(
                    "BROWSER",
                    "Browser session did not provide a Page.",
                )
            
                return False

            self.current_page = page

            # =================================================================
            # 2. REAL NAVIGATION
            # =================================================================

            response = await self._navigate(
                page,
                url,
            )

            if response is None:

                logger.warning(
                    "NAVIGATION",
                    (
                        f"Browser did not return a response "
                        f"for {url}; page discarded."
                    ),
                )
            
                return False

            try:

                status = int(
                    response.status
                )

            except Exception:

                status = 0

            if status >= 400:

                logger.warning(
                    "NAVIGATION",
                    (
                        f"HTTP {status} for {url}. "
                        "Not treating browser error page as "
                        "application discovery."
                    ),
                )

                return False

            current_url = self._canonical_url(
                getattr(
                    page,
                    "url",
                    url,
                )
            )

            if not current_url:
                return False

            if not self._same_origin(
                current_url
            ):
                logger.warning(
                    "NAVIGATION",
                    (
                        "Browser navigation left application origin: "
                        f"{current_url}"
                    ),
                )
                return False

            if current_url != url:

                self.observed_navigations.add(
                    current_url
                )

                self.observed_routes.add(
                    current_url
                )

            self.current_url = current_url

            logger.info(
                "CRAWLER",
                (
                    f"Rendered application page -> "
                    f"{current_url}"
                ),
            )

            # =================================================================
            # 3. INITIAL RENDERED DOM
            # =================================================================

            initial_static = await self._collect_static(
                page,
                current_url,
            )

            self._record_dom_observations(
                initial_static
            )

            # =================================================================
            # 4. INITIAL RUNTIME
            # =================================================================

            initial_runtime = await self._collect_runtime(
                page,
                current_url,
                session=session,
            )

            self._record_runtime_observations(
                initial_runtime
            )

            logger.info(
                "RUNTIME",
                (
                    "Initial runtime observation complete."
                ),
            )

            # =================================================================
            # 5. RUNTIME BEHAVIOR
            # =================================================================

            behavior = await self._run_behavior(
                page,
                initial_runtime,
            )

            # =================================================================
            # 6. CONTROLLED REAL INTERACTION
            # =================================================================
            #
            # InteractionEngine is responsible for deciding how to explore
            # the currently rendered application state.
            #
            # The crawler does not invent selectors/routes.
            # =================================================================
            # =========================================================
            # INITIAL REAL BROWSER STATE SCREENSHOT
            #
            # Capture before behavioral exploration so an interaction
            # problem can never prevent the genuine page screenshot.
            # =========================================================

            initial_screenshot_path = None

            try:

                page_number = self.pages_crawled + 1

                initial_screenshot_path = await self._capture_screenshot(
                    page=page,
                    url=url,
                    depth=depth,
                    page_number=page_number,
                )
                

                if initial_screenshot_path:

                    logger.info(
                        "SCREENSHOT",
                        (
                            "Captured initial browser state: "
                            f"{page.url}"
                        ),
                    )

            except Exception as exc:

                logger.debug(
                    "SCREENSHOT",
                    (
                        "Initial screenshot skipped: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )
            

            interaction = await self._run_interactions(
                page,
                initial_runtime,
            )

            self._record_interaction_observations(
                interaction
            )
            
            self._promote_interaction_evidence(
                interaction
            )

            # InteractionEngine marks this when a browser action
            # leaves the application's origin.
            external_navigation = bool(
                isinstance(interaction, dict)
                and interaction.get("external_navigation", False)
            )

            if external_navigation:
                external_url = interaction.get(
                    "external_url",
                    "",
                )

                logger.info(
                    "DISCOVERY",
                    (
                        "External browser destination observed; "
                        "recorded as evidence only: "
                        f"{external_url}"
                    ),
                )

                        # =================================================================
            # 7. POST-INTERACTION DOM
            # =================================================================
            #
            # If interaction navigated outside the application origin,
            # the external page is NEVER treated as an AVAF application
            # state.
            #
            # The external destination is already recorded as behavioral
            # evidence by InteractionEngine.
            #
            # Restore the known application page before continuing the
            # crawler lifecycle so PageBuilder, screenshots, attack-surface
            # extraction and target promotion remain application-scoped.
            # =================================================================

            if external_navigation:

                logger.info(
                    "DISCOVERY",
                    (
                        "Interaction left application origin. "
                        "External destination will not be crawled."
                    ),
                )

                try:

                    await page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=30000,
                    )

                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=5000,
                        )
                    except Exception:
                        pass

                    restored_url = self._canonical_url(
                        getattr(
                            page,
                            "url",
                            current_url,
                        )
                    )

                    if (
                        not restored_url
                        or not self._same_origin(restored_url)
                    ):

                        logger.warning(
                            "NAVIGATION",
                            (
                                "Unable to restore application origin "
                                "after external interaction; "
                                "discarding post-interaction state."
                            ),
                        )

                        return

                    current_url = restored_url
                    self.current_url = restored_url

                    logger.info(
                        "DISCOVERY",
                        (
                            "Application state restored after "
                            "external navigation: "
                            f"{restored_url}"
                        ),
                    )

                except Exception as exc:

                    logger.warning(
                        "NAVIGATION",
                        (
                            "Failed to restore application page after "
                            f"external navigation: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )

                    return

            else:

                final_url = self._canonical_url(
                    getattr(
                        page,
                        "url",
                        current_url,
                    )
                )

                if final_url and self._same_origin(
                    final_url
                ):

                    if final_url != current_url:

                        self.observed_navigations.add(
                            final_url
                        )

                        self.observed_routes.add(
                            final_url
                        )

                        self.interaction_routes.add(
                            final_url
                        )

                    current_url = final_url
                    self.current_url = final_url

            # ---------------------------------------------------------------
            # Collect the post-interaction application DOM.
            #
            # This is deliberately performed only while the browser is
            # confirmed to be on the application origin.
            # ---------------------------------------------------------------

            final_static = await self._collect_static(
                page,
                current_url,
            )

            self._record_dom_observations(
                final_static
            )

            # =================================================================
            # 8. POST-INTERACTION RUNTIME
            # =================================================================

            final_runtime = await self._collect_runtime(
                page,
                current_url,
                session=session,
            )

            self._record_runtime_observations(
                final_runtime
            )

            # =================================================================
            # 9. NETWORK
            #
            # Network capture remains alive until AFTER interaction.
            # =================================================================

            network_result = await self._collect_network(
                session
            )

            self._record_network_observations(
                network_result
            )

            # =================================================================
            # 10. SELECT MOST COMPLETE OBSERVATION
            # =================================================================

            static = (
                final_static
                if final_static is not None
                else initial_static
            )

            runtime = (
                final_runtime
                if final_runtime is not None
                else initial_runtime
            )

            # =================================================================
            # 11. DISCOVERY MODEL
            # =================================================================

            discovery = self._build_discovery(
                static,
                runtime,
                network_result,
            )

            if discovery is None:

                logger.error(
                    "DISCOVERY",
                    "DiscoveryBuilder returned None.",
                )
            
                return False

            # =================================================================
            # 12. PAGE RESULT
            # =================================================================

            page_result = await self._build_page(
                page=page,
                response=response,
                url=url,
                depth=depth,
                runtime=runtime,
                discovery=discovery,
                behavior=behavior,
                interaction=interaction,
            )

            if page_result is None:
            
                logger.error(
                    "PAGE",
                    (
                        "PageBuilder returned None; "
                        "page will not be stored."
                    ),
                )
            
                return False

            # =================================================================
            # 13. RUNTIME METADATA
            # =================================================================

            self._update_page_metadata(
                page_result,
                runtime,
            )

            # -----------------------------------------------------------------
            # 14. SCREENSHOT
            #
            # The crawler owns page identity.
            # ScreenshotEngine must use the SAME page number.
            # -----------------------------------------------------------------
            screenshot_path = initial_screenshot_path
            

            if screenshot_path:

                self._attach_screenshot_metadata(
                    page_result,
                    screenshot_path,
                )

                
                self._emit_screenshot(
                    {
                        "url": current_url,
                        "path": screenshot_path,
                        "depth": depth,
                        "page_number": page_number,
                    }
                )

            # =================================================================
            # 15. STORE REAL PAGE
            # =================================================================

            self.results.append(
                page_result
            )
            
            self._progress(
                self._calculate_progress()
            )

            self.pages_crawled += 1

            self.pages_seen.add(
                current_url
            )

            self.target_reachable = True

            logger.info(
                "CRAWLER",
                (
                    f"Stored real discovered page "
                    f"#{self.pages_crawled}: "
                    f"{current_url}"
                ),
            )

            # =================================================================
            # 16. WORKFLOW
            # =================================================================

            self._register_page(
                runtime,
                current_url,
                depth,
            )

            # =================================================================
            # 17. ATTACK-SURFACE OBSERVATIONS
            #
            # This records evidence only.
            #
            # It does NOT validate vulnerabilities.
            # =================================================================

            self._register_attack_surface(
                runtime,
                depth,
                network_result=network_result,
                static=static,
            )

            # =================================================================
            # 18. PROMOTE ONLY BROWSER-OBSERVED NAVIGATION
            # =================================================================

            await self._discover_targets(
                current_url=current_url,
                depth=depth,
                static=static,
                runtime=runtime,
                interaction=interaction,
                page=page,
            )

            self._update_progress()
            
            return True

        except PlaywrightTimeoutError as exc:
        
            logger.warning(
                "NAVIGATION",
                (
                    f"Browser timeout for {url}: "
                    f"{exc}"
                ),
            )
        
            return False
        
        except Exception as exc:
        
            logger.error(
                "PROCESS",
                (
                    f"Page processing failed for {url}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
        
            logger.debug(
                "PROCESS",
                traceback.format_exc(),
            )
        
            return False
        
        finally:
        
            await self._cleanup(
                page,
                network,
            )
        
        return True

    # =========================================================================
    # NAVIGATION
    # =========================================================================

    async def _navigate(
        self,
        page,
        url: str,
    ):
        """
        Navigate only to an already-approved queue target.

        This method never creates alternative URLs.
        """

        logger.info(
            "NAVIGATION",
            f"Browser navigating -> {url}",
        )

        try:

            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30000,
            )

        except PlaywrightTimeoutError:

            logger.warning(
                "NAVIGATION",
                f"Navigation timeout: {url}",
            )

            try:

                await page.wait_for_load_state(
                    "domcontentloaded",
                    timeout=5000,
                )

            except Exception:
                pass

            try:

                current = page.url

            except Exception:

                current = ""

            if current:
                logger.info(
                    "NAVIGATION",
                    f"Browser settled on -> {current}",
                )

            return None

        # Allow application JavaScript to render naturally.
        #
        # This is NOT used to fake progress.
        #
        # It gives the browser a chance to finish normal DOM/runtime work.

        try:

            await page.wait_for_load_state(
                "networkidle",
                timeout=5000,
            )

        except Exception:
            pass

        logger.info(
            "NAVIGATION",
            (
                "Browser navigation complete -> "
                f"{getattr(page, 'url', url)}"
            ),
        )

        return response

    # =========================================================================
    # SESSION
    # =========================================================================

    async def _create_page_session(self):
        """
        Adapt to the existing BrowserManager.

        Preferred:

            BrowserManager.create_page_session()

        Fallback:

            BrowserManager.new_page()

        The fallback creates the existing collector components around that page.
        """

        browser = self.browser

        # ---------------------------------------------------------------------
        # Existing integrated session API
        # ---------------------------------------------------------------------

        for method_name in (
            "create_page_session",
            "create_session",
            "new_page_session",
            "new_session",
        ):

            method = getattr(
                browser,
                method_name,
                None,
            )

            if method is None:
                continue

            try:

                result = method()

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                if isinstance(
                    result,
                    dict,
                ):

                    if result.get(
                        "page"
                    ) is not None:

                        return result

            except TypeError:
                continue

            except Exception as exc:

                logger.debug(
                    "BROWSER",
                    (
                        f"{method_name} failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        # ---------------------------------------------------------------------
        # Page-only fallback
        # ---------------------------------------------------------------------

        page = None

        for method_name in (
            "new_page",
            "create_page",
            "open_page",
        ):

            method = getattr(
                browser,
                method_name,
                None,
            )

            if method is None:
                continue

            try:

                result = method()

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                if result is not None:

                    page = result
                    break

            except TypeError:
                continue

            except Exception as exc:

                logger.debug(
                    "BROWSER",
                    (
                        f"{method_name} failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        if page is None:

            logger.error(
                "BROWSER",
                (
                    "BrowserManager did not expose a usable "
                    "page/session creation API."
                ),
            )

            return None

        # ---------------------------------------------------------------------
        # Attach the existing collectors.
        # ---------------------------------------------------------------------

        network = NetworkCollector()

        runtime = RuntimeCollector()

        try:

            attach = getattr(
                network,
                "attach",
                None,
            )

            if attach is not None:
                result = attach(
                    page
                )

                if inspect.isawaitable(
                    result
                ):
                    await result

        except Exception as exc:

            logger.error(
                "NETWORK",
                (
                    "Network collector attachment failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        try:

            attach = getattr(
                runtime,
                "attach",
                None,
            )

            if attach is not None:
                result = attach(
                    page
                )

                if inspect.isawaitable(
                    result
                ):
                    await result

        except Exception as exc:

            logger.debug(
                "RUNTIME",
                (
                    "Runtime collector attachment failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return {
            "page": page,
            "network": network,
            "runtime": runtime,
        }

    # =========================================================================
    # STATIC DOM
    # =========================================================================

    async def _collect_static(
        self,
        page,
        url,
    ):
        """
        Observe the actual rendered DOM.

        StaticDOMExtractor remains a component of Phase 1.

        IMPORTANT:

        Its links/forms are observations.

        They are NOT automatically converted into crawl targets.
        """

        if page is None:
            return None

        extractor = StaticDOMExtractor()

        try:

            await extractor.attach(
                page
            )

        except Exception as exc:

            logger.error(
                "STATIC",
                (
                    "StaticDOMExtractor attach failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            return None

        try:

            result = extractor.extract(
                url
            )

            if inspect.isawaitable(
                result
            ):
                result = await result

            if result is not None:

                logger.info(
                    "STATIC",
                    (
                        "Rendered DOM observed: "
                        f"{url}"
                    ),
                )

                return result

        except Exception as exc:

            logger.error(
                "STATIC",
                (
                    "Rendered DOM extraction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        # Compatibility with extractors whose extract() only mutates state.

        try:

            builder = getattr(
                extractor,
                "build_result",
                None,
            )

            if builder is not None:

                result = builder()

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                return result

        except Exception as exc:

            logger.error(
                "STATIC",
                (
                    "Static DOM result construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return None

    # =========================================================================
    # RUNTIME
    # =========================================================================

    async def _collect_runtime(
        self,
        page,
        url,
        session=None,
    ):
        """
        Collect runtime artifacts produced by the real browser.

        No endpoint guessing is performed here.

        RuntimeCollector owns the canonical RuntimeResult.
        """

        collector = None

        # ==========================================================
        # GET SESSION RUNTIME COLLECTOR
        # ==========================================================

        if session is not None:

            collector = session.get(
                "runtime"
            )

        # ==========================================================
        # CREATE COLLECTOR WHEN SESSION DOES NOT PROVIDE ONE
        # ==========================================================

        if collector is None:

            collector = RuntimeCollector()

            try:

                attach = getattr(
                    collector,
                    "attach",
                    None,
                )

                if attach is not None:

                    attached = attach(
                        page
                    )

                    if inspect.isawaitable(
                        attached
                    ):
                        await attached

            except Exception as exc:

                logger.error(
                    "RUNTIME",
                    (
                        "Runtime collector attach failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

                logger.debug(
                    "RUNTIME",
                    traceback.format_exc(),
                )

        # ==========================================================
        # COLLECT RUNTIME OBSERVATIONS
        # ==========================================================

        try:

            collect = getattr(
                collector,
                "collect_runtime",
                None,
            )

            if collect is not None:

                collected = collect()

                if inspect.isawaitable(
                    collected
                ):
                    collected = await collected

                # RuntimeCollector.collect_runtime()
                # currently stores the canonical result in
                # collector.result.
                #
                # Prefer an explicitly returned result when
                # available. Otherwise use collector.result.

                result = (
                    collected
                    if collected is not None
                    else getattr(
                        collector,
                        "result",
                        None,
                    )
                )

                if result is not None:

                    return result

        except Exception as exc:

            logger.error(
                "RUNTIME",
                (
                    "Runtime collection failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "RUNTIME",
                traceback.format_exc(),
            )

        # ==========================================================
        # COMPATIBILITY FALLBACK
        # ==========================================================
        #
        # If a collector does not return a result from
        # collect_runtime(), but exposes build_result(),
        # construct the canonical result from it.
        # ==========================================================

        try:

            builder = getattr(
                collector,
                "build_result",
                None,
            )

            if builder is not None:

                result = builder()

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                if result is not None:

                    return result

        except Exception as exc:

            logger.error(
                "RUNTIME",
                (
                    "Runtime result construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "RUNTIME",
                traceback.format_exc(),
            )

        # ==========================================================
        # NO RESULT
        # ==========================================================

        return None
    
    # =========================================================================
    # NETWORK
    # =========================================================================

    async def _collect_network(
        self,
        session,
    ):
        """
        Finalize browser network capture exactly once.

        Interaction-generated requests must already have been captured.
        """

        if not session:
            return None

        collector = session.get(
            "network"
        )

        if collector is None:
            return None

        logger.info(
            "NETWORK",
            "Finalizing complete browser network observation...",
        )

        try:

            stop = getattr(
                collector,
                "stop_capture",
                None,
            )

            if stop is not None:

                result = stop()

                if inspect.isawaitable(
                    result
                ):
                    await result

        except Exception as exc:

            logger.debug(
                "NETWORK",
                (
                    "Network capture stop failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        try:

                        # ==============================================================
            # PRESERVE REAL REDIRECT EVIDENCE BEFORE RETURNING RESULT
            # ==============================================================
            #
            # The redirect-source evidence belongs to NetworkCollector,
            # while build_result() returns NetworkResult.
            #
            # Transfer the browser-observed evidence to the crawler before
            # the collector object is no longer available to the caller.
            #
            # No URL is generated here.
            # ==============================================================

            get_redirect_sources = getattr(
                collector,
                "get_external_redirect_sources",
                None,
            )

            if callable(
                get_redirect_sources
            ):

                try:

                    redirect_sources = (
                        get_redirect_sources()
                    )

                    if redirect_sources:

                        for source_url in redirect_sources:

                            normalized_source = (
                                self._canonical_url(
                                    source_url
                                )
                            )

                            if not normalized_source:
                                continue

                            if not self._same_origin(
                                normalized_source
                            ):
                                continue

                            self.external_redirect_sources.add(
                                normalized_source
                            )

                            logger.info(
                                "DISCOVERY",
                                (
                                    "Browser-observed external redirect "
                                    "source preserved: "
                                    f"{normalized_source}"
                                ),
                            )

                except Exception as exc:

                    logger.debug(
                        "NETWORK",
                        (
                            "External redirect evidence transfer failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )

            builder = getattr(
                collector,
                "build_result",
                None,
            )

            if builder is not None:

                result = builder()

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                return result
            
        except Exception as exc:

            logger.error(
                "NETWORK",
                (
                    "Network result construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return None

    # =========================================================================
    # BEHAVIOR
    # =========================================================================

    async def _run_behavior(
        self,
        page,
        runtime,
    ):
        """
        Interpret already-observed runtime behavior.

        This method does not generate attacks.
        """

        if runtime is None:
            return self._empty_interaction()

        runtime_data = getattr(
            runtime,
            "runtime_data",
            {},
        )

        try:

            process = getattr(
                self.runtime_processor,
                "process",
                None,
            )

            if process is not None:

                result = process(
                    page=page,
                    runtime_data=runtime_data,
                )

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                return (
                    result
                    if result is not None
                    else self._empty_interaction()
                )

            collect = getattr(
                self.runtime_processor,
                "collect",
                None,
            )

            if collect is not None:

                result = collect(
                    page=page,
                    runtime=runtime_data,
                )

                if inspect.isawaitable(
                    result
                ):
                    result = await result

                return (
                    result
                    if result is not None
                    else self._empty_interaction()
                )

        except Exception as exc:

            logger.error(
                "RUNTIME",
                (
                    "Runtime behavior processing failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "RUNTIME",
                traceback.format_exc(),
            )

        return self._empty_interaction()

    # =========================================================================
    # INTERACTION
    # =========================================================================

    async def _run_interactions(
        self,
        page,
        runtime,
    ):
        """
        Run controlled browser interaction discovery.

        InteractionEngine works against the actual rendered application state.

        It is not given generated URLs.

        It is not given endpoint wordlists.

        It is not given synthetic attack payloads.
        """

        if self.interaction is None:

            logger.warning(
                "INTERACTION",
                "InteractionEngine unavailable.",
            )

            return self._empty_interaction()

        logger.info(
            "INTERACTION",
            (
                "Starting real browser behavioral exploration..."
            ),
        )

        try:

            explore = getattr(
                self.interaction,
                "explore",
                None,
            )

            if explore is None:

                logger.warning(
                    "INTERACTION",
                    "InteractionEngine has no explore() method.",
                )

                return self._empty_interaction()

            try:

                result = explore(
                    page=page,
                    decision_engine=self.decision_engine,
                )

            except TypeError:

                result = explore(
                    page,
                    self.decision_engine,
                )

            if inspect.isawaitable(
                result
            ):
                result = await result

            if result is None:

                logger.info(
                    "INTERACTION",
                    (
                        "InteractionEngine reported no "
                        "additional observations."
                    ),
                )

                return self._empty_interaction()

            logger.info(
                "INTERACTION",
                "Behavioral exploration complete.",
            )

            return result

        except Exception as exc:

            logger.error(
                "INTERACTION",
                (
                    "Behavioral exploration failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "INTERACTION",
                traceback.format_exc(),
            )

            # A broken interaction component must not erase observations
            # already collected from the real browser.

            return self._empty_interaction()
        
    def _promote_interaction_evidence(
        self,
        interaction,
    ):
        """
        Promote evidence produced by InteractionEngine into the crawler's
        canonical Phase-1 observation sets.

        Only browser-observed evidence is accepted.

        This method never generates URLs, parameters or endpoints.
        """

        if not isinstance(
            interaction,
            dict,
        ):
            return

        # -------------------------------------------------------------
        # REAL BROWSER NAVIGATIONS
        # -------------------------------------------------------------
        for value in interaction.get(
            "navigations",
            [],
        ) or []:

            normalized = self._canonical_url(
                value
            )

            if not normalized:
                continue

            if not self._same_origin(
                normalized
            ):
                continue

            if self._is_external_redirect_source(
                normalized
            ):
                continue

            self.observed_navigations.add(
                normalized
            )

            self.observed_routes.add(
                normalized
            )

            self.interaction_routes.add(
                normalized
            )

        # -------------------------------------------------------------
        # RUNTIME / NETWORK OBSERVATIONS
        # -------------------------------------------------------------
        for observation in interaction.get(
            "network_observations",
            [],
        ) or []:

            if not isinstance(
                observation,
                dict,
            ):
                continue

            value = observation.get(
                "url",
                "",
            )

            normalized = self._canonical_url(
                value
            )

            if not normalized:
                continue

            if not self._same_origin(
                normalized
            ):
                continue

            self.observed_endpoints.add(
                normalized
            )

        
        
    def _is_external_redirect_source(
        self,
        url,
    ) -> bool:
        """
        Return True when the browser/network layer has already observed
        this application URL as an external redirect source.
    
        Comparison is performed against canonical URL forms and also
        decoded query-string representations so that an observed URL
        such as:
    
            /redirect?to=https://example.com
    
        matches the browser-queued representation:
    
            /redirect?to=https%3A%2F%2Fexample.com
        """
    
        candidate = self._canonical_url(
            url
        )
    
        if not candidate:
            return False
    
        # Direct canonical match.
        if candidate in self.external_redirect_sources:
            return True
    
        try:
            candidate_parsed = urlparse(
                candidate
            )
    
            candidate_pairs = parse_qsl(
                candidate_parsed.query,
                keep_blank_values=True,
            )
    
            for source in self.external_redirect_sources:
    
                source_canonical = self._canonical_url(
                    source
                )
    
                if not source_canonical:
                    continue
    
                source_parsed = urlparse(
                    source_canonical
                )
    
                if (
                    candidate_parsed.scheme.lower()
                    != source_parsed.scheme.lower()
                ):
                    continue
    
                if (
                    (candidate_parsed.hostname or "").lower()
                    != (source_parsed.hostname or "").lower()
                ):
                    continue
    
                if candidate_parsed.port != source_parsed.port:
                    continue
    
                if candidate_parsed.path != source_parsed.path:
                    continue
    
                source_pairs = parse_qsl(
                    source_parsed.query,
                    keep_blank_values=True,
                )
    
                if sorted(candidate_pairs) == sorted(source_pairs):
                    return True
    
        except Exception:
            return False
    
        return False

    # =========================================================================
    # DISCOVERY TARGET PROMOTION
    # =========================================================================

    async def _discover_targets(
        self,
        current_url,
        depth,
        static=None,
        runtime=None,
        interaction=None,
        page=None,
    ):
        """
        Promote ONLY browser-observed application navigations.

        ABSOLUTELY IMPORTANT:

        This method intentionally does NOT inspect:

            static.links
            static.forms
            page.locator("a[href]")
            page.locator("form[action]")
            routerlink
            data-href
            data-url
            data-route

        merely to create crawl targets.

        Those are passive DOM observations.

        A crawl target requires behavioral/navigation evidence.

        Valid sources are:

            1. browser URL after navigation
            2. browser URL after interaction
            3. runtime navigation observations
            4. interaction-engine navigation observations
            5. explicit browser-observed navigation records

        Network API/XHR/fetch endpoints are attack-surface evidence.
        They are NOT automatically page targets.
        """

        if depth >= self.max_depth:
            return

        candidates = set()

        # ---------------------------------------------------------------------
        # 1. CURRENT REAL BROWSER URL
        # ---------------------------------------------------------------------

        if page is not None:

            try:

                if not page.is_closed():

                    browser_url = self._canonical_url(
                        page.url
                    )

                    if (
                        browser_url
                        and browser_url != current_url
                        and self._same_origin(
                            browser_url
                        )
                    ):

                        candidates.add(
                            browser_url
                        )

                        self.observed_navigations.add(
                            browser_url
                        )

            except Exception as exc:

                logger.debug(
                    "DISCOVERY",
                    (
                        "Unable to read browser URL: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        # ---------------------------------------------------------------------
        # 2. RUNTIME NAVIGATION OBSERVATIONS
        # ---------------------------------------------------------------------

        self._extract_observed_navigation_values(
            runtime,
            candidates,
        )

        # ---------------------------------------------------------------------
        # 3. INTERACTION NAVIGATION OBSERVATIONS
        # ---------------------------------------------------------------------

        self._extract_observed_navigation_values(
            interaction,
            candidates,
        )

        # ---------------------------------------------------------------------
        # 4. CRAWLER'S OBSERVED NAVIGATION SET
        # ---------------------------------------------------------------------
        
        # -------------------------------------------------------------
        # Only promote navigation evidence that has survived the
        # completed browser/network observation stage.
        #
        # InteractionEngine may observe a same-origin redirect source
        # before NetworkCollector has completed the redirect chain.
        # external_redirect_sources is therefore authoritative here.
        # -------------------------------------------------------------

                # -------------------------------------------------------------
        # Only process navigation observations that have not already
        # reached the promotion stage.
        # -------------------------------------------------------------

        observed_navigation_candidates = (
            set(self.observed_navigations)
            |
            set(self.interaction_routes)
        )

        candidates.update(
            observed_navigation_candidates
            - self.promoted_navigation_candidates
        )

        # Remove application URLs that the browser/network layer has
        # positively identified as sources of external redirects.
        candidates = {
            candidate
            for candidate in candidates
            if not self._is_external_redirect_source(
                candidate
            )
        }

        # ---------------------------------------------------------------------
        # 5. NORMALIZE AND QUEUE
        # ---------------------------------------------------------------------

        queued = 0

        for candidate in sorted(
            candidates
        ):

            if not isinstance(
                candidate,
                str,
            ):
                continue

            normalized = self._canonical_url(
                candidate
            )

            if not normalized:
                continue
            
            if self._is_external_redirect_source(normalized):
                logger.debug(
                    "DISCOVERY",
                    (
                        "Skipping external-redirect source: "
                        f"{normalized}"
                    ),
                )
                continue

            if not self._same_origin(
                normalized
            ):
                continue

            if not self._is_navigable_document(
                normalized
            ):
                continue

            accepted = await self._queue_observed_navigation(
                normalized,
                depth=depth + 1,
                source="browser_observation",
                priority=90,
            )

            if accepted:
                self.observed_routes.add(
                    normalized
                )

                queued += 1

                logger.info(
                    "DISCOVERY",
                    (
                        "REAL browser navigation queued: "
                        f"{normalized} "
                        f"(depth={depth + 1})"
                    ),
                )
            logger.info(
            "DISCOVERY",
            (
                "Browser-observed target promotion | "
                f"new_observations={len(candidates)} | "
                f"queued={queued}"
            ),
        )

    def _extract_observed_navigation_values(
        self,
        source,
        output,
    ):
        """
        Extract navigation values from explicit observation structures.

        This is deliberately NOT a recursive URL scraper.

        Only navigation-specific fields are accepted.
        """

        if source is None:
            return

        navigation_keys = (
            "navigations",
            "navigation",
            "navigation_url",
            "navigation_urls",
            "observed_navigations",
            "dynamic_navigations",
            "runtime_navigations",
            "observed_routes",
        )

        if isinstance(
            source,
            dict,
        ):

            for key in navigation_keys:

                values = source.get(
                    key
                )

                self._append_navigation_values(
                    values,
                    output,
                )

            runtime_data = source.get(
                "runtime_data"
            )

            if isinstance(
                runtime_data,
                dict,
            ):

                for key in navigation_keys:

                    values = runtime_data.get(
                        key
                    )

                    self._append_navigation_values(
                        values,
                        output,
                    )

            return

        for key in navigation_keys:

            try:

                values = getattr(
                    source,
                    key,
                    None,
                )

            except Exception:

                values = None

            self._append_navigation_values(
                values,
                output,
            )

        runtime_data = getattr(
            source,
            "runtime_data",
            None,
        )

        if isinstance(
            runtime_data,
            dict,
        ):

            for key in navigation_keys:

                self._append_navigation_values(
                    runtime_data.get(
                        key
                    ),
                    output,
                )

    @staticmethod
    def _append_navigation_values(
        values,
        output,
    ):
        """
        Add explicitly reported navigation values.

        No URL extraction from arbitrary strings is performed.
        """

        if values is None:
            return

        if isinstance(
            values,
            str,
        ):

            if values.strip():
                output.add(
                    values.strip()
                )

            return

        if isinstance(
            values,
            dict,
        ):

            for key in (
                "url",
                "final_url",
                "navigation_url",
                "current_url",
            ):

                value = values.get(
                    key
                )

                if isinstance(
                    value,
                    str,
                ) and value.strip():

                    output.add(
                        value.strip()
                    )

            return

        if isinstance(
            values,
            (list, tuple, set),
        ):

            for value in values:

                PlaywrightCrawler._append_navigation_values(
                    value,
                    output,
                )

    # =========================================================================
    # DISCOVERY MODEL
    # =========================================================================

    def _build_discovery(
        self,
        static,
        runtime,
        network,
    ):
        """
        Build the canonical DiscoveryResult.

        DiscoveryBuilder remains the single model integration point.
        """

        try:

            self.discovery_builder.reset()

            self.discovery_builder.add_static_dom(
                static
            )

            self.discovery_builder.add_runtime(
                runtime
            )

            self.discovery_builder.add_network(
                network
            )

            return self.discovery_builder.build()

        except Exception as exc:

            logger.error(
                "DISCOVERY",
                (
                    "DiscoveryResult construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "DISCOVERY",
                traceback.format_exc(),
            )

            return None

    # =========================================================================
    # PAGE BUILDER
    # =========================================================================

    async def _build_page(
        self,
        page,
        response,
        url,
        depth,
        runtime,
        discovery,
        behavior,
        interaction,
    ):
        """
        Build PageResult using the existing PageBuilder.

        The crawler never fabricates vulnerability results here.
        """

        if discovery is None:
            return None

        status = 0

        if response is not None:

            try:
                status = int(
                    response.status
                )
            except Exception:
                status = 0

        title = ""

        final_url = url

        dom_hash = ""

        try:

            title = await page.title()

        except Exception:
            pass

        try:

            final_url = self._canonical_url(
                page.url
            ) or url

        except Exception:
            pass

        if runtime is not None:

            dom_hash = getattr(
                runtime,
                "dom_hash",
                "",
            ) or ""

        metadata = {
            "phase": 1,
            "discovery_mode": "browser_observed",
            "behavior": behavior,
            "interaction": interaction,
            "observed_navigation": (
                final_url
                if final_url != url
                else ""
            ),
        }

        try:

            page_result = self.page_builder.build(
                discovery=discovery,
                url=url,
                final_url=final_url,
                title=title,
                status=status,
                depth=depth,
                html="",
                dom_hash=dom_hash,
                content_hash=dom_hash,
                render_time=0.0,
                metadata=metadata,
            )

            return page_result

        except Exception as exc:

            logger.error(
                "PAGE",
                (
                    "PageBuilder failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            logger.debug(
                "PAGE",
                traceback.format_exc(),
            )

            return None

    # =========================================================================
    # PAGE METADATA
    # =========================================================================

    def _update_page_metadata(
        self,
        page_result,
        runtime,
    ):
        """
        Attach runtime observations through the existing PageResult contract.
        """

        if page_result is None:
            return

        metadata = getattr(
            page_result,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):

            metadata = {}

            try:
                page_result.metadata = metadata
            except Exception:
                return

        runtime_data = getattr(
            runtime,
            "runtime_data",
            {},
        )

        if not isinstance(
            runtime_data,
            dict,
        ):
            runtime_data = {}

        metadata[
            "runtime_artifacts"
        ] = runtime_data.get(
            "artifacts",
            {},
        )

        runtime_events = getattr(
            runtime,
            "events",
            [],
        )

        if not isinstance(
            runtime_events,
            list,
        ):
            runtime_events = []

        metadata[
            "runtime_events"
        ] = runtime_events

        metadata[
            "runtime_data"
        ] = runtime_data
        
        print("\n========== CRAWLER RUNTIME DEBUG ==========", flush=True)
        print(
            "[DEBUG] crawler runtime_data type:",
            type(runtime_data),
            flush=True,
        )
        
        print(
            "[DEBUG] crawler runtime_data keys:",
            list(runtime_data.keys())
            if isinstance(runtime_data, dict)
            else "NOT A DICT",
            flush=True,
        )
        
        print(
            "[DEBUG] crawler runtime_data.parameters:",
            runtime_data.get("parameters")
            if isinstance(runtime_data, dict)
            else "N/A",
            flush=True,
        )
        
        print(
            "[DEBUG] crawler runtime_data.forms:",
            runtime_data.get("forms")
            if isinstance(runtime_data, dict)
            else "N/A",
            flush=True,
        )
        
        print(
            "[DEBUG] crawler runtime_data.controls:",
            runtime_data.get("controls")
            if isinstance(runtime_data, dict)
            else "N/A",
            flush=True,
        )
        
        print("============================================\n", flush=True)

        dom_hash = getattr(
            runtime,
            "dom_hash",
            "",
        )

        if dom_hash:

            metadata[
                "dom_hash"
            ] = dom_hash

    # =========================================================================
    # OBSERVATION REGISTRATION
    # =========================================================================

    def _register_page(
        self,
        runtime,
        url,
        depth,
    ):
        """
        Register the observed browser state in the workflow graph.
        """

        if self.workflow_graph is None:
            return

        dom_hash = getattr(
            runtime,
            "dom_hash",
            "",
        ) if runtime is not None else ""

        register = getattr(
            self.workflow_graph,
            "register_page",
            None,
        )

        if register is None:
            return

        try:

            register(
                url=url,
                dom_hash=dom_hash,
                depth=depth,
            )

        except Exception as exc:

            logger.debug(
                "WORKFLOW",
                (
                    "Workflow page registration failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    def _register_attack_surface(
        self,
        runtime,
        depth,
        network_result=None,
        static=None,
    ):
        """
        Register observed application evidence.

        This is NOT vulnerability validation.

        Phase 1 merely preserves evidence for later validation.
        """

        observations = []

        if runtime is not None:

            runtime_data = getattr(
                runtime,
                "runtime_data",
                {},
            )

            if isinstance(
                runtime_data,
                dict,
            ):

                artifacts = runtime_data.get(
                    "artifacts",
                    {},
                )

                if isinstance(
                    artifacts,
                    dict,
                ):

                    observations.append(
                        artifacts
                    )

        observations.extend(
            (
                static,
                network_result,
            )
        )

        for value in observations:

            self._collect_observed_models(
                value
            )

        self.attack_surfaces.extend(
            self.forms
        )

        self.attack_surfaces.extend(
            self.controls
        )

    def _collect_observed_models(
        self,
        value,
    ):
        """
        Collect model-level observations without generating anything.

        This function does not create URLs or parameters.
        """

        if value is None:
            return

        if isinstance(
            value,
            dict,
        ):

            forms = value.get(
                "forms"
            )

            if isinstance(
                forms,
                list,
            ):

                self.forms.extend(
                    forms
                )

            controls = value.get(
                "controls"
            )

            if isinstance(
                controls,
                list,
            ):

                self.controls.extend(
                    controls
                )

                        # Network endpoints are counted centrally by
            # _record_network_observations().
            #
            # Do not increment endpoints_discovered here because
            # this method may receive the same observation through
            # multiple architecture layers.
            return

        forms = getattr(
            value,
            "forms",
            None,
        )

        if isinstance(
            forms,
            list,
        ):

            self.forms.extend(
                forms
            )

        controls = getattr(
            value,
            "controls",
            None,
        )

        if isinstance(
            controls,
            list,
        ):

            self.controls.extend(
                controls
            )
            
    @staticmethod
    def _observation_key(
        value,
    ):
        """
        Create a stable identity for an observed model.

        This is only used for deduplication.

        It does not create or infer application data.
        """

        if value is None:
            return None

        if isinstance(
            value,
            str,
        ):
            return (
                "str",
                value.strip(),
            )

        if isinstance(
            value,
            dict,
        ):
            try:
                return (
                    "dict",
                    repr(
                        sorted(
                            (
                                str(key),
                                repr(val),
                            )
                            for key, val in value.items()
                        )
                    ),
                )
            except Exception:
                return (
                    "dict",
                    repr(value),
                )

        try:
            data = vars(
                value
            )

            return (
                type(value).__module__,
                type(value).__name__,
                repr(
                    sorted(
                        (
                            str(key),
                            repr(val),
                        )
                        for key, val in data.items()
                    )
                ),
            )

        except Exception:
            return (
                type(value).__module__,
                type(value).__name__,
                repr(value),
            )

    def _extend_unique_observations(
        self,
        destination,
        values,
    ):
        """
        Append only genuinely new observed objects.
        """

        if not isinstance(
            values,
            (list, tuple, set),
        ):
            return

        existing = {
            self._observation_key(
                item
            )
            for item in destination
        }

        for item in values:

            key = self._observation_key(
                item
            )

            if key is None:
                continue

            if key in existing:
                continue

            destination.append(
                item
            )

            existing.add(
                key
            )
            

    def _record_runtime_observations(
        self,
        runtime,
    ):
        """
        Preserve browser-observed runtime evidence.

        Runtime events, DOM forms, DOM controls and DOM parameters
        are observations only.

        IMPORTANT:

            Live-DOM links/routes are NOT promoted to crawl targets.

        A DOM link is passive evidence.

        A crawl route requires an actual browser-observed navigation
        or an explicit runtime navigation observation.
        """

        if runtime is None:
            return

        # =============================================================
        # 1. RUNTIME EVENTS
        # =============================================================

        events = getattr(
            runtime,
            "events",
            [],
        )

        if isinstance(
            events,
            (list, tuple, set),
        ):

            self._extend_unique_observations(
                self.runtime_events,
                events,
            )

        # =============================================================
        # 2. RUNTIME DATA
        # =============================================================

        runtime_data = getattr(
            runtime,
            "runtime_data",
            {},
        )

        if not isinstance(
            runtime_data,
            dict,
        ):
            return

        # =============================================================
        # 3. RUNTIME ARTIFACTS
        # =============================================================

        artifacts = runtime_data.get(
            "artifacts",
            {},
        )

        if not isinstance(
            artifacts,
            dict,
        ):
            artifacts = {}

        if artifacts:

            artifact_key = self._observation_key(
                artifacts
            )

            existing_keys = {
                self._observation_key(
                    item
                )
                for item in self.runtime_artifacts
            }

            if artifact_key not in existing_keys:

                self.runtime_artifacts.append(
                    artifacts
                )

        # =============================================================
        # 4. LIVE RUNTIME DOM
        # =============================================================
        #
        # RuntimeCollector stores the browser-rendered DOM here:
        #
        #     runtime_data["artifacts"]["dom"]
        #
        # These are genuine browser observations.
        # =============================================================

        live_dom = artifacts.get(
            "dom",
            {},
        )

        if not isinstance(
            live_dom,
            dict,
        ):
            return

        # =============================================================
        # 5. FORMS
        # =============================================================

        forms = live_dom.get(
            "forms",
            [],
        )

        if isinstance(
            forms,
            (list, tuple, set),
        ):

            self._extend_unique_observations(
                self.forms,
                forms,
            )

        # =============================================================
        # 6. CONTROLS
        # =============================================================

        controls = live_dom.get(
            "controls",
            [],
        )

        if isinstance(
            controls,
            (list, tuple, set),
        ):

            self._extend_unique_observations(
                self.controls,
                controls,
            )

        # =============================================================
        # 7. OBSERVED PARAMETERS
        # =============================================================
        #
        # RuntimeCollector explicitly extracts:
        #
        #     current URL query parameters
        #     actual form-control names
        #
        # Therefore these are legitimate Phase-1 parameter
        # observations.
        #
        # No parameter names are generated here.
        # =============================================================

        parameters = live_dom.get(
            "parameters",
            [],
        )

        if isinstance(
            parameters,
            (list, tuple, set),
        ):

            for parameter in parameters:

                if isinstance(
                    parameter,
                    dict,
                ):

                    name = str(
                        parameter.get(
                            "parameter",
                            "",
                        )
                        or ""
                    ).strip()

                    location = str(
                        parameter.get(
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                else:

                    name = str(
                        getattr(
                            parameter,
                            "parameter",
                            "",
                        )
                        or ""
                    ).strip()

                    location = str(
                        getattr(
                            parameter,
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                if not name:
                    continue

                self.observed_parameters.add(
                    (
                        name,
                        location,
                    )
                )

        # =============================================================
        # 8. DYNAMIC ROUTES
        # =============================================================
        #
        # DO NOT do:
        #
        #     self.observed_routes.update(live_dom["routes"])
        #
        # because RuntimeCollector's routes are currently derived
        # from rendered <a href> elements.
        #
        # Those are passive DOM links.
        #
        # They are evidence, but they are NOT proof that the browser
        # actually navigated to those destinations.
        #
        # Actual navigation remains handled through:
        #
        #     observed_navigations
        #     interaction_routes
        #     browser page.url
        #
        # We therefore intentionally do nothing with live_dom["routes"].
        # =============================================================

        # =============================================================
        # 9. DIAGNOSTIC COUNTERS
        # =============================================================

        self.forms_discovered = len(
            {
                self._observation_key(item)
                for item in self.forms
                if item is not None
            }
        )

        self.controls_discovered = len(
            {
                self._observation_key(item)
                for item in self.controls
                if item is not None
            }
        )
        
    def _record_interaction_observations(
        self,
        interaction,
    ):
        """
        Preserve interaction observations without turning passive attributes
        into crawl targets.
        """

        if interaction is None:
            return
        
        events = (
            interaction.get(
                "events",
                [],
            )
            if isinstance(
                interaction,
                dict,
            )
            else getattr(
                interaction,
                "events",
                [],
            )
        )

        if isinstance(
            events,
            list,
        ):

            if not hasattr(
                self,
                "interaction_events",
            ):
                self.interaction_events = []

            self._extend_unique_observations(
                self.interaction_events,
                events,
            )

        if isinstance(
            interaction,
            dict,
        ):

            controls = interaction.get(
                "controls",
                [],
            )

            if isinstance(
                controls,
                (list, tuple, set),
            ):
                self._extend_unique_observations(
                    self.controls,
                    controls,
                )
            
            forms = interaction.get(
                "forms",
                []
            )
            
            if isinstance(
                forms,
                (list, tuple, set),
            ):
                self._extend_unique_observations(
                    self.forms,
                    forms,
                )
                
    def _record_dom_observations(
        self,
        static_result,
    ):
        """
        Preserve browser-observed rendered DOM evidence.

        This records only evidence already observed from the rendered
        application DOM. It does not generate routes, endpoints,
        parameters, or attack targets.
        """

        if static_result is None:
            return

        # ---------------------------------------------------------
        # Read the existing static/rendered DOM result.
        # ---------------------------------------------------------
        forms = getattr(
            static_result,
            "forms",
            [],
        )

        controls = getattr(
            static_result,
            "controls",
            [],
        )

        parameters = getattr(
            static_result,
            "parameters",
            [],
        )

        # ---------------------------------------------------------
        # Some project models expose these values as dictionaries.
        # Support both model objects and dictionary observations.
        # ---------------------------------------------------------
        if isinstance(
            static_result,
            dict,
        ):
            forms = static_result.get(
                "forms",
                forms,
            )

            controls = static_result.get(
                "controls",
                controls,
            )

            parameters = static_result.get(
                "parameters",
                parameters,
            )

        # ---------------------------------------------------------
        # Preserve forms.
        # ---------------------------------------------------------
        if isinstance(
            forms,
            (list, tuple, set),
        ):
            self._extend_unique_observations(
                self.forms,
                forms,
            )

        # ---------------------------------------------------------
        # Preserve controls.
        # ---------------------------------------------------------
        if isinstance(
            controls,
            (list, tuple, set),
        ):
            self._extend_unique_observations(
                self.controls,
                controls,
            )

        # ---------------------------------------------------------
        # Preserve parameters that were actually observed in the
        # rendered DOM.
        # ---------------------------------------------------------
        if isinstance(
            parameters,
            (list, tuple, set),
        ):

            for parameter in parameters:

                if isinstance(
                    parameter,
                    dict,
                ):
                    name = str(
                        parameter.get(
                            "parameter",
                            "",
                        )
                        or ""
                    ).strip()

                    location = str(
                        parameter.get(
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                else:
                    name = str(
                        getattr(
                            parameter,
                            "parameter",
                            "",
                        )
                        or ""
                    ).strip()

                    location = str(
                        getattr(
                            parameter,
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                if not name:
                    continue

                self.observed_parameters.add(
                    (
                        name,
                        location,
                    )
                )

        # ---------------------------------------------------------
        # Maintain deduplicated counters.
        # ---------------------------------------------------------
        self.forms_discovered = len(
            {
                self._observation_key(item)
                for item in self.forms
                if item is not None
            }
        )

        self.controls_discovered = len(
            {
                self._observation_key(item)
                for item in self.controls
                if item is not None
            }
        )

    def _record_network_observations(
        self,
        network,
    ):
        """
        Preserve browser-generated network observations.
    
        Network traffic is evidence.
    
        A browser-observed application-origin HTTP redirect whose destination
        leaves the application origin is recorded as external redirect evidence.
    
        The redirect source is NOT promoted to a crawl target.
    
        No route is guessed here.
        """
        
        # ==============================================================
        # REAL PLAYWRIGHT REDIRECT-CHAIN EVIDENCE
        # ==============================================================
        #
        # NetworkCollector observes Playwright's actual
        # request.redirected_from relationship.
        #
        # This catches external redirects even when the Location
        # header is not preserved by the NetworkResponse model.
        # ==============================================================

        get_redirect_sources = getattr(
            network,
            "get_external_redirect_sources",
            None,
        )
        
        # -------------------------------------------------
        # A redirect source may have been observed earlier
        # and temporarily admitted to crawl bookkeeping
        # before the network exchange completed.
        #
        # It is no longer eligible for application crawling.
        # -------------------------------------------------

        

        if callable(
            get_redirect_sources
        ):

            try:

                redirect_sources = (
                    get_redirect_sources()
                )

                if redirect_sources:

                    for source_url in redirect_sources:

                        normalized_source = (
                            self._canonical_url(
                                source_url
                            )
                        )

                        if not normalized_source:
                            continue

                        if not self._same_origin(
                            normalized_source
                        ):
                            continue

                        self.external_redirect_sources.add(
                            normalized_source
                        )

                        logger.info(
                            "DISCOVERY",
                            (
                                "Browser-observed external redirect "
                                "source excluded from crawl targets: "
                                f"{normalized_source}"
                            ),
                        )

            except Exception as exc:

                logger.debug(
                    "DISCOVERY",
                    (
                        "External redirect evidence import failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        # ==============================================================
        # PRESERVE NETWORK OBSERVATION
        # ==============================================================
    
        if network is None:
            return
    
        # ==============================================================
        # PRESERVE NETWORK OBSERVATION
        # ==============================================================
    
        self.network_observations.append(
            network
        )
    
        # ==============================================================
        # REAL APPLICATION-ORIGIN HTTP REDIRECTS
        # ==============================================================
    
        responses = self._get_items(
            network,
            "responses",
        )
    
        for response in responses:
    
            try:
                status = int(
                    getattr(
                        response,
                        "status",
                        0,
                    )
                    or 0
                )
            except Exception:
                status = 0
    
            # Only real HTTP redirects.
            if status < 300 or status >= 400:
                continue
    
            response_url = str(
                getattr(
                    response,
                    "url",
                    "",
                )
                or ""
            ).strip()
    
            if not response_url:
                continue
    
            # Redirect source itself must belong to our application.
            if not self._same_origin(
                response_url
            ):
                continue
    
            # ----------------------------------------------------------
            # Read Location header.
            # ----------------------------------------------------------
    
            headers = getattr(
                response,
                "headers",
                [],
            )
    
            location = ""
    
            if isinstance(
                headers,
                dict,
            ):
    
                for name, value in headers.items():
    
                    if (
                        str(name)
                        .strip()
                        .lower()
                        == "location"
                    ):
    
                        location = str(
                            value
                            or ""
                        ).strip()
    
                        break
    
            elif isinstance(
                headers,
                list,
            ):
    
                for header in headers:
    
                    name = str(
                        getattr(
                            header,
                            "name",
                            "",
                        )
                        or ""
                    ).strip().lower()
    
                    if name != "location":
                        continue
    
                    location = str(
                        getattr(
                            header,
                            "value",
                            "",
                        )
                        or ""
                    ).strip()
    
                    break
    
            if not location:
                continue
    
            # ----------------------------------------------------------
            # Resolve redirect target exactly as the browser would resolve
            # the Location header against the response URL.
            # ----------------------------------------------------------
    
            try:
    
                redirect_target = urljoin(
                    response_url,
                    location,
                )
    
            except Exception:
    
                continue
    
            if not redirect_target:
                continue
    
            # Same-origin redirects are legitimate application navigation.
            if self._same_origin(
                redirect_target
            ):
                continue
    
            # ----------------------------------------------------------
            # External redirect confirmed by browser-observed HTTP data.
            # ----------------------------------------------------------
    
            source_normalized = self._canonical_url(
                response_url
            )
    
            if not source_normalized:
                continue
    
            self.external_redirect_sources.add(
                source_normalized
            )
    
            logger.info(
                "DISCOVERY",
                (
                    "Real external redirect observed; "
                    "source excluded from crawl targets: "
                    f"{source_normalized}"
                ),
            )
        
        # ==============================================================
        # REAL OBSERVED PARAMETER EVIDENCE
        # ==============================================================

        for endpoint in self._get_items(
            network,
            "endpoints",
        ):

            parameters = self._get_items(
                endpoint,
                "parameters",
            )

            for parameter in parameters:

                name = ""

                if isinstance(
                    parameter,
                    dict,
                ):

                    name = str(
                        parameter.get(
                            "name",
                            "",
                        )
                        or ""
                    ).strip()

                else:

                    name = str(
                        getattr(
                            parameter,
                            "name",
                            "",
                        )
                        or ""
                    ).strip()

                if not name:
                    continue

                location = ""

                if isinstance(
                    parameter,
                    dict,
                ):

                    location = str(
                        parameter.get(
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                else:

                    location = str(
                        getattr(
                            parameter,
                            "location",
                            "",
                        )
                        or ""
                    ).strip()

                self.observed_parameters.add(
                    (
                        name,
                        location,
                    )
                )
            
    
        # ==============================================================
        # NETWORK ENDPOINT EVIDENCE
        # ==============================================================
            
        endpoints = self._get_items(
            network,
            "endpoints",
        )
        
        for endpoint in endpoints:
        
            endpoint_url = self._extract_endpoint_url(
                endpoint
            )
        
            if not endpoint_url:
                continue
        
            normalized = self._canonical_url(
                endpoint_url
            )
        
            if not normalized:
                continue
        
            # Endpoints are evidence only.
            # Only same-origin endpoints belong to the application's
            # Phase-1 evidence set.
            if self._same_origin(
                normalized
            ):
        
                self.observed_endpoints.add(
                    normalized
                )
        
        self.endpoints_discovered = len(
            self.observed_endpoints
        )

    # =========================================================================
    # SCREENSHOTS
    # =========================================================================
    
    async def _capture_screenshot(
        self,
        page,
        url,
        depth,
        page_number=None,
    ):
        """
        Capture the currently rendered browser state.
    
        The crawler owns page identity.
        ScreenshotEngine owns screenshot storage.
    
        IMPORTANT:
            ScreenshotEngine.capture() accepts:
    
                page
                url
                page_number
    
            It does NOT accept depth.
    
        Depth remains crawler metadata and is not passed into the
        ScreenshotEngine API.
        """
    
        if self.screenshot_engine is None:
            logger.warning(
                "SCREENSHOT",
                "ScreenshotEngine unavailable.",
            )
            return None
    
        if page is None:
            logger.debug(
                "SCREENSHOT",
                "Capture skipped: page is None.",
            )
            return None
    
        engine = self.screenshot_engine
    
        # -------------------------------------------------------------
        # Use the actual supported screenshot API.
        # -------------------------------------------------------------
    
        capture = getattr(
            engine,
            "capture",
            None,
        )
    
        if capture is None:
            logger.error(
                "SCREENSHOT",
                "ScreenshotEngine has no capture() method.",
            )
            return None
    
        if page_number is None:
            logger.error(
                "SCREENSHOT",
                "Authoritative page number was not supplied.",
            )
            return None
    
        try:
    
            result = capture(
                page=page,
                url=url,
                page_number=page_number,
            )
    
            if inspect.isawaitable(result):
                result = await result
    
            if result:
                logger.debug(
                    "SCREENSHOT",
                    (
                        f"Crawler received screenshot path "
                        f"for page #{page_number}"
                    ),
                )
    
                return str(result)
    
            logger.warning(
                "SCREENSHOT",
                (
                    f"ScreenshotEngine returned no path "
                    f"for page #{page_number}: {url}"
                ),
            )
    
            return None
    
        except Exception as exc:
    
            logger.error(
                "SCREENSHOT",
                (
                    f"Screenshot capture failed for "
                    f"page #{page_number}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
    
            logger.debug(
                "SCREENSHOT",
                traceback.format_exc(),
            )
    
            return None
        
    async def _interaction_state_screenshot(
        self,
        page,
        state_info,
    ):
        """
        Capture a genuinely new rendered browser state.

        State screenshots are NOT crawler pages and do not consume page
        numbers. Identity is derived from the real browser state:
            URL + rendered DOM + selected browser-visible state metadata.

        The InteractionEngine state label is retained as metadata, but it is
        not used as the screenshot identity by itself.
        """

        if self.screenshot_engine is None or page is None:
            return None

        try:
            if page.is_closed():
                return None
        except Exception:
            return None

        if not isinstance(state_info, dict):
            state_info = {}
        
        # InteractionEngine's state_number is metadata only.
        # The crawler owns the authoritative screenshot number.
        state_label = str(
            state_info.get(
                "state",
                "",
            ) or ""
        ).strip()

        try:
            browser_url = str(page.url or self.target)
        except Exception:
            browser_url = self.target

        # -------------------------------------------------------------
        # Capture the actual rendered browser state before screenshot.
        # outerHTML is used only as an observation/fingerprint. It is never
        # promoted to a URL, route, parameter, or attack target.
        # -------------------------------------------------------------
        try:
            await page.wait_for_timeout(150)
        except Exception:
            pass

        try:
            rendered_dom = await page.locator(
                "html"
            ).evaluate(
                "(node) => node ? node.outerHTML : ''"
            )
        except Exception:
            try:
                rendered_dom = await page.content()
            except Exception:
                rendered_dom = ""

        # Include visible text and URL so state changes that are represented
        # outside a small DOM mutation are less likely to collide.
        try:
            visible_text = await page.locator(
                "body"
            ).inner_text(
                timeout=3000
            )
        except Exception:
            visible_text = ""

        state_material = (
            browser_url
            + "\n"
            + rendered_dom
            + "\n"
            + visible_text
        )

        state_hash = hashlib.sha256(
            state_material.encode(
                "utf-8",
                "ignore",
            )
        ).hexdigest()[:16]

        # Do not save duplicate screenshots of the same actual browser state.
        # if state_hash in self._captured_state_fingerprints:
        #     logger.debug(
        #         "SCREENSHOT",
        #         (
        #             "Duplicate browser state screenshot skipped: "
        #             f"{browser_url} [{state_hash}]"
        #         ),
        #     )
        #     return None

        # self._captured_state_fingerprints.add(state_hash)
        # self._last_state_fingerprint = state_hash
        
        # Do not save duplicate screenshots of the same actual browser state.
        if state_hash in self._captured_state_fingerprints:
            logger.debug(
                "SCREENSHOT",
                (
                    "Duplicate browser state screenshot skipped: "
                    f"{browser_url} [{state_hash}]"
                ),
            )
            return None
        
        # The fingerprint is new, therefore this is a genuinely new
        # browser-observed state. Only now assign the next screenshot number.
        self._captured_state_fingerprints.add(state_hash)
        self._last_state_fingerprint = state_hash
        
        # Assign the next number only after this browser state
        # has passed the real fingerprint-based uniqueness check.
        self._state_screenshot_counter += 1
        state_number = self._state_screenshot_counter
        
        self._state_screenshot_counter += 1
        state_number = self._state_screenshot_counter

        filename_url = (
            browser_url.replace("https://", "")
            .replace("http://", "")
        )

        safe_name = "".join(
            ch if ch.isalnum() else "_"
            for ch in filename_url
        ).strip("_") or "application"

        output_dir = self.screenshot_engine.output / "states"
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = output_dir / (
            f"state_{state_number:04d}_"
            f"{safe_name}_"
            f"{state_hash}.png"
        )

        try:
            await page.screenshot(
                path=str(path),
                full_page=True,
                animations="disabled",
            )

            if path.exists():
                logger.info(
                    "SCREENSHOT",
                    (
                        "Captured unique browser state "
                        f"#{state_number}: {browser_url} -> {path}"
                    ),
                )
                return str(path.resolve())

        except Exception as exc:
            # A failed capture must not permanently consume the fingerprint.
            self._captured_state_fingerprints.discard(state_hash)
            
            self._state_screenshot_counter = max(
    0,
                self._state_screenshot_counter - 1,
            )

            logger.debug(
                "SCREENSHOT",
                (
                    "State screenshot failed | "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return None

    @staticmethod
    def _attach_screenshot_metadata(
        page_result,
        screenshot_path,
    ):
        if page_result is None:
            return

        try:
            page_result.screenshot = (
                screenshot_path
            )
        except Exception:
            pass

        metadata = getattr(
            page_result,
            "metadata",
            None,
        )

        if isinstance(
            metadata,
            dict,
        ):

            metadata[
                "screenshot"
            ] = screenshot_path

    def _emit_screenshot(
        self,
        screenshot_record,
    ):
        callback = self.screenshot_callback

        if callback is None:
            return

        try:
            callback(
                screenshot_record
            )
        except Exception as exc:

            logger.debug(
                "SCREENSHOT",
                (
                    "Screenshot callback failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    # =========================================================================
    # CLEANUP
    # =========================================================================

    async def _cleanup(
        self,
        page,
        network,
    ):
        """
        Clean up the page/session.

        BrowserManager owns browser lifecycle.
        """

        if network is not None:

            try:

                stop = getattr(
                    network,
                    "stop_capture",
                    None,
                )

                if stop is not None:

                    result = stop()

                    if inspect.isawaitable(
                        result
                    ):
                        await result

            except Exception as exc:

                logger.debug(
                    "NETWORK",
                    (
                        "Network cleanup failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        if page is not None:

            try:

                if not page.is_closed():

                    close = getattr(
                        self.browser,
                        "close_page",
                        None,
                    )

                    if close is not None:

                        result = close(
                            page
                        )

                        if inspect.isawaitable(
                            result
                        ):
                            await result

                    else:

                        await page.close()

            except Exception as exc:

                logger.debug(
                    "BROWSER",
                    (
                        "Page cleanup failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

        self.current_page = None

    async def _cleanup_page(
        self,
        page,
        network,
    ):
        """
        Compatibility alias.
        """

        await self._cleanup(
            page,
            network,
        )

    # =========================================================================
    # URL NORMALIZATION
    # =========================================================================

    def _canonical_url(
        self,
        url,
    ):
        """
        Canonicalize a URL without inventing anything.

        Query parameters are preserved.

        Their ordering is normalized only for deduplication.
        """

        if not isinstance(
            url,
            str,
        ):
            return ""

        value = url.strip()

        if not value:
            return ""

        parsed = urlparse(
            value
        )

        if not parsed.scheme:

            base_target = getattr(
                self,
                "target",
                "",
            )

            if not base_target:
                return ""

            value = urljoin(
                base_target,
                value,
            )

            parsed = urlparse(
                value
            )

        scheme = parsed.scheme.lower()

        if scheme not in (
            "http",
            "https",
        ):
            return ""

        hostname = (
            parsed.hostname
            or ""
        ).lower()

        if not hostname:
            return ""

        try:

            port = parsed.port

        except ValueError:

            return ""

        if port is None:

            host = hostname

        else:

            host = (
                f"{hostname}:{port}"
            )

        path = parsed.path or "/"

        # Normalize repeated slashes in the path only.
        while "//" in path:

            path = path.replace(
                "//",
                "/",
            )

        query_pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        query_pairs.sort()

        query = urlencode(
            query_pairs,
            doseq=True,
        )

        fragment = parsed.fragment or ""

        return urlunparse(
            (
                scheme,
                host,
                path,
                "",
                query,
                fragment,
            )
        )

    # Compatibility alias.
    def _normalize_url(
        self,
        url,
    ):
        return self._canonical_url(
            url
        )

    def _same_origin(
        self,
        url,
    ):
        try:

            target = urlparse(
                self.target
            )

            candidate = urlparse(
                url
            )

            return (
                target.scheme.lower(),
                target.hostname,
                target.port,
            ) == (
                candidate.scheme.lower(),
                candidate.hostname,
                candidate.port,
            )

        except Exception:

            return False

    def _origin(
        self,
        url,
    ):
        try:

            parsed = urlparse(
                url
            )

            return (
                parsed.scheme.lower(),
                parsed.hostname,
                parsed.port,
            )

        except Exception:

            return None

    # =========================================================================
    # PAGE RESOURCE FILTER
    # =========================================================================

    @classmethod
    def _is_static(
        cls,
        url,
    ):
        """
        Return True only for obvious presentation/binary resources.

        This is NOT a route detector.

        JavaScript and JSON remain eligible observations.
        """

        if not url:
            return True

        try:

            path = (
                urlparse(
                    url
                ).path
                or ""
            ).lower()

        except Exception:

            return False

        for extension in cls.STATIC_EXTENSIONS:

            if path.endswith(
                extension
            ):

                return True

        return False

    def _is_navigable_document(
        self,
        url,
    ):
        """
        Determine whether an observed navigation can reasonably be processed
        as an application document.

        No route semantics are used.
        """

        if not url:
            return False

        lowered = url.lower()

        if lowered.startswith(
            NON_NAVIGATION_SCHEMES
        ):
            return False

        if not self._same_origin(
            url
        ):
            return False

        if self._is_static(
            url
        ):
            return False

        return True

    # =========================================================================
    # OBSERVATION HELPERS
    # =========================================================================

    @staticmethod
    def _get_items(
        value,
        name,
    ):
        """
        Read an existing AVAF model collection.

        Supports both:

            result.items

        and:

            result.<field>

        This method only reads existing browser-observed data.
        It never creates or infers observations.
        """

        if value is None:
            return []

        # -------------------------------------------------------------
        # Dictionary representation
        # -------------------------------------------------------------

        if isinstance(
            value,
            dict,
        ):

            value = value.get(
                name,
                [],
            )

        # -------------------------------------------------------------
        # Object representation
        # -------------------------------------------------------------

        else:

            value = getattr(
                value,
                name,
                [],
            )

        # -------------------------------------------------------------
        # Direct list/tuple
        # -------------------------------------------------------------

        if isinstance(
            value,
            list,
        ):

            return value

        if isinstance(
            value,
            tuple,
        ):

            return list(
                value
            )

        # -------------------------------------------------------------
        # AVAF collection container
        #
        # NetworkResult uses containers such as:
        #
        #     result.endpoints.items
        #     result.requests.items
        #     result.responses.items
        #
        # Therefore the field itself may not be a list.
        # -------------------------------------------------------------

        items = getattr(
            value,
            "items",
            None,
        )

        if isinstance(
            items,
            list,
        ):

            return items

        if isinstance(
            items,
            tuple,
        ):

            return list(
                items
            )

        return []
    
    @staticmethod
    def _extract_endpoint_url(
        endpoint,
    ):
        if endpoint is None:
            return ""

        if isinstance(
            endpoint,
            str,
        ):
            return endpoint

        if isinstance(
            endpoint,
            dict,
        ):

            for key in (
                "url",
                "endpoint",
                "request_url",
            ):

                value = endpoint.get(
                    key
                )

                if isinstance(
                    value,
                    str,
                ) and value.strip():

                    return value.strip()

            return ""

        for key in (
            "url",
            "endpoint",
            "request_url",
        ):

            try:

                value = getattr(
                    endpoint,
                    key,
                    None,
                )

                if isinstance(
                    value,
                    str,
                ) and value.strip():

                    return value.strip()

            except Exception:
                pass

        return ""
    
    # =========================================================================
    # FINAL DISCOVERY SUMMARY
    # =========================================================================

    def _get_discovery_summary(self):
        """
        Build the final Phase-1 discovery summary from real observations.

        No value is hard-coded.

        Useful vectors represent unique actionable/browser-observed
        application surfaces and are NOT calculated by blindly adding
        every counter together.
        """

        routes = len(
            self.observed_routes
        )

        events = (
            len(
                self.runtime_events
            )
            +
            len(
                self.interaction_events
            )
        )

        

        forms = len(
            {
                self._observation_key(item)
                for item in self.forms
                if item is not None
            }
        )

        controls = len(
            {
                self._observation_key(item)
                for item in self.controls
                if item is not None
            }
        )

        parameters = len(
            self.observed_parameters
        )

        endpoints = len(
            self.observed_endpoints
        )

        # Keep public counters synchronized with the authoritative
        # evidence sets.
        self.forms_discovered = forms
        self.controls_discovered = controls
        self.endpoints_discovered = endpoints

        pages = len(
            self.results
        )

        # -------------------------------------------------------------
        # Useful vectors
        #
        # A vector is an actually observed application surface that can
        # carry meaningful Phase-2 evidence.
        #
        # We use unique identities so the same form/control/parameter/
        # endpoint is not counted repeatedly.
        # -------------------------------------------------------------

        useful_vectors = set()

        # Observed application routes.
        for route in self.observed_routes:

            useful_vectors.add(
                (
                    "route",
                    route,
                )
            )

        # Observed forms.
        for form in self.forms:

            useful_vectors.add(
                (
                    "form",
                    self._observation_key(
                        form
                    ),
                )
            )

        # Observed controls.
        for control in self.controls:

            useful_vectors.add(
                (
                    "control",
                    self._observation_key(
                        control
                    ),
                )
            )

        # Observed endpoints.
        for endpoint in self.observed_endpoints:

            useful_vectors.add(
                (
                    "endpoint",
                    endpoint,
                )
            )

        # Observed request parameters.
        for parameter in self.observed_parameters:

            useful_vectors.add(
                (
                    "parameter",
                    parameter,
                )
            )

        return {
            "pages": pages,
            "routes": routes,
            "events": events,
            "parameters": parameters,
            "forms": forms,
            "controls": controls,
            "endpoints": endpoints,
            "useful_vectors": len(
                useful_vectors
            ),
        }

    # =========================================================================
    # PROGRESS
    # =========================================================================

    def _progress(self, value):
        value = max(1, min(70, int(value)))
    
        if value <= getattr(self, "_last_progress", 0):
            return
    
        self._last_progress = value
    
        if self.progress_callback:
            self.progress_callback(value)

    def _update_progress(self):
        if not self.running:
            return
    
        target = int(self._calculate_progress())
        target = max(1, min(70, target))
    
        current = int(getattr(self, "_last_progress", 0))
    
        if target <= current:
            return
    
        for value in range(current + 1, target + 1):
            self._progress(value)

    def _calculate_progress(self):
        """
        Calculate Phase-1 discovery progress from real crawler state.

        Phase 1 owns 0-69%.
        70% is reserved for the explicit discovery-complete handoff.

        Progress is based only on actual browser/crawler observations.
        It does not use elapsed time, artificial increments, or a
        fabricated page quota.
        """

        if not self.running:
            return self._last_progress

        # -------------------------------------------------------------
        # 1. Browser startup
        # -------------------------------------------------------------

        if not self.browser_started:
            return 5

        progress = 8

        # -------------------------------------------------------------
        # 2. Real scheduled browser work
        # -------------------------------------------------------------

        scheduled = max(
            0,
            int(
                getattr(
                    self,
                    "_scheduled_work",
                    0,
                )
                or 0
            ),
        )

        completed = max(
            0,
            int(
                getattr(
                    self,
                    "_completed_work",
                    0,
                )
                or 0
            ),
        )

        if scheduled > 0:
            progress = max(
                progress,
                15,
            )

        if completed > 0:
            progress = max(
                progress,
                25,
            )

        # -------------------------------------------------------------
        # 3. Browser-observed discovery evidence
        # -------------------------------------------------------------

        pages = len(
            getattr(
                self,
                "pages_seen",
                set(),
            )
            or set()
        )

        routes = len(
            getattr(
                self,
                "observed_routes",
                set(),
            )
            or set()
        )

        navigations = len(
            getattr(
                self,
                "observed_navigations",
                set(),
            )
            or set()
        )

        endpoints = len(
            getattr(
                self,
                "observed_endpoints",
                set(),
            )
            or set()
        )

        parameters = len(
            getattr(
                self,
                "observed_parameters",
                set(),
            )
            or set()
        )

        forms = len(
            getattr(
                self,
                "forms",
                [],
            )
            or []
        )

        controls = len(
            getattr(
                self,
                "controls",
                [],
            )
            or []
        )

        runtime_events = len(
            getattr(
                self,
                "runtime_events",
                [],
            )
            or []
        )

        interaction_events = len(
            getattr(
                self,
                "interaction_events",
                [],
            )
            or []
        )

        network_observations = len(
            getattr(
                self,
                "network_observations",
                [],
            )
            or []
        )

        # -------------------------------------------------------------
        # 4. Actual browser observations advance progress
        # -------------------------------------------------------------

        if pages > 0:
            progress = max(
                progress,
                30,
            )

        if runtime_events > 0:
            progress = max(
                progress,
                35,
            )

        if network_observations > 0:
            progress = max(
                progress,
                40,
            )

        if routes > 0 or navigations > 0:
            progress = max(
                progress,
                45,
            )

        if endpoints > 0:
            progress = max(
                progress,
                50,
            )

        if parameters > 0:
            progress = max(
                progress,
                53,
            )

        if forms > 0:
            progress = max(
                progress,
                55,
            )

        if controls > 0:
            progress = max(
                progress,
                57,
            )

        if interaction_events > 0:
            progress = max(
                progress,
                60,
            )

        # -------------------------------------------------------------
        # 5. Additional genuinely discovered pages
        #
        # More pages can increase progress, but there is no target
        # page quota and no artificial percentage-per-page calculation.
        # -------------------------------------------------------------

        if pages > 1:
            progress = max(
                progress,
                min(
                    64,
                    60 + min(
                        4,
                        pages - 1,
                    ),
                ),
            )

        # -------------------------------------------------------------
        # 6. Real crawler convergence
        #
        # 68 means all currently scheduled browser work has completed
        # and the queue is genuinely empty.
        #
        # 69 means the crawler is at the final pre-handoff stage.
        # 70 is emitted only by _run() after discovery completion.
        # -------------------------------------------------------------

        try:
            queue_empty = bool(
                self.queue.empty()
            )

        except Exception:
            queue_empty = False

        if (
            scheduled > 0
            and completed >= scheduled
        ):
            progress = max(
                progress,
                66,
            )

        if (
            queue_empty
            and scheduled > 0
            and completed >= scheduled
        ):
            progress = max(
                progress,
                68,
            )

        return min(
            69,
            max(
                self._last_progress,
                int(progress),
            ),
        )

    # =========================================================================
    # COMPATIBILITY
    # =========================================================================

    def _empty_interaction(self):
        """
        Return a fresh empty observation structure.

        Never return the class-level mutable object directly.
        """

        return {
            key: list(value)
            for key, value
            in self.DEFAULT_INTERACTION.items()
        }

    def _semantic_hash(
        self,
        value,
    ):
        """
        Hash helper retained for compatibility.

        It is an observation fingerprint only.
        """

        if value is None:
            return ""

        if not isinstance(
            value,
            str,
        ):

            value = repr(
                value
            )

        return hashlib.sha256(
            value.encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()

    async def hash(
        self,
        page,
    ):
        """
        Compatibility helper for existing tests.
        """

        if page is None:
            return ""

        try:

            content = await page.content()

        except Exception:

            return ""

        return self._semantic_hash(
            content
        )

    def _attach_screenshot(
        self,
        page_result,
        path,
    ):
        self._attach_screenshot_metadata(
            page_result,
            path,
        )

    # =========================================================================
    # LEGACY DISCOVERY API
    # =========================================================================
    #
    # These methods intentionally do NOTHING unless supplied with actual
    # browser-observed navigation evidence.
    #
    # They are retained so old callers do not accidentally reintroduce static
    # link crawling.
    # =========================================================================

    def _discover_static_links(
        self,
        current_url,
        depth,
        static,
    ):
        """
        Intentionally disabled.

        Passive DOM links are observations, not crawl targets.
        """

        logger.debug(
            "DISCOVERY",
            (
                "Passive static-link promotion disabled by "
                "browser-observed discovery architecture."
            ),
        )

    def _discover_runtime_routes(
        self,
        current_url,
        depth,
        runtime,
    ):
        """
        Only explicit runtime navigation observations are eligible.

        This method does not scan arbitrary runtime artifacts.
        """

        candidates = set()

        self._extract_observed_navigation_values(
            runtime,
            candidates,
        )

        for candidate in candidates:

            normalized = self._canonical_url(
                candidate
            )

            if not normalized:
                continue

            if not self._same_origin(
                normalized
            ):
                continue

            if not self._is_navigable_document(
                normalized
            ):
                continue

            # This legacy method cannot await.
            #
            # Record it for _discover_targets(), which performs the actual
            # asynchronous queue admission.
            self.observed_navigations.add(
                normalized
            )

    def _discover_runtime_pages(
        self,
        depth,
        runtime,
    ):
        """
        Deliberately does not convert arbitrary runtime artifacts into pages.

        Only explicit navigation observations are considered.
        """

        candidates = set()

        self._extract_observed_navigation_values(
            runtime,
            candidates,
        )

        for candidate in candidates:

            normalized = self._canonical_url(
                candidate
            )

            if normalized:
                self.observed_navigations.add(
                    normalized
                )

    def _register_runtime_nodes(
        self,
        depth,
        runtime,
    ):
        """
        Preserve explicit runtime navigation information.

        This method deliberately does NOT treat live-DOM links as
        navigation evidence.

        Runtime DOM routes are currently derived from rendered
        anchor elements, so they remain passive observations.

        Only explicit navigation fields from the runtime export
        may become observed navigation records.
        """

        if runtime is None:
            return

        runtime_data = getattr(
            runtime,
            "runtime_data",
            {},
        )

        if not isinstance(
            runtime_data,
            dict,
        ):
            return

        # -------------------------------------------------------------
        # Explicit runtime navigation observations
        # -------------------------------------------------------------

        candidates = set()

        self._extract_observed_navigation_values(
            runtime_data,
            candidates,
        )

        for route in candidates:

            if not isinstance(
                route,
                str,
            ):
                continue

            normalized = self._canonical_url(
                route
            )

            if not normalized:
                continue

            if not self._same_origin(
                normalized
            ):
                continue

            if not self._is_navigable_document(
                normalized
            ):
                continue

            self.observed_navigations.add(
                normalized
            )

# =============================================================================
# END
# =============================================================================

