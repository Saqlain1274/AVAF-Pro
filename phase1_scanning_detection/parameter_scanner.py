
# """
# AVAF Pro
# Phase-1 Observed Attack-Surface Candidate Extractor

# Architecture
# ------------

# PlaywrightCrawler
#         |
#         v
# Canonical PageResult / DiscoveryResult
#         |
#         +-- rendered DOM
#         +-- forms
#         +-- controls
#         +-- runtime observations
#         +-- browser network observations
#         +-- observed routes
#         |
#         v
# ParameterScanner
#         |
#         v
# parameter_candidates.json
#         |
#         v
# Phase-2 Validation

# IMPORTANT
# ---------
# This module performs discovery normalization only.

# It does NOT:
#     - generate payloads
#     - fuzz parameters
#     - guess URLs
#     - crawl wordlists
#     - attack the target
#     - manufacture routes

# Every candidate must originate from an observation produced by
# the real Playwright browser/crawler.
# """

# from __future__ import annotations

# import asyncio
# from asyncio.log import logger
# import json
# from pathlib import Path
# from urllib.parse import parse_qsl, urlparse


# class ParameterScanner:

#     # =========================================================
#     # STATIC RESOURCE FILTER
#     # =========================================================

#     STATIC_EXTENSIONS = {
#         ".css",
#         ".png",
#         ".jpg",
#         ".jpeg",
#         ".gif",
#         ".webp",
#         ".avif",
#         ".svg",
#         ".ico",
#         ".bmp",
#         ".tif",
#         ".tiff",

#         ".woff",
#         ".woff2",
#         ".woff3",
#         ".ttf",
#         ".otf",
#         ".eot",

#         ".mp3",
#         ".wav",
#         ".ogg",
#         ".m4a",
#         ".mp4",
#         ".webm",
#         ".mov",
#         ".avi",

#         ".zip",
#         ".rar",
#         ".7z",
#         ".tar",
#         ".gz",

#         ".map",
#     }

#     NOISE_PARAMETERS = {
#         "_",
#         "cachebuster",
#         "cache_buster",
#         "cb",
#     }

#     STATIC_RESOURCE_TYPES = {
#         "image",
#         "stylesheet",
#         "font",
#         "media",
#         "manifest",
#         "icon",
#         "texttrack",
#         "websocket",
#     }

#     # =========================================================
#     # INITIALIZATION
#     # =========================================================

#     def __init__(
#         self,
#         scan_data,
#         progress=None,
#     ):

#         self.scan_data = scan_data or {}
#         self.progress = progress

#         self.target_url = str(
#             self.scan_data.get("target")
#             or self.scan_data.get("target_url")
#             or ""
#         ).strip()

#         self.target_origin = self._origin(
#             self.target_url
#         )

#         # Scanner owns 70 -> 100.
#         self.last_progress = 70

#         self.statistics = {
#             "pages": 0,

#             "network_candidates": 0,
#             "form_candidates": 0,
#             "runtime_candidates": 0,
#             "route_candidates": 0,
#             "interaction_candidates": 0,

#             "ignored_static": 0,
#             "ignored_noise": 0,
#             "ignored_external": 0,

#             "duplicates": 0,
#         }

#     # =========================================================
#     # MAIN EXTRACTION
#     # =========================================================

#     async def extract_candidates(
#         self,
#         save_to=None,
#     ):

#         pages = (
#             self.scan_data.get(
#                 "pages_analyzed",
#                 [],
#             )
#             or []
#         )

#         if not isinstance(
#             pages,
#             list,
#         ):
#             pages = []

#         total_pages = len(pages)

#         found = {}

#         # -----------------------------------------------------
#         # NO DISCOVERY
#         # -----------------------------------------------------

#         if not pages:

#             print(
#                 "[INFO] No pages available for parameter extraction.",
#                 flush=True,
#             )
        
#             if save_to:
#                 self._save(
#                     save_to,
#                     [],
#                 )
        
#             # Scanner has completed its work even though
#             # there were no pages to analyze.
#             self._emit_progress(100)
        
#             print(
#                 "[INFO] Candidate extraction completed.",
#                 flush=True,
#             )
        
#             return []

#         print(
#             f"[INFO] Analyzing {total_pages} discovered pages...",
#             flush=True,
#         )

#         # -----------------------------------------------------
#         # PAGE-BY-PAGE OBSERVATION CONSUMPTION
#         # -----------------------------------------------------

#         for index, page in enumerate(
#             pages,
#             start=1,
#         ):

#             if not isinstance(
#                 page,
#                 dict,
#             ):
#                 continue

#             self.statistics["pages"] += 1

#             discovery = self._dict(
#                 page.get(
#                     "discovery",
#                     {},
#                 )
#             )
            
#             # -------------------------------------------------------------
#             # PageResult preserves additional runtime evidence in metadata.
#             # -------------------------------------------------------------
            
#             metadata = self._dict(
#                 page.get(
#                     "metadata",
#                     {},
#                 )
#             )
            
#             metadata = self._dict(
#                 page.get(
#                     "metadata",
#                     {},
#                 )
#             )
            
#             static = self._dict(
#                 discovery.get(
#                     "static_dom",
#                     {},
#                 )
#             )
            
#             runtime = self._dict(
#                 discovery.get(
#                     "runtime",
#                     {},
#                 )
#             )
            
#             # -------------------------------------------------------------
#             # PageResult preserves the browser-observed runtime export
#             # inside metadata["runtime_data"].
#             #
#             # Use it only when the canonical discovery runtime is missing
#             # or incomplete.
#             #
#             # Nothing is generated here.
#             # -------------------------------------------------------------
            
#             metadata_runtime = self._dict(
#                 metadata.get(
#                     "runtime_data",
#                     {},
#                 )
#             )
            
#             if metadata_runtime:
            
#                 if not runtime:
#                     runtime = metadata_runtime
            
#                 else:
#                     # Preserve the canonical runtime object, but expose the
#                     # browser-observed artifact collections when they are
#                     # absent from the canonical representation.
#                     if (
#                         "artifacts" not in runtime
#                         and "artifacts" in metadata_runtime
#                     ):
#                         runtime["artifacts"] = metadata_runtime[
#                             "artifacts"
#                         ]
            
#                     if (
#                         "events" not in runtime
#                         and "events" in metadata_runtime
#                     ):
#                         runtime["events"] = metadata_runtime[
#                             "events"
#                         ]
            
#                     if (
#                         "parameters" not in runtime
#                         and "parameters" in metadata_runtime
#                     ):
#                         runtime["parameters"] = metadata_runtime[
#                             "parameters"
#                         ]
            
#                     if (
#                         "forms" not in runtime
#                         and "forms" in metadata_runtime
#                     ):
#                         runtime["forms"] = metadata_runtime[
#                             "forms"
#                         ]
            
#                     if (
#                         "controls" not in runtime
#                         and "controls" in metadata_runtime
#                     ):
#                         runtime["controls"] = metadata_runtime[
#                             "controls"
#                         ]
            
#             network = self._dict(
#                 discovery.get(
#                     "network",
#                     {},
#                 )
#             )
            
#             # =============================================================
#             # BEHAVIOR / INTERACTION OBSERVATIONS
#             # =============================================================
#             #
#             # DiscoveryResult normally contains:
#             #
#             #     static_dom
#             #     runtime
#             #     network
#             #
#             # PageBuilder additionally preserves browser-observed behavior
#             # and interaction results in PageResult.metadata.
#             #
#             # Therefore metadata is used as the fallback source for these
#             # observation streams.
#             #
#             # Nothing is generated here. We only consume observations
#             # already produced by the browser.
#             # =============================================================
            
#             behavior = self._dict(
#                 discovery.get(
#                     "behavior",
#                     metadata.get(
#                         "behavior",
#                         page.get(
#                             "behavior",
#                             {},
#                         ),
#                     ),
#                 )
#             )
            
#             interaction = self._dict(
#                 discovery.get(
#                     "interaction",
#                     metadata.get(
#                         "interaction",
#                         page.get(
#                             "interaction",
#                             {},
#                         ),
#                     ),
#                 )
#             )
            
#             page_url = str(
#                 page.get(
#                     "final_url"
#                 )
#                 or page.get(
#                     "url"
#                 )
#                 or ""
#             ).strip()
            
#             # =============================================================
#             # SCANNER PROGRESS
#             # =============================================================
#             #
#             # ParameterScanner owns the real 70 -> 100 handoff.
#             #
#             # Each discovered page is genuine scanner work.
#             #
#             # The percentage calculation determines how far the scanner
#             # has progressed, while _emit_progress() is responsible for
#             # emitting every missing integer in sequence.
#             #
#             # 70 = crawler handoff
#             # 71..99 = actual candidate processing
#             # 100 = scanner genuinely complete
#             # =============================================================

#             if total_pages > 0:

#                 target_progress = (
#                     70
#                     + int(
#                         (
#                             index
#                             / total_pages
#                         ) * 29
#                     )
#                 )

#                 target_progress = max(
#                     70,
#                     min(
#                         99,
#                         target_progress,
#                     ),
#                 )

#                 self._emit_progress(
#                     target_progress
#                 )
                
#             # =================================================
#             # A. REAL PAGE URL
#             # =================================================

#             if page_url:

#                 self._consume_url(
#                     found,
#                     page_url,
#                     source="observed-page-url",
#                 )

#             # =================================================
#             # B. NETWORK OBSERVATIONS
#             # =================================================

#             network_items = []

#             for key in (
#                 "endpoints",
#                 "requests",
#                 "observed_endpoints",
#                 "observed_requests",
#             ):

#                 network_items.extend(
#                     self._items(
#                         network.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for endpoint in network_items:

#                 self._consume_endpoint(
#                     found,
#                     endpoint,
#                 )

#             # =================================================
#             # C. RENDERED DOM FORMS
#             # =================================================

#             form_items = []

#             for key in (
#                 "forms",
#                 "rendered_forms",
#                 "observed_forms",
#             ):

#                 form_items.extend(
#                     self._items(
#                         static.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for form in form_items:

#                 self._consume_form(
#                     found,
#                     form,
#                     source="rendered-dom-form",
#                     page_url=page_url,
#                 )

#             # =================================================
#             # D. RUNTIME FORMS
#             # =================================================

#             runtime_forms = []

#             for key in (
#                 "runtime_forms",
#                 "forms",
#                 "observed_forms",
#                 "form_controls",
#             ):

#                 runtime_forms.extend(
#                     self._items(
#                         runtime.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for form in runtime_forms:

#                 self._consume_form(
#                     found,
#                     form,
#                     source="runtime-form",
#                     page_url=page_url,
#                 )

#                        # =================================================
#             # E. PASSIVE RENDERED DOM LINKS
#             # =================================================
#             #
#             # These remain browser-observed evidence, but they
#             # are NOT candidate routes.
#             #
#             # A DOM href does not prove that the browser actually
#             # navigated to that URL.
#             #
#             # Actual navigation candidates come from:
#             #
#             #   - browser-observed page URL
#             #   - InteractionEngine navigation evidence
#             #
#             # Do not promote passive href values here.
#             # =================================================
            
#             # =================================================
#             # F. RUNTIME ROUTES
#             # =================================================

#             # =================================================
#             # F. RUNTIME NAVIGATION EVIDENCE
#             # =================================================
#             #
#             # Runtime DOM route collections may contain passive
#             # href observations. They are not promoted.
#             #
#             # Only an explicitly recorded navigation event is
#             # eligible here.
#             # =================================================

#             runtime_navigations = self._items(
#                 runtime.get(
#                     "navigations",
#                     [],
#                 )
#             )

#             for navigation in runtime_navigations:

#                 route_url = self._value(
#                     navigation,
#                     "url",
#                     "destination",
#                     "target",
#                 )

#                 if not route_url and isinstance(
#                     navigation,
#                     str,
#                 ):
#                     route_url = navigation

#                 if not route_url:
#                     continue

#                 before = len(found)

#                 self._consume_url(
#                     found,
#                     route_url,
#                     source="browser-observed-navigation",
#                     base_url=page_url,
#                 )

#                 if len(found) > before:

#                     self.statistics[
#                         "runtime_candidates"
#                     ] += 1
#             # =================================================
#             # G. INTERACTION ROUTES
#             # =================================================

#             interaction_routes = []

#             for key in (
#                 "routes",
#                 "navigations",
#                 "observed_routes",
#                 "navigation_routes",
#             ):

#                 interaction_routes.extend(
#                     self._items(
#                         interaction.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for route in interaction_routes:

#                 route_url = self._value(
#                     route,
#                     "url",
#                     "href",
#                     "route",
#                     "target",
#                     "destination",
#                 )

#                 if not route_url and isinstance(
#                     route,
#                     str,
#                 ):
#                     route_url = route

#                 if route_url:

#                     before = len(found)

#                     self._consume_url(
#                         found,
#                         route_url,
#                         source="interaction-route",
#                         base_url=page_url,
#                     )

#                     if len(found) > before:

#                         self.statistics[
#                             "interaction_candidates"
#                         ] += 1

#             # =================================================
#             # H. RUNTIME CONTROLS / INPUTS
#             # =================================================

#             controls = []

#             for key in (
#                 "controls",
#                 "inputs",
#                 "interactive_elements",
#                 "observed_inputs",
#                 "form_controls",
#             ):

#                 controls.extend(
#                     self._items(
#                         runtime.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for control in controls:

#                 self._consume_control(
#                     found,
#                     control,
#                     page_url,
#                     source="runtime-control",
#                 )
                
#             # =================================================
#             # H.1 RUNTIME DOM PARAMETERS
#             # =================================================
#             #
#             # RuntimeCollector records actual browser-observed
#             # parameters under:
#             #
#             #     runtime["artifacts"]["dom"]["parameters"]
#             #
#             # These are legitimate observations because they came
#             # from the rendered browser state.
#             #
#             # Do NOT infer parameter names from runtime events,
#             # JavaScript text, labels, or arbitrary strings.
#             # =================================================
            
#             runtime_artifacts = self._dict(
#                 runtime.get(
#                     "artifacts",
#                     {},
#                 )
#             )
            
#             runtime_dom = self._dict(
#                 runtime_artifacts.get(
#                     "dom",
#                     {},
#                 )
#             )
            
            
            
#             runtime_parameters = self._items(
#                 runtime_dom.get(
#                     "parameters",
#                     [],
#                 )
#             )
            
#             for parameter in runtime_parameters:
            
#                 if isinstance(
#                     parameter,
#                     dict,
#                 ):
            
#                     name = self._value(
#                         parameter,
#                         "parameter",
#                         "name",
#                     )
            
#                     value = self._value(
#                         parameter,
#                         "value",
#                         "default_value",
#                     )
            
#                     location = self._value(
#                         parameter,
#                         "location",
#                     ) or "runtime"
            
#                     method = self._value(
#                         parameter,
#                         "method",
#                     ) or "GET"
            
#                     url = self._value(
#                         parameter,
#                         "url",
#                         "page_url",
#                     ) or page_url
            
#                 else:
            
#                     name = self._value(
#                         parameter,
#                         "parameter",
#                         "name",
#                     )
            
#                     value = ""
            
#                     location = "runtime"
#                     method = "GET"
#                     url = page_url
            
#                 if not name:
#                     continue
            
#                 normalized_url = self._normalize_url(
#                     url,
#                     page_url,
#                 )
            
#                 if not normalized_url:
#                     continue
            
#                 before = len(found)
            
#                 self._add(
#                     found,
#                     url=normalized_url,
#                     method=method,
#                     name=name,
#                     value=value,
#                     location=location,
#                     source="runtime-dom-parameter",
#                     data_type="string",
#                     candidate_type="runtime-input",
#                 )
            
#                 if len(found) > before:
            
#                     self.statistics[
#                         "runtime_candidates"
#                     ] += 1


#             # =================================================
#             # H.2 RUNTIME DOM FORMS
#             # =================================================
#             #
#             # RuntimeCollector may preserve forms inside the live
#             # runtime DOM artifact.
#             #
#             # These are browser-observed forms only.
#             # Nothing is generated or guessed here.
#             # =================================================

#             runtime_dom_forms = self._items(
#                 runtime_dom.get(
#                     "forms",
#                     [],
#                 )
#             )

#             for form in runtime_dom_forms:

#                 self._consume_form(
#                     found,
#                     form,
#                     source="runtime-dom-form",
#                     page_url=page_url,
#                 )

#             # =================================================
#             # I. BEHAVIOR OBSERVATIONS
#             # =================================================

#             behavior_items = []

#             for key in (
#                 "routes",
#                 "navigations",
#                 "requests",
#                 "endpoints",
#                 "inputs",
#                 "controls",
#                 "forms",
#             ):

#                 behavior_items.extend(
#                     self._items(
#                         behavior.get(
#                             key,
#                             [],
#                         )
#                     )
#                 )

#             for item in behavior_items:

#                 self._consume_behavior(
#                     found,
#                     item,
#                     page_url,
#                 )

#             # =================================================
#             # REAL PAGE PROGRESS
#             #
#             # 70 = scanner started
#             # 99 = all pages consumed and candidate list ready
#             # 100 = JSON successfully saved
#             # =================================================

#             target = (
#                 70
#                 + int(
#                     (
#                         index
#                         / total_pages
#                     ) * 29
#                 )
#             )

#             target = max(
#                 70,
#                 min(
#                     99,
#                     target,
#                 ),
#             )

#             self._emit_progress(
#                 target
#             )

#             print(
#                 f"[INFO] [SCANNER] "
#                 f"Page {index}/{total_pages} -> "
#                 f"{len(found)} observed candidates",
#                 flush=True,
#             )

#             # Give the event loop a chance to process GUI output.
#             await asyncio.sleep(0)

#         # =====================================================
#         # FINAL DEDUPLICATION
#         # =====================================================

#         candidates = list(
#             found.values()
#         )

#         unique = {}

#         for candidate in candidates:

#             if not isinstance(
#                 candidate,
#                 dict,
#             ):
#                 continue

#             candidate_type = str(
#                 candidate.get(
#                     "candidate_type",
#                     "observed-input",
#                 )
#             ).strip().lower()

#             url = str(
#                 candidate.get(
#                     "url",
#                     "",
#                 )
#             ).strip()

#             method = str(
#                 candidate.get(
#                     "method",
#                     "GET",
#                 )
#             ).upper()

#             location = str(
#                 candidate.get(
#                     "location",
#                     "",
#                 )
#             ).strip().lower()

#             parameter = str(
#                 candidate.get(
#                     "parameter",
#                     "",
#                 )
#             ).strip().lower()

#             # Routes are allowed to have no parameter.
#             if candidate_type == "observed-route":

#                 signature = (
#                     candidate_type,
#                     method,
#                     url,
#                     location,
#                 )

#             else:

#                 if not parameter:

#                     continue

#                 signature = (
#                     candidate_type,
#                     method,
#                     url,
#                     location,
#                     parameter,
#                 )

#             if signature in unique:

#                 self.statistics[
#                     "duplicates"
#                 ] += 1

#                 continue

#             unique[
#                 signature
#             ] = candidate

#         candidates = list(
#             unique.values()
#         )

#         # =====================================================
#         # SORT
#         # =====================================================

#         candidates.sort(
#             key=lambda item: (
#                 str(
#                     item.get(
#                         "url",
#                         "",
#                     )
#                 ),
#                 str(
#                     item.get(
#                         "method",
#                         "GET",
#                     )
#                 ),
#                 str(
#                     item.get(
#                         "location",
#                         "",
#                     )
#                 ),
#                 str(
#                     item.get(
#                         "parameter",
#                         "",
#                     )
#                 ),
#             )
#         )
        
#         # =========================================================
#         # FINALIZATION
#         # =========================================================
#         #
#         # 99 = all real observations processed.
#         #
#         # 100 is emitted ONLY after:
#         #   1. candidates constructed
#         #   2. duplicates removed
#         #   3. candidates sorted
#         #   4. output successfully saved
#         # =========================================================
        
#         self.last_progress = max(
#             self.last_progress,
#             99,
#         )
        
#         self._emit_progress(
#             self.last_progress
#         )     
        
#         # =========================================================
#         # SAVE FINAL CANDIDATES
#         # =========================================================
        
#         if save_to:
        
#             self._save(
#                 save_to,
#                 candidates,
#             )
        
#         # =============================================================
#         # FINALIZATION
#         # =============================================================
#         #
#         # At this point:
#         #
#         #   - all pages have been analyzed
#         #   - all observations have been processed
#         #   - candidates have been finalized
#         #   - statistics are complete
#         #
#         # 96-99 are optional final scanner states.
#         # 100 is emitted ONLY after the scanner has genuinely finished.
#         # =============================================================
        
#         for value in (
#             96,
#             97,
#             98,
#             99,
#         ):
#             if value > self.last_progress:
#                 self._emit_progress(
#                     value
#                 )
        
        
#         # =============================================================
#         # SUMMARY
#         # =============================================================
        
#         print(
#             "",
#             flush=True,
#         )
        
#         print(
#             "========== PHASE-1 SCANNER ==========",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Pages analyzed: "
#             f"{self.statistics['pages']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Network vectors: "
#             f"{self.statistics['network_candidates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Form vectors: "
#             f"{self.statistics['form_candidates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Runtime vectors: "
#             f"{self.statistics['runtime_candidates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Route vectors: "
#             f"{self.statistics['route_candidates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Interaction vectors: "
#             f"{self.statistics['interaction_candidates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Ignored static: "
#             f"{self.statistics['ignored_static']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Ignored noise: "
#             f"{self.statistics['ignored_noise']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] External observations ignored: "
#             f"{self.statistics['ignored_external']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Duplicates merged: "
#             f"{self.statistics['duplicates']}",
#             flush=True,
#         )
        
#         print(
#             f"[INFO] Useful observed candidates: "
#             f"{len(candidates)}",
#             flush=True,
#         )
        
#         print(
#             "=====================================",
#             flush=True,
#         )
        
        
#         # =============================================================
#         # SCANNER COMPLETE
#         # =============================================================
#         #
#         # NOTHING BELOW THIS LINE SHOULD PERFORM SCANNER WORK.
#         #
#         # 100 means extract_candidates() has genuinely completed.
#         # =============================================================
        
#         self._emit_progress(
#             100
#         )
        
#         print(
#             "[INFO] Candidate extraction completed.",
#             flush=True,
#         )
        
#         return candidates

#     # =========================================================
#     # GENERIC HELPERS
#     # =========================================================

#     @staticmethod
#     def _dict(value):

#         return (
#             value
#             if isinstance(
#                 value,
#                 dict,
#             )
#             else {}
#         )

#     @staticmethod
#     def _items(value):

#         if value is None:
#             return []

#         if isinstance(
#             value,
#             dict,
#         ):

#             for key in (
#                 "items",
#                 "values",
#                 "data",
#                 "results",
#             ):

#                 nested = value.get(
#                     key
#                 )

#                 if isinstance(
#                     nested,
#                     list,
#                 ):

#                     return nested

#             return [value]

#         if isinstance(
#             value,
#             (list, tuple, set),
#         ):

#             return list(value)

#         return [value]

#     @staticmethod
#     def _value(
#         item,
#         *keys,
#     ):

#         if isinstance(
#             item,
#             str,
#         ):

#             return item

#         if not isinstance(
#             item,
#             dict,
#         ):

#             return ""

#         for key in keys:

#             value = item.get(
#                 key
#             )

#             if value not in (
#                 None,
#                 "",
#             ):

#                 return str(
#                     value
#                 ).strip()

#         return ""

#     @staticmethod
#     def _origin(url):

#         try:

#             parsed = urlparse(
#                 str(url)
#             )

#             if not parsed.hostname:
#                 return None

#             return (
#                 parsed.scheme.lower(),
#                 parsed.hostname.lower(),
#                 parsed.port
#                 or (
#                     443
#                     if parsed.scheme.lower()
#                     == "https"
#                     else 80
#                 ),
#             )

#         except Exception:

#             return None

#     # =========================================================
#     # URL VALIDATION
#     # =========================================================

#     def _normalize_url(
#         self,
#         url,
#         base_url="",
#     ):

#         if not url:
#             return ""

#         url = str(
#             url
#         ).strip()

#         if url.startswith(
#             ("#", "javascript:", "mailto:", "tel:")
#         ):
#             return ""

#         try:

#             parsed = urlparse(
#                 url
#             )

#             if not parsed.scheme:

#                 if base_url:

#                     from urllib.parse import urljoin

#                     url = urljoin(
#                         base_url,
#                         url,
#                     )

#                     parsed = urlparse(
#                         url
#                     )

#             if not parsed.scheme or not parsed.netloc:

#                 return ""

#             normalized = parsed.geturl()

#         except Exception:

#             return ""

#         # -----------------------------------------------------
#         # Same-origin only
#         # -----------------------------------------------------

#         if self.target_origin:

#             if self._origin(
#                 normalized
#             ) != self.target_origin:

#                 self.statistics[
#                     "ignored_external"
#                 ] += 1

#                 return ""

#         # -----------------------------------------------------
#         # Static resources are never application routes
#         # -----------------------------------------------------

#         path = (
#             parsed.path
#             or ""
#         ).lower()

#         if any(
#             path.endswith(
#                 extension
#             )
#             for extension in self.STATIC_EXTENSIONS
#         ):

#             self.statistics[
#                 "ignored_static"
#             ] += 1

#             return ""

#         return normalized

#     # =========================================================
#     # URL CONSUMPTION
#     # =========================================================

#     def _consume_url(
#         self,
#         found,
#         url,
#         source,
#         base_url="",
#     ):

#         normalized = self._normalize_url(
#             url,
#             base_url,
#         )

#         if not normalized:
#             return

#         parsed = urlparse(
#             normalized
#         )

#         # -----------------------------------------------------
#         # Query parameters
#         # -----------------------------------------------------

#         try:

#             parameters = parse_qsl(
#                 parsed.query,
#                 keep_blank_values=True,
#             )

#         except Exception:

#             parameters = []

#         for name, value in parameters:

#             name = str(
#                 name
#                 or ""
#             ).strip()

#             if not name:
#                 continue

#             before = len(
#                 found
#             )

#             self._add(
#                 found,
#                 url=normalized,
#                 method="GET",
#                 name=name,
#                 value=value,
#                 location="query",
#                 source=source,
#                 data_type="string",
#                 candidate_type="observed-parameter",
#             )

#             if len(found) > before:

#                 self.statistics[
#                     "route_candidates"
#                 ] += 1

#         # -----------------------------------------------------
#         # REAL ROUTE
#         #
#         # A route itself is useful to Phase-2 even if it has no
#         # query parameter.
#         # -----------------------------------------------------

#         before = len(
#             found
#         )

#         self._add(
#             found,
#             url=normalized,
#             method="GET",
#             name="",
#             value="",
#             location="path",
#             source=source,
#             data_type="route",
#             candidate_type="observed-route",
#         )

#         if len(found) > before:

#             self.statistics[
#                 "route_candidates"
#             ] += 1

#     # =========================================================
#     # NETWORK ENDPOINT
#     # =========================================================

#     def _consume_endpoint(
#         self,
#         found,
#         endpoint,
#     ):

#         if not isinstance(
#             endpoint,
#             dict,
#         ):
#             return

#         resource_type = str(
#             endpoint.get(
#                 "resource_type",
#                 endpoint.get(
#                     "type",
#                     "",
#                 ),
#             )
#         ).lower().strip()

#         if resource_type in self.STATIC_RESOURCE_TYPES:

#             self.statistics[
#                 "ignored_static"
#             ] += 1

#             return

#         url = self._value(
#             endpoint,
#             "url",
#             "request_url",
#             "href",
#             "endpoint",
#             "route",
#         )

#         if not url:
#             return

#         normalized = self._normalize_url(
#             url
#         )

#         if not normalized:
#             return

#         method = str(
#             endpoint.get(
#                 "method",
#                 "GET",
#             )
#             or "GET"
#         ).upper()

#         # -----------------------------------------------------
#         # Query parameters in observed network request
#         # -----------------------------------------------------

#         parsed = urlparse(
#             normalized
#         )

#         for name, value in parse_qsl(
#             parsed.query,
#             keep_blank_values=True,
#         ):

#             before = len(
#                 found
#             )

#             self._add(
#                 found,
#                 url=normalized,
#                 method=method,
#                 name=name,
#                 value=value,
#                 location="query",
#                 source="browser-network",
#                 data_type="string",
#                 candidate_type="network-parameter",
#             )

#             if len(found) > before:

#                 self.statistics[
#                     "network_candidates"
#                 ] += 1

#         # -----------------------------------------------------
#         # Observed route itself
#         # -----------------------------------------------------

#         before = len(
#             found
#         )

#         self._add(
#             found,
#             url=normalized,
#             method=method,
#             name="",
#             value="",
#             location="network",
#             source="browser-network",
#             data_type="route",
#             candidate_type="observed-route",
#         )

#         if len(found) > before:

#             self.statistics[
#                 "network_candidates"
#             ] += 1

#     # =========================================================
#     # FORM
#     # =========================================================

#     def _consume_form(
#         self,
#         found,
#         form,
#         source,
#         page_url="",
#     ):

#         if not isinstance(
#             form,
#             dict,
#         ):
#             return

#         action = self._value(
#             form,
#             "action",
#             "url",
#             "target",
#             "endpoint",
#         )

#         if not action:
#             action = page_url

#         action = self._normalize_url(
#             action,
#             page_url,
#         )

#         if not action:
#             return

#         method = str(
#             form.get(
#                 "method",
#                 "GET",
#             )
#             or "GET"
#         ).upper()

#         controls = []

#         for key in (
#             "inputs",
#             "controls",
#             "fields",
#             "elements",
#             "form_controls",
#         ):

#             controls.extend(
#                 self._items(
#                     form.get(
#                         key,
#                         [],
#                     )
#                 )
#             )

#         # Some DOM extractors expose individual collections.
#         for key in (
#             "selects",
#             "textareas",
#             "buttons",
#         ):

#             controls.extend(
#                 self._items(
#                     form.get(
#                         key,
#                         [],
#                     )
#                 )
#             )

#         for control in controls:

#             if not isinstance(
#                 control,
#                 dict,
#             ):
#                 continue

#             name = self._value(
#                 control,
#                 "name",
#                 "parameter",
#                 "param",
#                 "formcontrolname",
#                 "formControlName",
#                 "id",
#             )

#             if not name:
#                 continue

#             value = self._value(
#                 control,
#                 "value",
#                 "default_value",
#                 "selected_value",
#             )

#             data_type = self._value(
#                 control,
#                 "type",
#                 "input_type",
#             ) or "string"

#             before = len(
#                 found
#             )

#             self._add(
#                 found,
#                 url=action,
#                 method=method,
#                 name=name,
#                 value=value,
#                 location="form",
#                 source=source,
#                 data_type=data_type,
#                 candidate_type="form-input",
#             )

#             if len(found) > before:

#                 self.statistics[
#                     "form_candidates"
#                 ] += 1

#     # =========================================================
#     # RUNTIME CONTROL
#     # =========================================================

#     def _consume_control(
#         self,
#         found,
#         control,
#         page_url,
#         source,
#     ):

#         if not isinstance(
#             control,
#             dict,
#         ):
#             return

#         name = self._value(
#             control,
#             "name",
#             "parameter",
#             "param",
#             "formcontrolname",
#             "formControlName",
#             "id",
#             "aria_label",
#             "aria-label",
#         )

#         if not name:
#             return

#         url = self._value(
#             control,
#             "url",
#             "action",
#             "target",
#             "endpoint",
#         ) or page_url

#         url = self._normalize_url(
#             url,
#             page_url,
#         )

#         if not url:
#             return

#         value = self._value(
#             control,
#             "value",
#             "default_value",
#             "selected_value",
#         )

#         before = len(
#             found
#         )

#         self._add(
#             found,
#             url=url,
#             method=str(
#                 control.get(
#                     "method",
#                     "GET",
#                 )
#                 or "GET"
#             ).upper(),
#             name=name,
#             value=value,
#             location="runtime",
#             source=source,
#             data_type=self._value(
#                 control,
#                 "type",
#             ) or "string",
#             candidate_type="runtime-input",
#         )

#         if len(found) > before:

#             self.statistics[
#                 "runtime_candidates"
#             ] += 1

#     # =========================================================
#     # BEHAVIOR
#     # =========================================================

#     def _consume_behavior(
#         self,
#         found,
#         item,
#         page_url,
#     ):

#         if not isinstance(
#             item,
#             dict,
#         ):
#             return

#         url = self._value(
#             item,
#             "url",
#             "href",
#             "route",
#             "target",
#             "destination",
#             "endpoint",
#         )

#         if url:

#             self._consume_url(
#                 found,
#                 url,
#                 source="behavior",
#                 base_url=page_url,
#             )

#         name = self._value(
#             item,
#             "parameter",
#             "param",
#             "name",
#             "input_name",
#         )

#         if not name:
#             return

#         target = self._normalize_url(
#             url or page_url,
#             page_url,
#         )

#         if not target:
#             return

#         before = len(
#             found
#         )

#         self._add(
#             found,
#             url=target,
#             method=str(
#                 item.get(
#                     "method",
#                     "GET",
#                 )
#                 or "GET"
#             ).upper(),
#             name=name,
#             value=self._value(
#                 item,
#                 "value",
#                 "input_value",
#             ),
#             location="behavior",
#             source="behavior",
#             data_type="string",
#             candidate_type="behavior-input",
#         )

#         if len(found) > before:

#             self.statistics[
#                 "runtime_candidates"
#             ] += 1

#     # =========================================================
#     # ADD
#     # =========================================================

#     def _add(
#         self,
#         found,
#         *,
#         url,
#         method,
#         name="",
#         value="",
#         location="",
#         source="",
#         data_type="string",
#         candidate_type="observed-input",
#     ):

#         url = str(
#             url
#             or ""
#         ).strip()

#         if not url:
#             return

#         method = str(
#             method
#             or "GET"
#         ).upper().strip()

#         name = str(
#             name
#             or ""
#         ).strip()

#         location = str(
#             location
#             or ""
#         ).strip().lower()

#         candidate_type = str(
#             candidate_type
#             or "observed-input"
#         ).strip().lower()

#         # -----------------------------------------------------
#         # Noise filtering
#         # -----------------------------------------------------

#         if name.lower() in self.NOISE_PARAMETERS:

#             self.statistics[
#                 "ignored_noise"
#             ] += 1

#             return

#         # -----------------------------------------------------
#         # Routes are allowed to have no parameter.
#         # Input candidates are not.
#         # -----------------------------------------------------

#         if (
#             candidate_type
#             != "observed-route"
#             and not name
#         ):

#             return

#         # -----------------------------------------------------
#         # Stable candidate identity
#         # -----------------------------------------------------

#         if candidate_type == "observed-route":

#             signature = (
#                 candidate_type,
#                 method,
#                 url,
#                 location,
#             )

#         else:

#             signature = (
#                 candidate_type,
#                 method,
#                 url,
#                 location,
#                 name.lower(),
#             )

#         if signature in found:

#             self.statistics[
#                 "duplicates"
#             ] += 1

#             return

#         found[
#             signature
#         ] = {
#             "url": url,
#             "method": method,
#             "parameter": name,
#             "value": str(
#                 value
#                 or ""
#             ),
#             "location": location,
#             "source": str(
#                 source
#                 or ""
#             ),
#             "data_type": str(
#                 data_type
#                 or "string"
#             ),
#             "candidate_type": candidate_type,
#             "observed": True,
#         }

#     # =========================================================
#     # PROGRESS
#     # =========================================================

#     def _emit_progress(
#         self,
#         value,
#     ):
#         """
#         Report monotonic ParameterScanner progress.

#         ParameterScanner owns:
#             70 -> 100

#         When real scanner work advances from one calculated
#         percentage to another, every intermediate integer is
#         emitted in order.

#         Example:

#             70 -> 75

#         becomes:

#             71
#             72
#             73
#             74
#             75

#         No timer, sleep, or fabricated work is used.
#         """

#         try:

#             value = int(
#                 value
#             )

#         except (
#             TypeError,
#             ValueError,
#         ):

#             return

#         value = max(
#             70,
#             min(
#                 100,
#                 value,
#             ),
#         )

#         last = getattr(
#             self,
#             "last_progress",
#             70,
#         )

#         if value < last:
#             value = last

#         if value == last:
#             return

#         callback = getattr(
#             self,
#             "progress",
#             None,
#         )

#         # -------------------------------------------------------------
#         # Emit every real progress value between the previous
#         # calculated state and the new calculated state.
#         #
#         # The intermediate values are not time-based. They are simply
#         # the integer representation of the scanner's newly reached
#         # progress boundary.
#         # -------------------------------------------------------------

#         for progress_value in range(
#             last + 1,
#             value + 1,
#         ):

#             self.last_progress = (
#                 progress_value
#             )

#             if not callable(
#                 callback
#             ):
#                 continue

#             try:

#                 callback(
#                     progress_value
#                 )

#             except Exception as exc:

#                 logger.debug(
#                     "PROGRESS",
#                     (
#                         "GUI progress callback failed: "
#                         f"{type(exc).__name__}: {exc}"
#                     ),
#                 )

#                 break

#     # =========================================================
#     # SAVE
#     # =========================================================

#     @staticmethod
#     def _save(
#         path,
#         candidates,
#     ):

#         path = Path(
#             path
#         )

#         path.parent.mkdir(
#             parents=True,
#             exist_ok=True,
#         )

#         path.write_text(
#             json.dumps(
#                 candidates,
#                 indent=4,
#                 ensure_ascii=False,
#             ),
#             encoding="utf-8",
#         )










"""
AVAF Pro
Phase-1 Observed Attack-Surface Candidate Extractor

Architecture
------------

PlaywrightCrawler
        |
        v
Canonical PageResult / DiscoveryResult
        |
        +-- rendered DOM
        +-- forms
        +-- controls
        +-- runtime observations
        +-- browser network observations
        +-- observed routes
        |
        v
ParameterScanner
        |
        v
parameter_candidates.json
        |
        v
Phase-2 Validation

IMPORTANT
---------
This module performs discovery normalization only.

It does NOT:
    - generate payloads
    - fuzz parameters
    - guess URLs
    - crawl wordlists
    - attack the target
    - manufacture routes

Every candidate must originate from an observation produced by
the real Playwright browser/crawler.
"""

from __future__ import annotations

import asyncio
from asyncio.log import logger
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


class ParameterScanner:

    # =========================================================
    # STATIC RESOURCE FILTER
    # =========================================================

    STATIC_EXTENSIONS = {
        ".css",
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

        ".woff",
        ".woff2",
        ".woff3",
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

        ".map",
    }

    NOISE_PARAMETERS = {
        "_",
        "cachebuster",
        "cache_buster",
        "cb",
    }

    STATIC_RESOURCE_TYPES = {
        "image",
        "stylesheet",
        "font",
        "media",
        "manifest",
        "icon",
        "texttrack",
        "websocket",
    }

    # =========================================================
    # INITIALIZATION
    # =========================================================

    def __init__(
        self,
        scan_data,
        progress=None,
    ):

        self.scan_data = scan_data or {}
        self.progress = progress

        self.target_url = str(
            self.scan_data.get("target")
            or self.scan_data.get("target_url")
            or ""
        ).strip()

        self.target_origin = self._origin(
            self.target_url
        )

        # Scanner owns 70 -> 100.
        self.last_progress = 70

        self.statistics = {
            "pages": 0,

            "network_candidates": 0,
            "form_candidates": 0,
            "runtime_candidates": 0,
            "route_candidates": 0,
            "interaction_candidates": 0,

            "ignored_static": 0,
            "ignored_noise": 0,
            "ignored_external": 0,

            "duplicates": 0,
        }

    # =========================================================
    # MAIN EXTRACTION
    # =========================================================

    async def extract_candidates(
        self,
        save_to=None,
    ):

        pages = (
            self.scan_data.get(
                "pages_analyzed",
                [],
            )
            or []
        )

        if not isinstance(
            pages,
            list,
        ):
            pages = []

        total_pages = len(pages)

        found = {}

        # -----------------------------------------------------
        # NO DISCOVERY
        # -----------------------------------------------------

        if not pages:

            print(
                "[INFO] No pages available for parameter extraction.",
                flush=True,
            )
        
            if save_to:
                self._save(
                    save_to,
                    [],
                )
        
            # Scanner has completed its work even though
            # there were no pages to analyze.
            self._emit_progress(100)
        
            print(
                "[INFO] Candidate extraction completed.",
                flush=True,
            )
        
            return []

        print(
            f"[INFO] Analyzing {total_pages} discovered pages...",
            flush=True,
        )

        # -----------------------------------------------------
        # PAGE-BY-PAGE OBSERVATION CONSUMPTION
        # -----------------------------------------------------

        for index, page in enumerate(
            pages,
            start=1,
        ):

            if not isinstance(
                page,
                dict,
            ):
                continue

            self.statistics["pages"] += 1

            discovery = self._dict(
                page.get(
                    "discovery",
                    {},
                )
            )
            
            # -------------------------------------------------------------
            # PageResult preserves additional runtime evidence in metadata.
            # -------------------------------------------------------------
            
            metadata = self._dict(
                page.get(
                    "metadata",
                    {},
                )
            )
            

            
            static = self._dict(
                discovery.get(
                    "static_dom",
                    {},
                )
            )
            
            runtime = self._dict(
                discovery.get(
                    "runtime",
                    {},
                )
            )
            
            # -------------------------------------------------------------
            # PageResult preserves the browser-observed runtime export
            # inside metadata["runtime_data"].
            #
            # Use it only when the canonical discovery runtime is missing
            # or incomplete.
            #
            # Nothing is generated here.
            # -------------------------------------------------------------
            
            metadata_runtime = self._dict(
                metadata.get(
                    "runtime_data",
                    {},
                )
            )
            
            if metadata_runtime:
            
                if not runtime:
                    runtime = metadata_runtime
            
                else:
                    # Preserve the canonical runtime object, but expose the
                    # browser-observed artifact collections when they are
                    # absent from the canonical representation.
                    if (
                        "artifacts" not in runtime
                        and "artifacts" in metadata_runtime
                    ):
                        runtime["artifacts"] = metadata_runtime[
                            "artifacts"
                        ]
            
                    if (
                        "events" not in runtime
                        and "events" in metadata_runtime
                    ):
                        runtime["events"] = metadata_runtime[
                            "events"
                        ]
            
                    if (
                        "parameters" not in runtime
                        and "parameters" in metadata_runtime
                    ):
                        runtime["parameters"] = metadata_runtime[
                            "parameters"
                        ]
            
                    if (
                        "forms" not in runtime
                        and "forms" in metadata_runtime
                    ):
                        runtime["forms"] = metadata_runtime[
                            "forms"
                        ]
            
                    if (
                        "controls" not in runtime
                        and "controls" in metadata_runtime
                    ):
                        runtime["controls"] = metadata_runtime[
                            "controls"
                        ]
            
            network = self._dict(
                discovery.get(
                    "network",
                    {},
                )
            )
            
            print("\n========== SCANNER RUNTIME DEBUG ==========", flush=True)
            print(
                "[DEBUG] scanner runtime type:",
                type(runtime),
                flush=True,
            )
            
            print(
                "[DEBUG] scanner runtime keys:",
                list(runtime.keys())
                if isinstance(runtime, dict)
                else "NOT A DICT",
                flush=True,
            )
            
            print(
                "[DEBUG] scanner runtime.parameters:",
                runtime.get("parameters")
                if isinstance(runtime, dict)
                else "N/A",
                flush=True,
            )
            
            print(
                "[DEBUG] scanner runtime.forms:",
                runtime.get("forms")
                if isinstance(runtime, dict)
                else "N/A",
                flush=True,
            )
            
            print(
                "[DEBUG] scanner runtime.controls:",
                runtime.get("controls")
                if isinstance(runtime, dict)
                else "N/A",
                flush=True,
            )
            
            print(
                "[DEBUG] scanner runtime.artifacts:",
                (
                    list(
                        runtime.get(
                            "artifacts",
                            {},
                        ).keys()
                    )
                    if isinstance(
                        runtime.get(
                            "artifacts",
                            {},
                        ),
                        dict,
                    )
                    else "NO ARTIFACTS"
                )
                if isinstance(runtime, dict)
                else "N/A",
                flush=True,
            )
            
            print("============================================\n", flush=True)
            
            # =============================================================
            # BEHAVIOR / INTERACTION OBSERVATIONS
            # =============================================================
            #
            # DiscoveryResult normally contains:
            #
            #     static_dom
            #     runtime
            #     network
            #
            # PageBuilder additionally preserves browser-observed behavior
            # and interaction results in PageResult.metadata.
            #
            # Therefore metadata is used as the fallback source for these
            # observation streams.
            #
            # Nothing is generated here. We only consume observations
            # already produced by the browser.
            # =============================================================
            
            behavior = self._dict(
                discovery.get(
                    "behavior",
                    metadata.get(
                        "behavior",
                        page.get(
                            "behavior",
                            {},
                        ),
                    ),
                )
            )
            
            interaction = self._dict(
                discovery.get(
                    "interaction",
                    metadata.get(
                        "interaction",
                        page.get(
                            "interaction",
                            {},
                        ),
                    ),
                )
            )
            
            page_url = str(
                page.get(
                    "final_url"
                )
                or page.get(
                    "url"
                )
                or ""
            ).strip()
            
            # =============================================================
            # SCANNER PROGRESS
            # =============================================================
            #
            # ParameterScanner owns the real 70 -> 100 handoff.
            #
            # Each discovered page is genuine scanner work.
            #
            # The percentage calculation determines how far the scanner
            # has progressed, while _emit_progress() is responsible for
            # emitting every missing integer in sequence.
            #
            # 70 = crawler handoff
            # 71..99 = actual candidate processing
            # 100 = scanner genuinely complete
            # =============================================================

            if total_pages > 0:

                target_progress = (
                    70
                    + int(
                        (
                            index
                            / total_pages
                        ) * 29
                    )
                )

                target_progress = max(
                    70,
                    min(
                        99,
                        target_progress,
                    ),
                )

                self._emit_progress(
                    target_progress
                )
                
            # =================================================
            # A. REAL PAGE URL
            # =================================================

            if page_url:

                self._consume_url(
                    found,
                    page_url,
                    source="observed-page-url",
                )

            # =================================================
            # B. NETWORK OBSERVATIONS
            # =================================================

            network_items = []

            for key in (
                "endpoints",
                "requests",
                "observed_endpoints",
                "observed_requests",
            ):

                network_items.extend(
                    self._items(
                        network.get(
                            key,
                            [],
                        )
                    )
                )

            for endpoint in network_items:

                self._consume_endpoint(
                    found,
                    endpoint,
                )

            # =================================================
            # C. RENDERED DOM FORMS
            # =================================================

            form_items = []

            for key in (
                "forms",
                "rendered_forms",
                "observed_forms",
            ):

                form_items.extend(
                    self._items(
                        static.get(
                            key,
                            [],
                        )
                    )
                )

            for form in form_items:

                self._consume_form(
                    found,
                    form,
                    source="rendered-dom-form",
                    page_url=page_url,
                )

            # =================================================
            # D. RUNTIME FORMS
            # =================================================

            runtime_forms = []

            for key in (
                "runtime_forms",
                "forms",
                "observed_forms",
                "form_controls",
            ):

                runtime_forms.extend(
                    self._items(
                        runtime.get(
                            key,
                            [],
                        )
                    )
                )

            for form in runtime_forms:

                self._consume_form(
                    found,
                    form,
                    source="runtime-form",
                    page_url=page_url,
                )

                       # =================================================
            # E. PASSIVE RENDERED DOM LINKS
            # =================================================
            #
            # These remain browser-observed evidence, but they
            # are NOT candidate routes.
            #
            # A DOM href does not prove that the browser actually
            # navigated to that URL.
            #
            # Actual navigation candidates come from:
            #
            #   - browser-observed page URL
            #   - InteractionEngine navigation evidence
            #
            # Do not promote passive href values here.
            # =================================================
            
            # =================================================
            # F. RUNTIME ROUTES
            # =================================================

            # =================================================
            # F. RUNTIME NAVIGATION EVIDENCE
            # =================================================
            #
            # Runtime DOM route collections may contain passive
            # href observations. They are not promoted.
            #
            # Only an explicitly recorded navigation event is
            # eligible here.
            # =================================================

            runtime_navigations = self._items(
                runtime.get(
                    "navigations",
                    [],
                )
            )

            for navigation in runtime_navigations:

                route_url = self._value(
                    navigation,
                    "url",
                    "destination",
                    "target",
                )

                if not route_url and isinstance(
                    navigation,
                    str,
                ):
                    route_url = navigation

                if not route_url:
                    continue

                before = len(found)

                self._consume_url(
                    found,
                    route_url,
                    source="browser-observed-navigation",
                    base_url=page_url,
                )

                if len(found) > before:

                    self.statistics[
                        "runtime_candidates"
                    ] += 1
            # =================================================
            # G. INTERACTION ROUTES
            # =================================================

            interaction_routes = []

            for key in (
                "routes",
                "navigations",
                "observed_routes",
                "navigation_routes",
            ):

                interaction_routes.extend(
                    self._items(
                        interaction.get(
                            key,
                            [],
                        )
                    )
                )

            for route in interaction_routes:

                route_url = self._value(
                    route,
                    "url",
                    "href",
                    "route",
                    "target",
                    "destination",
                )

                if not route_url and isinstance(
                    route,
                    str,
                ):
                    route_url = route

                if route_url:

                    before = len(found)

                    self._consume_url(
                        found,
                        route_url,
                        source="interaction-route",
                        base_url=page_url,
                    )

                    if len(found) > before:

                        self.statistics[
                            "interaction_candidates"
                        ] += 1

            # =================================================
            # H. RUNTIME CONTROLS / INPUTS
            # =================================================

            controls = []

            for key in (
                "controls",
                "inputs",
                "interactive_elements",
                "observed_inputs",
                "form_controls",
            ):

                controls.extend(
                    self._items(
                        runtime.get(
                            key,
                            [],
                        )
                    )
                )

            for control in controls:

                self._consume_control(
                    found,
                    control,
                    page_url,
                    source="runtime-control",
                )
                
            # =================================================
            # H.1 RUNTIME DOM PARAMETERS
            # =================================================
            #
            # RuntimeCollector records actual browser-observed
            # parameters under:
            #
            #     runtime["artifacts"]["dom"]["parameters"]
            #
            # These are legitimate observations because they came
            # from the rendered browser state.
            #
            # Do NOT infer parameter names from runtime events,
            # JavaScript text, labels, or arbitrary strings.
            # =================================================
            
            runtime_artifacts = self._dict(
                runtime.get(
                    "artifacts",
                    {},
                )
            )
            
            runtime_dom = self._dict(
                runtime_artifacts.get(
                    "dom",
                    {},
                )
            )
            
            
            
            runtime_parameters = self._items(
                runtime_dom.get(
                    "parameters",
                    [],
                )
            )
            
            for parameter in runtime_parameters:
            
                if isinstance(
                    parameter,
                    dict,
                ):
            
                    name = self._value(
                        parameter,
                        "parameter",
                        "name",
                    )
            
                    value = self._value(
                        parameter,
                        "value",
                        "default_value",
                    )
            
                    location = self._value(
                        parameter,
                        "location",
                    ) or "runtime"
            
                    method = self._value(
                        parameter,
                        "method",
                    ) or "GET"
            
                    url = self._value(
                        parameter,
                        "url",
                        "page_url",
                    ) or page_url
            
                else:
            
                    name = self._value(
                        parameter,
                        "parameter",
                        "name",
                    )
            
                    value = ""
            
                    location = "runtime"
                    method = "GET"
                    url = page_url
            
                if not name:
                    continue
            
                normalized_url = self._normalize_url(
                    url,
                    page_url,
                )
            
                if not normalized_url:
                    continue
            
                before = len(found)
            
                self._add(
                    found,
                    url=normalized_url,
                    method=method,
                    name=name,
                    value=value,
                    location=location,
                    source="runtime-dom-parameter",
                    data_type="string",
                    candidate_type="runtime-input",
                )
            
                if len(found) > before:
            
                    self.statistics[
                        "runtime_candidates"
                    ] += 1


            # =================================================
            # H.2 RUNTIME DOM FORMS
            # =================================================
            #
            # RuntimeCollector may preserve forms inside the live
            # runtime DOM artifact.
            #
            # These are browser-observed forms only.
            # Nothing is generated or guessed here.
            # =================================================

            runtime_dom_forms = self._items(
                runtime_dom.get(
                    "forms",
                    [],
                )
            )

            for form in runtime_dom_forms:

                self._consume_form(
                    found,
                    form,
                    source="runtime-dom-form",
                    page_url=page_url,
                )

            # =================================================
            # I. RUNTIME EVENT OBSERVATIONS
            # =================================================
            #
            # Consume only explicit browser-observed parameter/input
            # fields from runtime events. Arbitrary event names,
            # JavaScript text, labels, and guessed values are never
            # promoted into candidates.
            # =================================================

            runtime_events = self._items(
                runtime.get(
                    "events",
                    [],
                )
            )

            for event in runtime_events:

                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                event_name = self._value(
                    event,
                    "parameter",
                    "param",
                    "input_name",
                    "field",
                    "field_name",
                    "form_field",
                )

                if not event_name:
                    continue

                event_url = self._value(
                    event,
                    "url",
                    "page_url",
                    "action",
                    "target",
                    "endpoint",
                ) or page_url

                normalized_event_url = self._normalize_url(
                    event_url,
                    page_url,
                )

                if not normalized_event_url:
                    continue

                before = len(found)

                self._add(
                    found,
                    url=normalized_event_url,
                    method=self._value(
                        event,
                        "method",
                    ) or "GET",
                    name=event_name,
                    value=self._value(
                        event,
                        "value",
                        "input_value",
                        "default_value",
                    ),
                    location=self._value(
                        event,
                        "location",
                    ) or "runtime",
                    source="runtime-observation",
                    data_type=self._value(
                        event,
                        "type",
                        "input_type",
                    ) or "string",
                    candidate_type="runtime-observation",
                )

                if len(found) > before:

                    self.statistics[
                        "runtime_candidates"
                    ] += 1

            # =================================================
            # J. BEHAVIOR OBSERVATIONS
            # =================================================


            behavior_items = []

            for key in (
                "routes",
                "navigations",
                "requests",
                "endpoints",
                "inputs",
                "controls",
                "forms",
            ):

                behavior_items.extend(
                    self._items(
                        behavior.get(
                            key,
                            [],
                        )
                    )
                )

            for item in behavior_items:

                self._consume_behavior(
                    found,
                    item,
                    page_url,
                )

            # =================================================
            # REAL PAGE PROGRESS
            #
            # 70 = scanner started
            # 99 = all pages consumed and candidate list ready
            # 100 = JSON successfully saved
            # =================================================

            target = (
                70
                + int(
                    (
                        index
                        / total_pages
                    ) * 29
                )
            )

            target = max(
                70,
                min(
                    99,
                    target,
                ),
            )

            self._emit_progress(
                target
            )

            print(
                f"[INFO] [SCANNER] "
                f"Page {index}/{total_pages} -> "
                f"{len(found)} observed candidates",
                flush=True,
            )

            # Give the event loop a chance to process GUI output.
            await asyncio.sleep(0)

        # =====================================================
        # FINAL DEDUPLICATION
        # =====================================================

        candidates = list(
            found.values()
        )

        unique = {}

        for candidate in candidates:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            candidate_type = str(
                candidate.get(
                    "candidate_type",
                    "observed-input",
                )
            ).strip().lower()

            url = str(
                candidate.get(
                    "url",
                    "",
                )
            ).strip()

            method = str(
                candidate.get(
                    "method",
                    "GET",
                )
            ).upper()

            location = str(
                candidate.get(
                    "location",
                    "",
                )
            ).strip().lower()

            parameter = str(
                candidate.get(
                    "parameter",
                    "",
                )
            ).strip().lower()

            # Routes are allowed to have no parameter.
            if candidate_type == "observed-route":

                signature = (
                    candidate_type,
                    method,
                    url,
                    location,
                )

            else:

                if not parameter:

                    continue

                signature = (
                    candidate_type,
                    method,
                    url,
                    location,
                    parameter,
                )

            if signature in unique:

                self.statistics[
                    "duplicates"
                ] += 1

                continue

            unique[
                signature
            ] = candidate

        candidates = list(
            unique.values()
        )

        # =====================================================
        # SORT
        # =====================================================

        candidates.sort(
            key=lambda item: (
                str(
                    item.get(
                        "url",
                        "",
                    )
                ),
                str(
                    item.get(
                        "method",
                        "GET",
                    )
                ),
                str(
                    item.get(
                        "location",
                        "",
                    )
                ),
                str(
                    item.get(
                        "parameter",
                        "",
                    )
                ),
            )
        )
        
        # =========================================================
        # FINALIZATION
        # =========================================================
        #
        # 99 = all real observations processed.
        #
        # 100 is emitted ONLY after:
        #   1. candidates constructed
        #   2. duplicates removed
        #   3. candidates sorted
        #   4. output successfully saved
        # =========================================================
        
        self.last_progress = max(
            self.last_progress,
            99,
        )
        
        self._emit_progress(
            self.last_progress
        )     
        
        # =========================================================
        # SAVE FINAL CANDIDATES
        # =========================================================
        
        if save_to:
        
            self._save(
                save_to,
                candidates,
            )
        
        # =============================================================
        # FINALIZATION
        # =============================================================
        #
        # At this point:
        #
        #   - all pages have been analyzed
        #   - all observations have been processed
        #   - candidates have been finalized
        #   - statistics are complete
        #
        # 96-99 are optional final scanner states.
        # 100 is emitted ONLY after the scanner has genuinely finished.
        # =============================================================
        
        for value in (
            96,
            97,
            98,
            99,
        ):
            if value > self.last_progress:
                self._emit_progress(
                    value
                )
        
        
        # =============================================================
        # SUMMARY
        # =============================================================
        
        print(
            "",
            flush=True,
        )
        
        print(
            "========== PHASE-1 SCANNER ==========",
            flush=True,
        )
        
        print(
            f"[INFO] Pages analyzed: "
            f"{self.statistics['pages']}",
            flush=True,
        )
        
        print(
            f"[INFO] Network vectors: "
            f"{self.statistics['network_candidates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Form vectors: "
            f"{self.statistics['form_candidates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Runtime vectors: "
            f"{self.statistics['runtime_candidates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Route vectors: "
            f"{self.statistics['route_candidates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Interaction vectors: "
            f"{self.statistics['interaction_candidates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Ignored static: "
            f"{self.statistics['ignored_static']}",
            flush=True,
        )
        
        print(
            f"[INFO] Ignored noise: "
            f"{self.statistics['ignored_noise']}",
            flush=True,
        )
        
        print(
            f"[INFO] External observations ignored: "
            f"{self.statistics['ignored_external']}",
            flush=True,
        )
        
        print(
            f"[INFO] Duplicates merged: "
            f"{self.statistics['duplicates']}",
            flush=True,
        )
        
        print(
            f"[INFO] Useful observed candidates: "
            f"{len(candidates)}",
            flush=True,
        )
        
        print(
            "=====================================",
            flush=True,
        )
        
        
        # =============================================================
        # SCANNER COMPLETE
        # =============================================================
        #
        # NOTHING BELOW THIS LINE SHOULD PERFORM SCANNER WORK.
        #
        # 100 means extract_candidates() has genuinely completed.
        # =============================================================
        
        self._emit_progress(
            100
        )
        
        print(
            "[INFO] Candidate extraction completed.",
            flush=True,
        )
        
        return candidates

    # =========================================================
    # GENERIC HELPERS
    # =========================================================

    @staticmethod
    def _dict(value):

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _items(value):

        if value is None:
            return []

        if isinstance(
            value,
            dict,
        ):

            for key in (
                "items",
                "values",
                "data",
                "results",
            ):

                nested = value.get(
                    key
                )

                if isinstance(
                    nested,
                    list,
                ):

                    return nested

            return [value]

        if isinstance(
            value,
            (list, tuple, set),
        ):

            return list(value)

        return [value]

    @staticmethod
    def _value(
        item,
        *keys,
    ):

        if isinstance(
            item,
            str,
        ):

            return item

        if not isinstance(
            item,
            dict,
        ):

            return ""

        for key in keys:

            value = item.get(
                key
            )

            if value not in (
                None,
                "",
            ):

                return str(
                    value
                ).strip()

        return ""

    @staticmethod
    def _origin(url):

        try:

            parsed = urlparse(
                str(url)
            )

            if not parsed.hostname:
                return None

            return (
                parsed.scheme.lower(),
                parsed.hostname.lower(),
                parsed.port
                or (
                    443
                    if parsed.scheme.lower()
                    == "https"
                    else 80
                ),
            )

        except Exception:

            return None

    # =========================================================
    # URL VALIDATION
    # =========================================================

    def _normalize_url(
        self,
        url,
        base_url="",
    ):

        if not url:
            return ""

        url = str(
            url
        ).strip()

        if url.startswith(
            ("#", "javascript:", "mailto:", "tel:")
        ):
            return ""

        try:

            parsed = urlparse(
                url
            )

            if not parsed.scheme:

                if base_url:

                    from urllib.parse import urljoin

                    url = urljoin(
                        base_url,
                        url,
                    )

                    parsed = urlparse(
                        url
                    )

            if not parsed.scheme or not parsed.netloc:

                return ""

            normalized = parsed.geturl()

        except Exception:

            return ""

        # -----------------------------------------------------
        # Same-origin only
        # -----------------------------------------------------

        if self.target_origin:

            if self._origin(
                normalized
            ) != self.target_origin:

                self.statistics[
                    "ignored_external"
                ] += 1

                return ""

        # -----------------------------------------------------
        # Static resources are never application routes
        # -----------------------------------------------------

        path = (
            parsed.path
            or ""
        ).lower()

        if any(
            path.endswith(
                extension
            )
            for extension in self.STATIC_EXTENSIONS
        ):

            self.statistics[
                "ignored_static"
            ] += 1

            return ""

        return normalized

    # =========================================================
    # URL CONSUMPTION
    # =========================================================

    def _consume_url(
        self,
        found,
        url,
        source,
        base_url="",
    ):

        normalized = self._normalize_url(
            url,
            base_url,
        )

        if not normalized:
            return

        parsed = urlparse(
            normalized
        )

        # -----------------------------------------------------
        # Query parameters
        # -----------------------------------------------------

        try:

            parameters = parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )

        except Exception:

            parameters = []

        for name, value in parameters:

            name = str(
                name
                or ""
            ).strip()

            if not name:
                continue

            before = len(
                found
            )

            self._add(
                found,
                url=normalized,
                method="GET",
                name=name,
                value=value,
                location="query",
                source=source,
                data_type="string",
                candidate_type="observed-parameter",
            )

            if len(found) > before:

                self.statistics[
                    "route_candidates"
                ] += 1

        # -----------------------------------------------------
        # REAL ROUTE
        #
        # A route itself is useful to Phase-2 even if it has no
        # query parameter.
        # -----------------------------------------------------

        before = len(
            found
        )

        self._add(
            found,
            url=normalized,
            method="GET",
            name="",
            value="",
            location="path",
            source=source,
            data_type="route",
            candidate_type="observed-route",
        )

        if len(found) > before:

            self.statistics[
                "route_candidates"
            ] += 1

    # =========================================================
    # NETWORK ENDPOINT
    # =========================================================

    def _consume_endpoint(
        self,
        found,
        endpoint,
    ):

        if not isinstance(
            endpoint,
            dict,
        ):
            return

        resource_type = str(
            endpoint.get(
                "resource_type",
                endpoint.get(
                    "type",
                    "",
                ),
            )
        ).lower().strip()

        if resource_type in self.STATIC_RESOURCE_TYPES:

            self.statistics[
                "ignored_static"
            ] += 1

            return

        url = self._value(
            endpoint,
            "url",
            "request_url",
            "href",
            "endpoint",
            "route",
        )

        if not url:
            return

        normalized = self._normalize_url(
            url
        )

        if not normalized:
            return

        method = str(
            endpoint.get(
                "method",
                "GET",
            )
            or "GET"
        ).upper()

        # -----------------------------------------------------
        # Query parameters in observed network request
        # -----------------------------------------------------

        parsed = urlparse(
            normalized
        )

        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ):

            before = len(
                found
            )

            self._add(
                found,
                url=normalized,
                method=method,
                name=name,
                value=value,
                location="query",
                source="browser-network",
                data_type="string",
                candidate_type="network-parameter",
            )

            if len(found) > before:

                self.statistics[
                    "network_candidates"
                ] += 1

        # -----------------------------------------------------
        # Observed route itself
        # -----------------------------------------------------

        before = len(
            found
        )

        self._add(
            found,
            url=normalized,
            method=method,
            name="",
            value="",
            location="network",
            source="browser-network",
            data_type="route",
            candidate_type="observed-route",
        )

        if len(found) > before:

            self.statistics[
                "network_candidates"
            ] += 1

    # =========================================================
    # FORM
    # =========================================================

    def _consume_form(
        self,
        found,
        form,
        source,
        page_url="",
    ):

        if not isinstance(
            form,
            dict,
        ):
            return

        action = self._value(
            form,
            "action",
            "url",
            "target",
            "endpoint",
        )

        if not action:
            action = page_url

        action = self._normalize_url(
            action,
            page_url,
        )

        if not action:
            return

        method = str(
            form.get(
                "method",
                "GET",
            )
            or "GET"
        ).upper()

        controls = []

        for key in (
            "inputs",
            "controls",
            "fields",
            "elements",
            "form_controls",
        ):

            controls.extend(
                self._items(
                    form.get(
                        key,
                        [],
                    )
                )
            )

        # Some DOM extractors expose individual collections.
        for key in (
            "selects",
            "textareas",
            "buttons",
        ):

            controls.extend(
                self._items(
                    form.get(
                        key,
                        [],
                    )
                )
            )

        for control in controls:

            if not isinstance(
                control,
                dict,
            ):
                continue

            name = self._value(
                control,
                "name",
                "parameter",
                "param",
                "formcontrolname",
                "formControlName",
                "id",
            )

            if not name:
                continue

            value = self._value(
                control,
                "value",
                "default_value",
                "selected_value",
            )

            data_type = self._value(
                control,
                "type",
                "input_type",
            ) or "string"

            before = len(
                found
            )

            self._add(
                found,
                url=action,
                method=method,
                name=name,
                value=value,
                location="form",
                source=source,
                data_type=data_type,
                candidate_type="form-input",
            )

            if len(found) > before:

                self.statistics[
                    "form_candidates"
                ] += 1

    # =========================================================
    # RUNTIME CONTROL
    # =========================================================

    def _consume_control(
        self,
        found,
        control,
        page_url,
        source,
    ):

        if not isinstance(
            control,
            dict,
        ):
            return

        name = self._value(
            control,
            "name",
            "parameter",
            "param",
            "formcontrolname",
            "formControlName",
            "id",
            "aria_label",
            "aria-label",
        )

        if not name:
            return

        url = self._value(
            control,
            "url",
            "action",
            "target",
            "endpoint",
        ) or page_url

        url = self._normalize_url(
            url,
            page_url,
        )

        if not url:
            return

        value = self._value(
            control,
            "value",
            "default_value",
            "selected_value",
        )

        before = len(
            found
        )

        self._add(
            found,
            url=url,
            method=str(
                control.get(
                    "method",
                    "GET",
                )
                or "GET"
            ).upper(),
            name=name,
            value=value,
            location="runtime",
            source=source,
            data_type=self._value(
                control,
                "type",
            ) or "string",
            candidate_type="runtime-input",
        )

        if len(found) > before:

            self.statistics[
                "runtime_candidates"
            ] += 1

    # =========================================================
    # BEHAVIOR
    # =========================================================

    def _consume_behavior(
        self,
        found,
        item,
        page_url,
    ):

        if not isinstance(
            item,
            dict,
        ):
            return

        url = self._value(
            item,
            "url",
            "href",
            "route",
            "target",
            "destination",
            "endpoint",
        )

        if url:

            self._consume_url(
                found,
                url,
                source="behavior",
                base_url=page_url,
            )

        name = self._value(
            item,
            "parameter",
            "param",
            "name",
            "input_name",
        )

        if not name:
            return

        target = self._normalize_url(
            url or page_url,
            page_url,
        )

        if not target:
            return

        before = len(
            found
        )

        self._add(
            found,
            url=target,
            method=str(
                item.get(
                    "method",
                    "GET",
                )
                or "GET"
            ).upper(),
            name=name,
            value=self._value(
                item,
                "value",
                "input_value",
            ),
            location="behavior",
            source="behavior",
            data_type="string",
            candidate_type="behavior-input",
        )

        if len(found) > before:

            self.statistics[
                "runtime_candidates"
            ] += 1

    # =========================================================
    # ADD
    # =========================================================

    def _add(
        self,
        found,
        *,
        url,
        method,
        name="",
        value="",
        location="",
        source="",
        data_type="string",
        candidate_type="observed-input",
    ):

        url = str(
            url
            or ""
        ).strip()

        if not url:
            return

        method = str(
            method
            or "GET"
        ).upper().strip()

        name = str(
            name
            or ""
        ).strip()

        location = str(
            location
            or ""
        ).strip().lower()

        candidate_type = str(
            candidate_type
            or "observed-input"
        ).strip().lower()

        # -----------------------------------------------------
        # Noise filtering
        # -----------------------------------------------------

        if name.lower() in self.NOISE_PARAMETERS:

            self.statistics[
                "ignored_noise"
            ] += 1

            return

        # -----------------------------------------------------
        # Routes are allowed to have no parameter.
        # Input candidates are not.
        # -----------------------------------------------------

        if (
            candidate_type
            != "observed-route"
            and not name
        ):

            return

        # -----------------------------------------------------
        # Stable candidate identity
        # -----------------------------------------------------

        if candidate_type == "observed-route":

            signature = (
                candidate_type,
                method,
                url,
                location,
            )

        else:

            signature = (
                candidate_type,
                method,
                url,
                location,
                name.lower(),
            )

        if signature in found:

            self.statistics[
                "duplicates"
            ] += 1

            return

        found[
            signature
        ] = {
            "url": url,
            "method": method,
            "parameter": name,
            "value": str(
                value
                or ""
            ),
            "location": location,
            "source": str(
                source
                or ""
            ),
            "data_type": str(
                data_type
                or "string"
            ),
            "candidate_type": candidate_type,
            "observed": True,
        }

    # =========================================================
    # PROGRESS
    # =========================================================

    def _emit_progress(
        self,
        value,
    ):
        """
        Report monotonic ParameterScanner progress.

        ParameterScanner owns:
            70 -> 100

        When real scanner work advances from one calculated
        percentage to another, every intermediate integer is
        emitted in order.

        Example:

            70 -> 75

        becomes:

            71
            72
            73
            74
            75

        No timer, sleep, or fabricated work is used.
        """

        try:

            value = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return

        value = max(
            70,
            min(
                100,
                value,
            ),
        )

        last = getattr(
            self,
            "last_progress",
            70,
        )

        if value < last:
            value = last

        if value == last:
            return

        callback = getattr(
            self,
            "progress",
            None,
        )

        # -------------------------------------------------------------
        # Emit every real progress value between the previous
        # calculated state and the new calculated state.
        #
        # The intermediate values are not time-based. They are simply
        # the integer representation of the scanner's newly reached
        # progress boundary.
        # -------------------------------------------------------------

        for progress_value in range(
            last + 1,
            value + 1,
        ):

            self.last_progress = (
                progress_value
            )

            if not callable(
                callback
            ):
                continue

            try:

                callback(
                    progress_value
                )

            except Exception as exc:

                logger.debug(
                    "PROGRESS",
                    (
                        "GUI progress callback failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                )

                break

    # =========================================================
    # SAVE
    # =========================================================

    @staticmethod
    def _save(
        path,
        candidates,
    ):

        path = Path(
            path
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                candidates,
                indent=4,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )