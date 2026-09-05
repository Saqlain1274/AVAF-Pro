from __future__ import annotations

import json

import re
from urllib.parse import (
    parse_qsl,
    urlparse,
)

from playwright.async_api import (
    Page,
    Request,
    Response,
)

from phase1_scanning_detection.discovery.logger import logger

from phase1_scanning_detection.discovery.model import (
    HeaderInfo,
    NetworkRequest,
    NetworkResponse,
    NetworkResult,
    AttackEndpoint,
    AttackParameter,
)


# ==========================================================
# STATIC RESOURCE FILTER
# ==========================================================
#
# These resources are useful for rendering the page but are
# not useful as application-level discovery records.
#
# We still allow the browser to request them.
# We simply do not store them as Phase-1 application traffic.
# ==========================================================

STATIC_RESOURCE_TYPES = {
    "image",
    "media",
    "font",
    "stylesheet",
}

STATIC_EXTENSIONS = {
    # Images
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".avif",

    # Fonts
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",

    # Audio / video
    ".mp3",
    ".wav",
    ".ogg",
    ".mp4",
    ".webm",
    ".avi",
    ".mov",
    ".mpeg",

    # Presentation
    ".css",
    ".map",
}


# ==========================================================
# APPLICATION NETWORK TYPES
# ==========================================================

APPLICATION_RESOURCE_TYPES = {
    "document",
    "script",
    "xhr",
    "fetch",
    "websocket",
    "eventsource",
    "manifest",
    "other",
}


# ==========================================================
# API-LIKE CONTENT TYPES
# ==========================================================

API_CONTENT_TYPES = {
    "application/json",
    "application/graphql",
    "application/graphql-response+json",
    "application/problem+json",
    "application/x-www-form-urlencoded",
}


# ==========================================================
# NETWORK COLLECTOR
# ==========================================================

class NetworkCollector:
    """
    AVAF PRO
    Network Collector

    Passive browser-network observer.

    Responsibilities
    ----------------
    ✓ Capture requests observed by Playwright
    ✓ Capture responses observed by Playwright
    ✓ Ignore presentation-only static resources
    ✓ Normalize request metadata
    ✓ Normalize response metadata
    ✓ Discover application communication endpoints
    ✓ Extract observed request parameters
    ✓ Preserve request/response relationships
    ✓ Deduplicate repeated traffic
    ✓ Produce NetworkResult

    Never
    -----
    ✗ Replay requests
    ✗ Modify requests
    ✗ Inject payloads
    ✗ Validate vulnerabilities
    ✗ Generate attack traffic

    Phase-1 output
    --------------
    NetworkResult
        ├── requests
        ├── responses
        ├── endpoints
        ├── api_endpoints
        ├── unique_hosts
        ├── technologies
        └── security_headers
    """

    # ======================================================
    # INIT
    # ======================================================

    def __init__(self):

        self.page: Page | None = None

        # Application origin is established by the crawler before
        # navigation. Network traffic outside this origin is observed
        # by the browser but is not promoted into Phase-1 application
        # network evidence.
        self._application_origin: str | None = None
        
        # Browser-observed application URLs that directly redirected
        # the browser to an external origin.
        #
        # This is populated from Playwright's real redirect chain
        # (request.redirected_from). It is NOT generated or guessed.
        self._external_redirect_sources: set[str] = set()
        
        self._closed = False

        self._requests: dict[str, NetworkRequest] = {}

        self._responses: dict[str, NetworkResponse] = {}

        self._failed: set[str] = set()

        self._seen_request_keys: set[tuple] = set()

        self._seen_response_keys: set[tuple] = set()

        self._seen_endpoint_keys: set[tuple] = set()

        self._hosts: set[str] = set()

        self._api_urls: set[str] = set()

        self._technologies: set[str] = set()

        self._security_headers: dict[str, str] = {}

        self.result = NetworkResult()

    # ======================================================
    # RESET
    # ======================================================

    def reset(self):

        self._closed = False

        self._external_redirect_sources.clear()
        
        self._requests.clear()

        self._responses.clear()

        self._failed.clear()

        self._seen_request_keys.clear()

        self._seen_response_keys.clear()

        self._seen_endpoint_keys.clear()

        self._hosts.clear()

        self._api_urls.clear()

        self._technologies.clear()

        self._security_headers.clear()

        self.result = NetworkResult()

    # ======================================================
    # ATTACH
    # ======================================================

    async def attach(
        self,
        page: Page,
    ) -> None:

        self.page = page

        page.on(
            "request",
            self._on_request,
        )

        page.on(
            "response",
            self._on_response,
        )

        page.on(
            "requestfailed",
            self._on_failed,
        )

        logger.debug(
            "NETWORK",
            "Network listeners attached.",
        )

    # ======================================================
    # APPLICATION ORIGIN
    # ======================================================

    def set_application_origin(
        self,
        url: str,
    ) -> None:
        """
        Set the authoritative application origin.

        Only browser traffic belonging to this origin is retained
        as Phase-1 application network evidence.
        """

        try:
            parsed = urlparse(url)

            if not parsed.scheme or not parsed.netloc:
                self._application_origin = None
                return

            self._application_origin = (
                f"{parsed.scheme.lower()}://"
                f"{parsed.netloc.lower()}"
            )

            logger.debug(
                "NETWORK",
                (
                    "Application network origin set: "
                    f"{self._application_origin}"
                ),
            )

        except Exception as exc:

            self._application_origin = None

            logger.warning(
                "NETWORK",
                f"Application origin setup failed: {exc}",
            )

    def _is_application_url(
        self,
        url: str,
    ) -> bool:
        """
        Return True only for URLs belonging to the authoritative
        application origin.
        """

        if not url:
            return False

        if not self._application_origin:
            return True

        try:
            parsed = urlparse(url)

            origin = (
                f"{parsed.scheme.lower()}://"
                f"{parsed.netloc.lower()}"
            )

            return origin == self._application_origin

        except Exception:
            return False

    # ======================================================
    # START
    # ======================================================

    async def start_capture(self) -> None:

        self.reset()

        logger.info(
            "NETWORK",
            "Capture Started",
        )

    # ======================================================
    # STOP
    # ======================================================

    async def stop_capture(self) -> None:

        if self._closed:
            return

        self._closed = True

        logger.info(
            "NETWORK",
            "Finalizing network discovery...",
        )

        self._finalize_result()

        logger.info(
            "NETWORK",
            (
                f"Requests={len(self.result.requests.items)} "
                f"Responses={len(self.result.responses.items)} "
                f"Endpoints={len(self.result.endpoints.items)}"
            ),
        )

    # ======================================================
    # REQUEST EVENT
    # ======================================================

    def _on_request(
        self,
        request: Request,
    ) -> None:

        if self._closed:
            return

        try:

            if self._is_static_request(request):
                return

            url = request.url
            
            # ----------------------------------------------------------
            # REAL EXTERNAL REDIRECT EVIDENCE
            # ----------------------------------------------------------
            #
            # Playwright preserves the HTTP redirect chain through
            # request.redirected_from.
            #
            # If the current request belongs to an external origin and
            # redirected_from points to our application origin, then the
            # application URL in redirected_from is a REAL browser-observed
            # redirect source.
            #
            # We record that source as evidence but NEVER retain the
            # external request as application traffic.
            # ----------------------------------------------------------
            
            if not self._is_application_url(url):
            
                try:
            
                    redirected_from = request.redirected_from
            
                    if redirected_from is not None:
            
                        source_url = (
                            redirected_from.url
                            or ""
                        ).strip()
            
                        if (
                            source_url
                            and self._is_application_url(
                                source_url
                            )
                        ):
            
                            normalized_source = (
                                self._normalize_url(
                                    source_url
                                )
                            )
            
                            if normalized_source:
            
                                self._external_redirect_sources.add(
                                    normalized_source
                                )
            
                                logger.info(
                                    "NETWORK",
                                    (
                                        "External redirect source observed: "
                                        f"{normalized_source}"
                                    ),
                                )
            
                except Exception as exc:
            
                    logger.debug(
                        "NETWORK",
                        (
                            "Redirect-chain observation failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )
            
                # External traffic remains outside application evidence.
                return
            
            request_id = str(id(request))

            method = (
                request.method or "GET"
            ).upper()

            resource_type = (
                request.resource_type or "other"
            ).lower()

            headers = self._build_headers(
                request.headers
            )

            post_data = (
                request.post_data or ""
            )

            redirected_from = ""

            try:

                if request.redirected_from:

                    redirected_from = (
                        request.redirected_from.url
                    )

            except Exception:

                redirected_from = ""

            item = NetworkRequest(

                id=request_id,

                url=url,

                method=method,

                resource_type=resource_type,

                headers=headers,

                post_data=post_data,

                redirected_from=redirected_from,

            )

            # --------------------------------------------------
            # Host tracking
            # --------------------------------------------------

            self._register_host(url)

            # --------------------------------------------------
            # Request deduplication
            # --------------------------------------------------

            request_key = (

                method,

                self._normalize_url(url),

                resource_type,

                post_data,

            )

            if request_key in self._seen_request_keys:

                # Keep the first actual request object.
                # Repeated browser traffic should not produce
                # repeated discovery records.
                return

            self._seen_request_keys.add(
                request_key
            )

            self._requests[request_id] = item

            logger.debug(
                "NETWORK",
                f"REQUEST {method} {url}",
            )

        except Exception as exc:

            logger.warning(
                "NETWORK",
                f"Request observation failed: {exc}",
            )

    # ======================================================
    # RESPONSE EVENT
    # ======================================================

    def _on_response(
        self,
        response: Response,
    ) -> None:

        if self._closed:
            return

        try:

            request = response.request

            if self._is_static_request(
                request
            ):

                return

            url = response.url

            status = int(
                response.status
            )
            
            # ----------------------------------------------------------
            # REAL HTTP REDIRECT EVIDENCE
            # ----------------------------------------------------------
            #
            # The Playwright Response object is authoritative here.
            #
            # If an application-origin HTTP 3xx response points to an
            # external origin through Location, the response URL itself
            # is the real redirect source.
            #
            # This must be recorded BEFORE normal response filtering.
            # ----------------------------------------------------------
            
            if (
                self._is_application_url(url)
                and 300 <= status < 400
            ):
            
                try:
            
                    location = (
                        response.headers.get(
                            "location",
                            "",
                        )
                        or ""
                    ).strip()
            
                    if location:
            
                        from urllib.parse import urljoin
            
                        redirect_target = urljoin(
                            url,
                            location,
                        )
            
                        if (
                            redirect_target
                            and not self._is_application_url(
                                redirect_target
                            )
                        ):
            
                            normalized_source = (
                                self._normalize_url(
                                    url
                                )
                            )
            
                            if normalized_source:
            
                                self._external_redirect_sources.add(
                                    normalized_source
                                )
            
                                logger.info(
                                    "NETWORK",
                                    (
                                        "Real external HTTP redirect observed; "
                                        "source excluded from crawl targets: "
                                        f"{normalized_source}"
                                    ),
                                )
            
                except Exception as exc:
            
                    logger.debug(
                        "NETWORK",
                        (
                            "HTTP redirect analysis failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )
            
            # External-origin responses remain outside application
            # network evidence.
            if not self._is_application_url(url):
                return
            
            request_id = str(
                id(request)
            )

            status_text = (
                response.status_text or ""
            )

            headers = self._build_headers(
                response.headers
            )

            mime_type = (
                response.headers.get(
                    "content-type",
                    "",
                )
                or ""
            )

            mime_type = mime_type.split(
                ";",
                1,
            )[0].strip().lower()

            body_size = self._content_length(
                response
            )

            item = NetworkResponse(

                request_id=request_id,

                url=url,

                status=status,

                status_text=status_text,

                mime_type=mime_type,

                headers=headers,

                body_size=body_size,

            )

            response_key = (

                request_id,

                status,

                self._normalize_url(url),

                mime_type,

            )

            if response_key in self._seen_response_keys:

                return

            self._seen_response_keys.add(
                response_key
            )

            self._responses[request_id] = item

            self._register_host(url)

            self._collect_security_headers(
                response.headers
            )

            self._collect_technology_headers(
                response.headers
            )

            logger.debug(
                "NETWORK",
                (
                    f"RESPONSE {status} "
                    f"{url}"
                ),
            )

        except Exception as exc:

            logger.warning(
                "NETWORK",
                f"Response observation failed: {exc}",
            )

    # ======================================================
    # REQUEST FAILED
    # ======================================================

    def _on_failed(
        self,
        request: Request,
    ) -> None:

        try:

            if self._is_static_request(
                request
            ):

                return

            if not self._is_application_url(
                request.url
            ):
                return

            request_id = str(
                id(request)
            )

            self._failed.add(
                request_id
            )

            logger.debug(
                "NETWORK",
                (
                    f"FAILED "
                    f"{request.method} "
                    f"{request.url}"
                ),
            )

        except Exception:

            pass

    # ======================================================
    # FINAL RESULT
    # ======================================================

    def _finalize_result(self) -> None:

        result = NetworkResult()

        # --------------------------------------------------
        # Requests
        # --------------------------------------------------

        for request in self._requests.values():

            result.requests.items.append(
                request
            )

        # --------------------------------------------------
        # Responses
        # --------------------------------------------------

        for response in self._responses.values():

            result.responses.items.append(
                response
            )

        # --------------------------------------------------
        # Endpoint discovery
        # --------------------------------------------------

        for request_id, request in (
            self._requests.items()
        ):

            response = self._responses.get(
                request_id
            )

            endpoint = self._build_endpoint(
                request,
                response,
            )

            if endpoint is None:
                continue

            endpoint_key = self._endpoint_key(
                endpoint
            )

            if endpoint_key in self._seen_endpoint_keys:
                continue

            self._seen_endpoint_keys.add(
                endpoint_key
            )

            result.endpoints.items.append(
                endpoint
            )

            if self._is_api_request(
                request,
                response,
            ):

                self._api_urls.add(
                    self._normalize_url(
                        request.url
                    )
                )

        # --------------------------------------------------
        # Additional network metadata
        # --------------------------------------------------

        result.api_endpoints.extend(
            sorted(
                self._api_urls
            )
        )

        result.unique_hosts.extend(
            sorted(
                self._hosts
            )
        )

        result.technologies.extend(
            sorted(
                self._technologies
            )
        )

        result.security_headers.update(
            self._security_headers
        )

        # --------------------------------------------------
        # Statistics
        # --------------------------------------------------

        self._update_statistics(
            result
        )

        self.result = result

    # ======================================================
    # ENDPOINT BUILDING
    # ======================================================

    def _build_endpoint(
        self,
        request: NetworkRequest,
        response: NetworkResponse | None,
    ) -> AttackEndpoint | None:

        try:

            url = request.url

            if not url:
                return None

            if self._is_static_url(
                url
            ):

                return None

            content_type = ""

            if response:

                content_type = (
                    response.mime_type or ""
                )

            endpoint = AttackEndpoint(

                url=url,

                method=request.method,

                source=self._endpoint_source(
                    request
                ),

                content_type=content_type,

                authenticated=False,

                parameters=[],

            )

            # --------------------------------------------------
            # Query parameters
            # --------------------------------------------------

            self._extract_query_parameters(
                request,
                endpoint,
            )

            # --------------------------------------------------
            # Form body
            # --------------------------------------------------

            self._extract_form_parameters(
                request,
                endpoint,
            )

            # --------------------------------------------------
            # JSON body
            # --------------------------------------------------

            self._extract_json_parameters(
                request,
                endpoint,
            )

            # --------------------------------------------------
            # GraphQL body
            # --------------------------------------------------

            self._extract_graphql_parameters(
                request,
                endpoint,
            )

            # --------------------------------------------------
            # Header names
            # --------------------------------------------------

            self._extract_header_parameters(
                request,
                endpoint,
            )

            return endpoint

        except Exception as exc:

            logger.warning(
                "NETWORK",
                f"Endpoint build failed: {exc}",
            )

            return None

    # ======================================================
    # QUERY PARAMETERS
    # ======================================================

    def _extract_query_parameters(
        self,
        request: NetworkRequest,
        endpoint: AttackEndpoint,
    ) -> None:

        try:

            parsed = urlparse(
                request.url
            )

            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )

            seen = set()

            for name, value in pairs:

                key = (
                    "query",
                    name,
                )

                if key in seen:
                    continue

                seen.add(key)

                endpoint.parameters.append(

                    AttackParameter(

                        name=name,

                        value=value,

                        location="query",

                        data_type=self._data_type(
                            value
                        ),

                    )

                )

        except Exception as exc:

            logger.debug(
                "NETWORK",
                f"Query parameter extraction failed: {exc}",
            )

    # ======================================================
    # FORM PARAMETERS
    # ======================================================

    def _extract_form_parameters(
        self,
        request: NetworkRequest,
        endpoint: AttackEndpoint,
    ) -> None:

        body = (
            request.post_data or ""
        )

        if not body:
            return

        content_type = (
            self._request_content_type(
                request
            )
        )

        if (
            "application/x-www-form-urlencoded"
            not in content_type
        ):

            return

        try:

            pairs = parse_qsl(
                body,
                keep_blank_values=True,
            )

            existing = {
                (
                    p.location,
                    p.name,
                )
                for p in endpoint.parameters
            }

            for name, value in pairs:

                key = (
                    "body",
                    name,
                )

                if key in existing:
                    continue

                endpoint.parameters.append(

                    AttackParameter(

                        name=name,

                        value=value,

                        location="body",

                        data_type=self._data_type(
                            value
                        ),

                    )

                )

                existing.add(key)

        except Exception as exc:

            logger.debug(
                "NETWORK",
                f"Form extraction failed: {exc}",
            )

    # ======================================================
    # JSON PARAMETERS
    # ======================================================

    def _extract_json_parameters(
        self,
        request: NetworkRequest,
        endpoint: AttackEndpoint,
    ) -> None:

        body = (
            request.post_data or ""
        )

        if not body:
            return

        content_type = (
            endpoint.content_type or ""
        ).lower()

        request_content_type = (
            self._request_content_type(
                request
            )
        )

        if (
            "json" not in content_type
            and "json" not in request_content_type
        ):

            return

        try:

            data = json.loads(
                body
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):

            return

        self._append_json_parameters(
            endpoint,
            data,
        )
        
    def get_external_redirect_sources(self) -> set[str]:
        """
        Return application-origin URLs that the real browser observed
        redirecting to an external origin.

        These are evidence records only.
        """

        return set(
            self._external_redirect_sources
        )

    # ======================================================
    # JSON RECURSION
    # ======================================================

    def _append_json_parameters(
        self,
        endpoint: AttackEndpoint,
        data,
        prefix: str = "",
    ) -> None:

        if isinstance(
            data,
            dict,
        ):

            for name, value in data.items():

                full_name = (
                    f"{prefix}.{name}"
                    if prefix
                    else str(name)
                )

                if isinstance(
                    value,
                    (dict, list),
                ):

                    self._append_json_parameters(
                        endpoint,
                        value,
                        full_name,
                    )

                    continue

                endpoint.parameters.append(

                    AttackParameter(

                        name=full_name,

                        value=str(value),

                        location="json",

                        data_type=self._data_type(
                            value
                        ),

                    )

                )

        elif isinstance(
            data,
            list,
        ):

            for index, value in enumerate(
                data
            ):

                full_name = (
                    f"{prefix}[{index}]"
                    if prefix
                    else f"[{index}]"
                )

                if isinstance(
                    value,
                    (dict, list),
                ):

                    self._append_json_parameters(
                        endpoint,
                        value,
                        full_name,
                    )

                else:

                    endpoint.parameters.append(

                        AttackParameter(

                            name=full_name,

                            value=str(value),

                            location="json",

                            data_type=self._data_type(
                                value
                            ),

                        )

                    )

    # ======================================================
    # GRAPHQL
    # ======================================================

    def _extract_graphql_parameters(
        self,
        request: NetworkRequest,
        endpoint: AttackEndpoint,
    ) -> None:

        body = (
            request.post_data or ""
        )

        if not body:
            return

        content_type = (
            endpoint.content_type or ""
        ).lower()

        looks_like_graphql = (

            "graphql" in content_type

            or "/graphql" in
            urlparse(
                request.url
            ).path.lower()

        )

        if not looks_like_graphql:
            return

        try:

            data = json.loads(
                body
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):

            return

        if not isinstance(
            data,
            dict,
        ):

            return

        for field_name in (
            "query",
            "operationName",
        ):

            if field_name not in data:
                continue

            value = data.get(
                field_name
            )

            endpoint.parameters.append(

                AttackParameter(

                    name=field_name,

                    value=str(value),

                    location="json",

                    data_type="string",

                )

            )

        variables = data.get(
            "variables"
        )

        if variables is not None:

            self._append_json_parameters(
                endpoint,
                variables,
                "variables",
            )

    # ======================================================
    # HEADER METADATA
    # ======================================================

    def _extract_header_parameters(
        self,
        request: NetworkRequest,
        endpoint: AttackEndpoint,
    ) -> None:
        """
        Record selected request metadata as discovery
        parameters.

        We intentionally record header names rather than
        treating headers as vulnerability payloads.
        """

        interesting_headers = {
            "authorization",
            "content-type",
            "accept",
            "x-requested-with",
            "x-csrf-token",
            "x-xsrf-token",
        }

        existing = {
            (
                p.location,
                p.name,
            )
            for p in endpoint.parameters
        }

        for header in request.headers:

            name = (
                header.name or ""
            ).lower()

            if name not in interesting_headers:
                continue

            key = (
                "header",
                name,
            )

            if key in existing:
                continue

            endpoint.parameters.append(

                AttackParameter(

                    name=name,

                    value=header.value or "",

                    location="header",

                    data_type="string",

                )

            )

            existing.add(key)

    # ======================================================
    # API DETECTION
    # ======================================================

    def _is_api_request(
        self,
        request: NetworkRequest,
        response: NetworkResponse | None,
    ) -> bool:

        resource_type = (
            request.resource_type or ""
        ).lower()

        if resource_type in {
            "xhr",
            "fetch",
            "websocket",
            "eventsource",
        }:

            return True

        request_content_type = (
            self._request_content_type(
                request
            )
        )

        if any(
            token in request_content_type
            for token in (
                "json",
                "graphql",
            )
        ):

            return True

        if response:

            mime = (
                response.mime_type or ""
            ).lower()

            if any(
                token in mime
                for token in (
                    "json",
                    "graphql",
                )
            ):

                return True

        # --------------------------------------------------
        # No path-name guessing.
        #
        # A request is classified as application/API-style
        # communication only from browser-observed request/
        # response characteristics.
        #
        # The URL path itself is never used as a predefined
        # API detector.
        # --------------------------------------------------
        
        return False
        
    # ======================================================
    # ENDPOINT SOURCE
    # ======================================================

    @staticmethod
    def _endpoint_source(
        request: NetworkRequest,
    ) -> str:

        resource_type = (
            request.resource_type or ""
        ).lower()

        mapping = {

            "xhr": "xhr",

            "fetch": "fetch",

            "websocket": "websocket",

            "eventsource": "eventsource",

            "document": "navigation",

            "script": "script",

        }

        return mapping.get(
            resource_type,
            resource_type or "network",
        )

    # ======================================================
    # STATIC REQUEST CHECK
    # ======================================================

    def _is_static_request(
        self,
        request: Request,
    ) -> bool:

        try:

            resource_type = (
                request.resource_type or ""
            ).lower()

            if resource_type in STATIC_RESOURCE_TYPES:

                return True

            return self._is_static_url(
                request.url
            )

        except Exception:

            return False

    # ======================================================
    # STATIC URL CHECK
    # ======================================================

    @staticmethod
    def _is_static_url(
        url: str,
    ) -> bool:

        try:

            path = (
                urlparse(
                    url
                ).path.lower()
            )

            return any(
                path.endswith(ext)
                for ext in STATIC_EXTENSIONS
            )

        except Exception:

            return False

    # ======================================================
    # URL NORMALIZATION
    # ======================================================

    @staticmethod
    def _normalize_url(
        url: str,
    ) -> str:

        try:

            parsed = urlparse(
                url
            )

            scheme = (
                parsed.scheme.lower()
            )

            host = (
                parsed.netloc.lower()
            )

            path = (
                parsed.path or "/"
            )

            return (
                f"{scheme}://"
                f"{host}"
                f"{path}"
                f"?{parsed.query}"
                if parsed.query
                else
                f"{scheme}://"
                f"{host}"
                f"{path}"
            )

        except Exception:

            return url

    # ======================================================
    # HEADERS
    # ======================================================

    @staticmethod
    def _build_headers(
        headers: dict,
    ) -> list[HeaderInfo]:

        result = []

        for name, value in (
            headers or {}
        ).items():

            result.append(

                HeaderInfo(

                    name=str(name),

                    value=str(value),

                )

            )

        return result

    # ======================================================
    # CONTENT LENGTH
    # ======================================================

    @staticmethod
    def _content_length(
        response: Response,
    ) -> int:

        try:

            value = response.headers.get(
                "content-length"
            )

            if value:

                return int(value)

        except (
            ValueError,
            TypeError,
        ):

            pass

        return 0

    # ======================================================
    # REQUEST CONTENT TYPE
    # ======================================================

    @staticmethod
    def _request_content_type(
        request: NetworkRequest,
    ) -> str:

        for header in request.headers:

            if (
                header.name.lower()
                == "content-type"
            ):

                return (
                    header.value or ""
                ).lower()

        return ""

    # ======================================================
    # HOST TRACKING
    # ======================================================

    def _register_host(
        self,
        url: str,
    ) -> None:

        try:

            parsed = urlparse(
                url
            )

            host = (
                parsed.netloc.lower()
            )

            if host:

                self._hosts.add(
                    host
                )

        except Exception:

            pass

    # ======================================================
    # SECURITY HEADERS
    # ======================================================

    def _collect_security_headers(
        self,
        headers: dict,
    ) -> None:

        interesting = {
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        }

        for name, value in (
            headers or {}
        ).items():

            normalized = (
                name.lower()
            )

            if normalized in interesting:

                self._security_headers[
                    normalized
                ] = str(value)

    # ======================================================
    # TECHNOLOGY HEADERS
    # ======================================================

    def _collect_technology_headers(
        self,
        headers: dict,
    ) -> None:

        for name in (
            "server",
            "x-powered-by",
            "x-generator",
        ):

            value = (
                headers or {}
            ).get(name)

            if value:

                self._technologies.add(
                    f"{name}: {value}"
                )

    # ======================================================
    # DATA TYPE
    # ======================================================

    @staticmethod
    def _data_type(
        value,
    ) -> str:

        if isinstance(
            value,
            bool,
        ):

            return "bool"

        if isinstance(
            value,
            int,
        ):

            return "int"

        if isinstance(
            value,
            float,
        ):

            return "float"

        if isinstance(
            value,
            list,
        ):

            return "array"

        if isinstance(
            value,
            dict,
        ):

            return "json"

        return "string"

    # ======================================================
    # ENDPOINT KEY
    # ======================================================

    @staticmethod
    def _endpoint_key(
        endpoint: AttackEndpoint,
    ) -> tuple:

        parameters = tuple(
            sorted(
                (
                    parameter.location,
                    parameter.name,
                    parameter.data_type,
                )
                for parameter
                in endpoint.parameters
            )
        )

        return (

            endpoint.method.upper(),

            NetworkCollector._normalize_url(
                endpoint.url
            ),

            endpoint.source,

            parameters,

        )

    # ======================================================
    # STATISTICS
    # ======================================================

    @staticmethod
    def _update_statistics(
        result: NetworkResult,
    ) -> None:
        """
        ExtractorResult already owns statistics in the
        current AVAF model. Keep this defensive so the
        collector remains compatible if the statistics
        implementation changes.
        """

        containers = (
            result.requests,
            result.responses,
            result.endpoints,
        )

        for container in containers:

            try:

                container.statistics.total = len(
                    container.items
                )

                container.statistics.discovered = len(
                    container.items
                )

            except Exception:

                pass

    # ======================================================
    # RESULT
    # ======================================================

    def build_result(
        self,
    ) -> NetworkResult:

        return self.result
