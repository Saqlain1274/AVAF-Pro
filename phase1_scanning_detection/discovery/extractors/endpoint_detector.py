"""
===============================================================================
AVAF Pro

Browser-Observed Endpoint Detector
===============================================================================

This component does NOT discover endpoints by scanning arbitrary HTML.

Phase 1 is behavior-first.

Valid endpoint observations must originate from the browser observation
pipeline, for example:

    - rendered DOM navigation
    - actual browser navigation
    - fetch()
    - XMLHttpRequest
    - runtime navigation
    - form submission
    - History API
    - window.open()
    - application-generated network requests

This class only normalizes endpoint observations supplied by those
observation sources.

It must NEVER:

    - generate URLs
    - use a wordlist
    - guess common paths
    - classify paths by names such as /login or /admin
    - scan arbitrary JavaScript source for endpoint-looking strings
    - scan comments for endpoint-looking strings
    - treat CSS/images/fonts as application endpoints
    - validate vulnerabilities
    - attack the target
===============================================================================
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..base_extractor import BaseExtractor
from ..model import EndpointInfo
from ..model import ExtractorResult


class EndpointDetector(BaseExtractor):

    def __init__(self):
        super().__init__()

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def extract(
        self,
        base_url: str,
        observed_endpoints=None,
    ) -> ExtractorResult:
        """
        Normalize endpoints that were ALREADY observed by the browser.

        `observed_endpoints` may contain:

            str
            dict

        A string is treated as an already observed URL.

        A dictionary may contain:

            url
            endpoint
            method
            source
            category

        No endpoint is generated here.

        No HTML scanning occurs here.
        """

        self.start()

        try:

            observations = (
                observed_endpoints
                if observed_endpoints is not None
                else []
            )

            if isinstance(
                observations,
                (str, bytes),
            ):
                observations = [
                    observations
                ]

            observations = list(
                observations
            )

            self.set_total(
                len(observations)
            )

            seen = set()

            for observation in observations:

                self._extract_observed_endpoint(
                    base_url=base_url,
                    observation=observation,
                    seen=seen,
                )

        except Exception as exc:

            self.error(exc)

            self.warning(
                "Unable to normalize observed endpoints."
            )

        return self.finish()

    # ==========================================================
    # OBSERVED ENDPOINT NORMALIZATION
    # ==========================================================

    def _extract_observed_endpoint(
        self,
        base_url: str,
        observation,
        seen: set,
    ) -> None:

        try:

            if isinstance(
                observation,
                str,
            ):

                raw_url = observation.strip()

                if not raw_url:
                    return

                method = "GET"

                source = (
                    "browser-observation"
                )

                category = (
                    "endpoint"
                )

            elif isinstance(
                observation,
                dict,
            ):

                raw_url = str(
                    observation.get(
                        "url"
                    )
                    or observation.get(
                        "endpoint"
                    )
                    or ""
                ).strip()

                if not raw_url:
                    return

                method = str(
                    observation.get(
                        "method"
                    )
                    or "GET"
                ).upper()

                source = str(
                    observation.get(
                        "source"
                    )
                    or "browser-observation"
                )

                category = str(
                    observation.get(
                        "category"
                    )
                    or "endpoint"
                )

            else:

                return

            absolute = urljoin(
                base_url,
                raw_url,
            )

            if not self._is_http_url(
                absolute
            ):
                return

            key = (
                method,
                absolute,
                category,
                source,
            )

            if key in seen:

                self.duplicate()

                return

            seen.add(
                key
            )

            self.add_item(
                EndpointInfo(
                    url=absolute,
                    category=category,
                )
            )

        except Exception as exc:

            self.error(exc)

    # ==========================================================
    # URL VALIDATION
    # ==========================================================

    @staticmethod
    def _is_http_url(
        url: str,
    ) -> bool:

        lower = url.lower()

        return (
            lower.startswith(
                "http://"
            )
            or
            lower.startswith(
                "https://"
            )
        )