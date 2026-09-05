"""
===============================================================================
AVAF Pro
Link Extractor

Responsible ONLY for discovering static hyperlinks.

Does NOT:
    - Click links
    - Visit links
    - Queue links
    - Execute JavaScript

Returns:
    ExtractorResult[LinkInfo]
===============================================================================
"""

from __future__ import annotations

import logging

from typing import List, Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import Page

from ..base_extractor import BaseExtractor
from ..model import (
    LinkInfo,
    ExtractorResult,
)

logger = logging.getLogger(__name__)


class LinkExtractor(BaseExtractor):
    """
    Passive hyperlink extractor.
    """

    def __init__(self):
        super().__init__()

    # ==========================================================
    # Public API
    # ==========================================================

    async def extract(
        self,
        page: Page
    ) -> ExtractorResult:
        """
        Extract unique static hyperlinks from the current page.
        """

        self.start()

        self.logger.info("Extracting hyperlinks...")

        try:
            elements = await page.query_selector_all("a[href]")

        except Exception as exc:
            self.error(exc)
            return self.finish()

        self.set_total(len(elements))

        seen: set[str] = set()

        for element in elements:

            try:

                href = await element.get_attribute("href")

                url = self.normalize_url(
                    page.url,
                    href
                )

                # ----------------------------------------------
                # Invalid / ignored link
                # ----------------------------------------------

                if url is None:
                    self.ignore()
                    continue

                # ----------------------------------------------
                # Duplicate link
                # ----------------------------------------------

                if url in seen:
                    self.duplicate()
                    continue

                seen.add(url)

                # ----------------------------------------------
                # Read metadata safely
                # ----------------------------------------------

                try:
                    text = (
                        await element.inner_text()
                    ).strip()

                except Exception:
                    text = ""

                title = (
                    await element.get_attribute("title")
                    or ""
                )

                rel = (
                    await element.get_attribute("rel")
                    or ""
                )

                target = (
                    await element.get_attribute("target")
                    or ""
                )

                # ----------------------------------------------
                # Create normalized model
                # ----------------------------------------------

                link = LinkInfo(
                    url=url,
                    text=text,
                    title=title,
                    rel=rel,
                    target=target,
                    internal=self.is_internal(
                        page.url,
                        url
                    ),
                )

                self.add_item(link)

            except Exception as exc:

                self.error(exc)

        return self.finish()

    # ==========================================================
    # URL Normalization
    # ==========================================================

    @staticmethod
    def normalize_url(
        base_url: str,
        href: Optional[str]
    ) -> Optional[str]:
        """
        Convert a discovered href into an absolute URL.

        Non-navigation schemes are ignored.
        """

        if not href:
            return None

        href = href.strip()

        if not href:
            return None

        lowered = href.lower()

        ignored = (
            "#",
            "javascript:",
            "mailto:",
            "tel:",
            "sms:",
            "data:",
        )

        for prefix in ignored:

            if lowered.startswith(prefix):
                return None

        try:

            normalized = urljoin(
                base_url,
                href
            )

            parsed = urlparse(normalized)

            # Only HTTP/HTTPS links belong in web discovery
            if parsed.scheme.lower() not in (
                "http",
                "https",
            ):
                return None

            if not parsed.netloc:
                return None

            # Remove fragments because:
            #
            # page.php#top
            # page.php#footer
            #
            # are still the same HTTP resource.

            parsed = parsed._replace(
                fragment=""
            )

            return parsed.geturl()

        except Exception:

            return None

    # ==========================================================
    # Internal / External Detection
    # ==========================================================

    @staticmethod
    def is_internal(
        base_url: str,
        target_url: str
    ) -> bool:
        """
        Determine whether the discovered link belongs to
        the same host as the current page.
        """

        try:

            base = urlparse(base_url)

            target = urlparse(target_url)

            return (
                base.netloc.lower()
                ==
                target.netloc.lower()
            )

        except Exception:

            return False

    # ==========================================================
    # Query Parameters
    # ==========================================================

    @staticmethod
    def extract_parameters(
        links: List[LinkInfo]
    ) -> List[str]:
        """
        Extract unique query parameter names from links.

        Example:

            /product?id=10&category=books

        returns:

            ["category", "id"]
        """

        parameters: set[str] = set()

        for link in links:

            try:

                parsed = urlparse(
                    link.url
                )

                if not parsed.query:
                    continue

                for item in parsed.query.split("&"):

                    if "=" not in item:
                        continue

                    key = item.split(
                        "=",
                        1
                    )[0].strip()

                    if key:
                        parameters.add(key)

            except Exception:
                continue

        return sorted(parameters)