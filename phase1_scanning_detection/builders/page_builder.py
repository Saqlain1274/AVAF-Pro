"""
===============================================================================
AVAF Pro

Page Builder

Creates the final PageResult returned by the crawler.

Responsibilities
----------------
✓ Wrap DiscoveryResult
✓ Attach crawler metadata
✓ Keep PageResult creation centralized

Never
-----
✘ Crawl pages
✘ Parse HTML
✘ Modify DiscoveryResult
✘ Validate vulnerabilities
===============================================================================
"""

from __future__ import annotations

from phase1_scanning_detection.discovery.model import DiscoveryResult
from phase1_scanning_detection.models.model import PageResult


class PageBuilder:
    """
    Converts DiscoveryResult into PageResult.
    """

    def build(
        self,
        discovery: DiscoveryResult,
        *,
        url: str,
        final_url: str,
        title: str,
        status: int,
        depth: int,
        screenshot: str = "",
        html: str = "",
        dom_hash: str = "",
        content_hash: str = "",
        render_time: float = 0.0,
        metadata: dict | None = None,
    ) -> PageResult:

        page = PageResult(

            url=url,

            final_url=final_url,

            title=title,

            status=status,

            depth=depth,

            screenshot=screenshot,

            html=html,

            discovery=discovery,

            dom_hash=dom_hash,

            content_hash=content_hash,

            render_time=render_time,

            metadata=metadata or {},
        )

        return page
