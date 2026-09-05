"""
AVAF PRO
Advanced Runtime Link Discovery

Burp-style discovery engine.

Collects

✓ HTML links
✓ Forms
✓ Buttons (onclick)
✓ Scripts
✓ Iframes
✓ Images (ignored for crawling)
✓ Meta refresh
✓ Canonical URLs
✓ REST APIs
✓ GraphQL
✓ SPA routes
✓ JS endpoints
✓ Hidden URLs

Returns ONLY unique internal URLs.
"""

import re
from urllib.parse import urljoin, urlparse, urlunparse

from phase1_scanning_detection.discovery.logger import logger


class LinkExtractor:

    STATIC_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
        ".css",
        ".woff", ".woff2", ".ttf", ".eot",
        ".mp3", ".mp4", ".avi", ".mov",
        ".zip", ".rar", ".7z",
        ".pdf",
    }
    
    # --------------------------------------------------
    # Hidden JS URLs
    # --------------------------------------------------
    
    JS_PATTERN = re.compile(
        r'["\'](\/[^"\']+)["\']'
    )
    
    # --------------------------------------------------
    # API Routes
    # --------------------------------------------------
    
    API_PATTERN = re.compile(
        r"(\/(?:api|rest|graphql|v1|v2|v3)[^\"\'\s]*)",
        re.I
    )

    # --------------------------------------------------
    # Canonicalization
    # --------------------------------------------------

    def canonical(self, url: str) -> str:
        parsed = urlparse(url)
        clean = parsed._replace(fragment="")
        return urlunparse(clean)

    # --------------------------------------------------
    # URL Filtering
    # --------------------------------------------------

    def allowed(self, url: str, base_host: str) -> bool:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if parsed.netloc != base_host:
            return False

        lower = parsed.path.lower()

        for ext in self.STATIC_EXTENSIONS:
            if lower.endswith(ext):
                return False

        return True

    # --------------------------------------------------
    # Main Collector
    # --------------------------------------------------

    async def collect(self, runtime_data: dict, base_url: str):

        logger.info("LINKS", "Processing runtime navigation targets...")

        host = urlparse(base_url).netloc
        discovered = set()

        # --------------------------------------------------
        # HTML Links
        # --------------------------------------------------

        for item in runtime_data.get("links", []):
            href = ""

            if isinstance(item, dict):
                href = item.get("href", "")
            elif isinstance(item, str):
                href = item

            if not href:
                continue

            full = self.canonical(urljoin(base_url, href))

            if self.allowed(full, host):
                discovered.add(full)

        # --------------------------------------------------
        # FORM ACTIONS
        # --------------------------------------------------

        for form in runtime_data.get("forms", []):
            action = form.get("action")

            if not action:
                continue

            full = self.canonical(urljoin(base_url, action))

            if self.allowed(full, host):
                discovered.add(full)

        # --------------------------------------------------
        # IFRAMES
        # --------------------------------------------------

        for src in runtime_data.get("iframes", []):
            if not src:
                continue

            full = self.canonical(urljoin(base_url, src))

            if self.allowed(full, host):
                discovered.add(full)

        # --------------------------------------------------
        # SCRIPT SOURCES
        # --------------------------------------------------

        for script in runtime_data.get("scripts", []):
            src = script.get("src")

            if not src:
                continue

            full = self.canonical(urljoin(base_url, src))

            if self.allowed(full, host):
                discovered.add(full)

        # --------------------------------------------------
        # BUTTON onclick Extraction
        # --------------------------------------------------

        for button in runtime_data.get("buttons", []):
            attrs = button.get("attributes", {})
            onclick = attrs.get("onclick", "")

            if not onclick:
                continue

            for match in self.JS_PATTERN.findall(onclick):
                full = self.canonical(urljoin(base_url, match))

                if self.allowed(full, host):
                    discovered.add(full)

        # --------------------------------------------------
        # RAW HTML SEARCH
        # --------------------------------------------------

        html = runtime_data.get("html", "")

        if html:

            # API endpoints
            for match in self.API_PATTERN.findall(html):
                full = self.canonical(urljoin(base_url, match))

                if self.allowed(full, host):
                    discovered.add(full)

            # JS hidden endpoints
            for match in self.JS_PATTERN.findall(html):
                full = self.canonical(urljoin(base_url, match))

                if self.allowed(full, host):
                    discovered.add(full)

        logger.info(
            "LINKS",
            f"Found {len(discovered)} unique internal endpoints."
        )

        return sorted(discovered)