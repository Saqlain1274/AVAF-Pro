"""
AVAF PRO
Deduplication Engine

Responsibilities
----------------
✔ URL Canonicalization
✔ Duplicate URL Detection
✔ DOM Hashing
✔ HTML Hashing
✔ Screenshot Hashing
"""

from __future__ import annotations

import hashlib
import re

from urllib.parse import (
    urlparse,
    urlunparse,
    parse_qsl,
    urlencode
)


class Deduplicator:

    def __init__(self):

        self.urls = set()

        self.dom_hashes = set()

        self.content_hashes = set()

        self.image_hashes = set()
        
    def reset(self):
        """Reset all deduplication state for a new scan."""
        self.urls.clear()
        self.dom_hashes.clear()
        self.content_hashes.clear()
        self.image_hashes.clear()

    # ======================================================
    # Canonical URL
    # ======================================================

    def canonicalize(self, url: str) -> str:

        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        netloc = parsed.netloc.lower()

        path = parsed.path or "/"

        path = re.sub(r"/+", "/", path)
        
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        params = [
        
            (k, v)
        
            for k, v in parse_qsl(
        
                parsed.query,
        
                keep_blank_values=True
        
            )
        
            if not k.lower().startswith("utm_")
        
            and k.lower() not in {
        
                "fbclid",
        
                "gclid",
        
                "msclkid"
        
            }
        
        ]
        
        query = urlencode(
        
            sorted(params)
        
        ) 

        return urlunparse(

            (

                scheme,

                netloc,

                path,

                "",

                query,

                ""

            )

        )

    # ======================================================
    # URL
    # ======================================================

    def seen_url(self, url):

        url = self.canonicalize(url)

        if url in self.urls:

            return True

        self.urls.add(url)

        return False

    # ======================================================
    # DOM
    # ======================================================

    def dom_hash(self, dom):

        dom = re.sub(r"\s+", " ", dom)

        dom = re.sub(
        
            r'nonce="[^"]*"',
        
            "",
        
            dom,
        
            flags=re.I
        
        )
        
        dom = re.sub(
        
            r'csrf[^"]*',
        
            "",
        
            dom,
        
            flags=re.I
        
        )
        
        return hashlib.sha256(
        
            dom.encode()
        
        ).hexdigest()

        return hashlib.sha256(

            dom.encode()

        ).hexdigest()

    def seen_dom(self, dom):

        h = self.dom_hash(dom)

        if h in self.dom_hashes:

            return True

        self.dom_hashes.add(h)

        return False

    # ======================================================
    # HTML
    # ======================================================

    def html_hash(self, html):

        html = re.sub(

            r'nonce="[^"]*"',
        
            "",
        
            html,
        
            flags=re.I
        
        )
        
        html = re.sub(
        
            r'csrf[^"]*',
        
            "",
        
            html,
        
            flags=re.I
        
        )

        html = re.sub(

            r"\s+",

            " ",

            html

        )

        html = re.sub(

            r'csrf[^"]*',

            "",

            html,

            flags=re.I

        )

        return hashlib.sha256(

            html.encode()

        ).hexdigest()

    def seen_html(self, html):

        h = self.html_hash(html)

        if h in self.content_hashes:

            return True

        self.content_hashes.add(h)

        return False

    # ======================================================
    # IMAGE
    # ======================================================

    def image_hash(self, data):

        return hashlib.sha256(data).hexdigest()

    def seen_image(self, data):

        h = self.image_hash(data)

        if h in self.image_hashes:

            return True

        self.image_hashes.add(h)

        return False
    
    # ======================================================
    # RESET
    # ======================================================

    def reset(self):

        self.urls.clear()

        self.dom_hashes.clear()

        self.content_hashes.clear()

        self.image_hashes.clear()
        
    # ======================================================
    # UNIQUE URL
    # ======================================================

    def is_unique(self, url: str) -> bool:

        return not self.seen_url(url)
    
    # ======================================================
    # EXPORT
    # ======================================================

    def export(self):

        return {

            "urls": len(self.urls),

            "dom_hashes": len(self.dom_hashes),

            "content_hashes": len(self.content_hashes),

            "image_hashes": len(self.image_hashes)

        }