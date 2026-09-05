"""
===============================================================================
AVAF Pro

Technology Detector

Passive technology fingerprint detector.

Responsibilities
----------------
✓ HTML Analysis
✓ Meta Tag Analysis
✓ Script Analysis
✓ Framework Detection
✓ CMS Detection

Never
-----
✘ Execute JavaScript
✘ Runtime Analysis
✘ Active Scanning
===============================================================================
"""

from __future__ import annotations

import re

from ..base_extractor import BaseExtractor
from ..model import (
    ExtractorResult,
    MetaTag,
    ScriptInfo,
)


class TechnologyDetector(BaseExtractor):

    def __init__(self):

        super().__init__()

        self.rules = {

            "React": [

                re.compile(r"react", re.I),
                re.compile(r"_next", re.I),
                re.compile(r"react-dom", re.I),

            ],

            "Next.js": [

                re.compile(r"_next", re.I),
                re.compile(r"\bnext\b", re.I),

            ],

            "Vue.js": [

                re.compile(r"vue", re.I),

            ],

            "Angular": [

                re.compile(r"angular", re.I),
                re.compile(r"ng-", re.I),

            ],

            "jQuery": [

                re.compile(r"jquery", re.I),

            ],

            "Bootstrap": [

                re.compile(r"bootstrap", re.I),

            ],

            "TailwindCSS": [

                re.compile(r"tailwind", re.I),

            ],

            "WordPress": [

                re.compile(r"wp-content", re.I),
                re.compile(r"wp-json", re.I),
                re.compile(r"wordpress", re.I),

            ],

            "Laravel": [

                re.compile(r"laravel", re.I),
                re.compile(r"csrf-token", re.I),

            ],

            "Django": [

                re.compile(r"csrfmiddlewaretoken", re.I),

            ],

            "Flask": [

                re.compile(r"flask", re.I),

            ],

            "ASP.NET": [

                re.compile(r"__viewstate", re.I),
                re.compile(r"__eventvalidation", re.I),
                re.compile(r"asp\.net", re.I),

            ],

            "Cloudflare": [

                re.compile(r"cloudflare", re.I),

            ],

            "Google Analytics": [

                re.compile(r"google-analytics", re.I),
                re.compile(r"gtag", re.I),
                re.compile(r"analytics\.js", re.I),

            ],

            "reCAPTCHA": [

                re.compile(r"recaptcha", re.I),

            ],

        }

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def extract(
        self,
        html: str,
        meta_tags: list[MetaTag],
        scripts: list[ScriptInfo],
    ) -> ExtractorResult:

        self.start()

        try:

            search_text = self._build_search_text(

                html,
                meta_tags,
                scripts,

            )

            self.set_total(

                len(self.rules)

            )

            for technology in self.rules:

                self._detect_technology(

                    technology,
                    search_text,

                )

        except Exception as exc:

            self.error(exc)

            self.warning(

                "Unable to fingerprint technologies."

            )

        return self.finish()

    # ==========================================================
    # BUILD SEARCH TEXT
    # ==========================================================

    def _build_search_text(

        self,
        html: str,
        meta_tags: list[MetaTag],
        scripts: list[ScriptInfo],

    ) -> str:

        parts = [html]

        for meta in meta_tags:

            parts.append(meta.name)
            parts.append(meta.content)

        for script in scripts:

            parts.append(script.src)
            parts.append(script.script_type)

        return " ".join(parts).lower()

    # ==========================================================
    # DETECT TECHNOLOGY
    # ==========================================================

    def _detect_technology(

        self,
        technology: str,
        text: str,

    ) -> None:

        if self._matches(

            technology,
            text,

        ):

            self.add_item(

                technology

            )

    # ==========================================================
    # MATCH RULES
    # ==========================================================

    def _matches(

        self,
        technology: str,
        text: str,

    ) -> bool:

        patterns = self.rules.get(

            technology,
            [],

        )

        for pattern in patterns:

            if pattern.search(text):

                return True

        return False