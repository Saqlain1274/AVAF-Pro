"""
===============================================================================
AVAF Pro

Meta Extractor

Extracts HTML meta tags.

Responsibilities
----------------
✓ Meta Name
✓ Meta Property
✓ Charset
✓ HTTP Equiv
✓ Content

Never
-----
✘ Execute JavaScript
✘ Modify DOM
✘ Visit Links
===============================================================================
"""

from __future__ import annotations

from playwright.async_api import Page

from ..base_extractor import BaseExtractor
from ..model import (
    ExtractorResult,
    MetaTag,
)


class MetaExtractor(BaseExtractor):

    def __init__(self):

        super().__init__()

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    async def extract(
        self,
        page: Page,
    ) -> ExtractorResult:

        self.start()

        try:

            elements = await page.query_selector_all(
                "meta"
            )

            self.set_total(len(elements))

            for element in elements:

                meta = await self._extract_meta(
                    element
                )

                if meta is None:
                    continue

                self.add_item(meta)

        except Exception as exc:

            self.error(exc)

            self.warning(
                "Unable to extract meta tags."
            )

        return self.finish()

    # ==========================================================
    # META EXTRACTION
    # ==========================================================

    async def _extract_meta(
        self,
        element,
    ) -> MetaTag | None:

        try:

            name = await self._read_name(
                element
            )

            content = (
                await element.get_attribute(
                    "content"
                )
                or ""
            )

            return self._build_meta(
                name,
                content,
            )

        except Exception as exc:

            self.error(exc)

            return None

    # ==========================================================
    # BUILD MODEL
    # ==========================================================

    @staticmethod
    def _build_meta(
        name: str,
        content: str,
    ) -> MetaTag:

        return MetaTag(

            name=name,

            content=content,

        )

    # ==========================================================
    # HELPERS
    # ==========================================================

    async def _read_name(
        self,
        element,
    ) -> str:

        attributes = (

            "name",

            "property",

            "charset",

            "http-equiv",

        )

        for attribute in attributes:

            value = await element.get_attribute(
                attribute
            )

            if value:

                return value

        return ""