"""
===============================================================================
AVAF Pro

Script Extractor

Extracts JavaScript resources.

Responsibilities
----------------
✓ External Scripts
✓ Inline Scripts
✓ Module Scripts
✓ Async
✓ Defer
✓ Integrity
✓ Cross-Origin
✓ Script Size
✓ Minified Detection

Never
-----
✘ Execute JavaScript
✘ Modify DOM
✘ Visit URLs
===============================================================================
"""

from __future__ import annotations

from playwright.async_api import Page

from ..base_extractor import BaseExtractor
from ..model import (
    ExtractorResult,
    ScriptInfo,
)


class ScriptExtractor(BaseExtractor):

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

            scripts = await page.query_selector_all(
                "script"
            )

            self.set_total(len(scripts))

            for script in scripts:

                info = await self._extract_script(
                    script
                )

                if info is None:
                    continue

                self.add_item(info)

        except Exception as exc:

            self.error(exc)

            self.warning(
                "Unable to extract JavaScript resources."
            )

        return self.finish()

    # ==========================================================
    # SCRIPT EXTRACTION
    # ==========================================================

    async def _extract_script(
        self,
        script,
    ) -> ScriptInfo | None:

        try:

            src = await self._read_src(script)

            inline = src == ""

            content = await self._read_inline(
                script,
                inline,
            )

            return await self._build_script(
                script,
                src,
                inline,
                content,
            )

        except Exception as exc:

            self.error(exc)

            return None

    # ==========================================================
    # BUILD MODEL
    # ==========================================================

    async def _build_script(
        self,
        script,
        src: str,
        inline: bool,
        content: str,
    ) -> ScriptInfo:

        return ScriptInfo(

            src=src,

            script_type=await self._read_type(
                script
            ),

            inline=inline,

            async_script=await self._is_async(
                script
            ),

            defer_script=await self._is_defer(
                script
            ),

            integrity=await self._read_integrity(
                script
            ),

            crossorigin=await self._read_crossorigin(
                script
            ),

            size=len(content),

            minified=self._looks_minified(
                content
            ),

        )

    # ==========================================================
    # HELPERS
    # ==========================================================

    async def _read_src(
        self,
        script,
    ) -> str:

        return (
            await script.get_attribute("src")
            or ""
        )

    async def _read_type(
        self,
        script,
    ) -> str:

        return (
            await script.get_attribute("type")
            or "text/javascript"
        )

    async def _read_integrity(
        self,
        script,
    ) -> str:

        return (
            await script.get_attribute("integrity")
            or ""
        )

    async def _read_crossorigin(
        self,
        script,
    ) -> str:

        return (
            await script.get_attribute("crossorigin")
            or ""
        )

    async def _is_async(
        self,
        script,
    ) -> bool:

        return (
            await script.get_attribute("async")
        ) is not None

    async def _is_defer(
        self,
        script,
    ) -> bool:

        return (
            await script.get_attribute("defer")
        ) is not None

    async def _read_inline(
        self,
        script,
        inline: bool,
    ) -> str:

        if not inline:
            return ""

        try:

            return await script.inner_text()

        except Exception:

            return ""

    # ==========================================================
    # MINIFIED DETECTION
    # ==========================================================

    @staticmethod
    def _looks_minified(
        script: str,
    ) -> bool:

        if not script:

            return False

        lines = script.count("\n")

        if lines == 0:

            return len(script) > 500

        average = len(script) / max(lines, 1)

        return average > 250