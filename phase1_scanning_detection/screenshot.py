"""
AVAF PRO
Screenshot Engine

Captures one unique full-page screenshot for each discovered browser page.

Responsibilities:
    - Capture the current Playwright page after rendering/JavaScript execution.
    - Store screenshots separately.
    - Prevent filename collisions.
    - Keep screenshot logic independent from the GUI.
    - Return the screenshot path to PlaywrightCrawler.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional

from phase1_scanning_detection.discovery.logger import logger


class ScreenshotEngine:
    """
    Browser screenshot storage engine.

    The crawler decides WHEN a page should be captured.
    This class only captures and stores the screenshot.

    GUI integration should happen through PlaywrightCrawler,
    not directly inside this class.
    """

    def __init__(self):
        # ---------------------------------------------------------
        # Project location
        # ---------------------------------------------------------

        # This file is expected to live under:
        #
        # phase1_scanning_detection/
        #     discovery/
        #         screenshot_engine.py
        #
        # Therefore:
        #   parent      = discovery
        #   parent.parent = phase1_scanning_detection
        #
        phase1_root = Path(__file__).resolve().parent.parent

        self.output = phase1_root / "screenshots"

        self.output.mkdir(
            parents=True,
            exist_ok=True,
        )

        # The crawler owns page identity and screenshot numbering.
        # ScreenshotEngine must never maintain a competing counter.

    # =============================================================
    # URL SANITIZATION
    # =============================================================

    @staticmethod
    def _safe_name(value: str) -> str:
        """
        Convert a URL component into a filesystem-safe string.
        """

        value = re.sub(
            r"[^a-zA-Z0-9._-]+",
            "_",
            value,
        )

        value = value.strip("._")

        if not value:
            value = "page"

        return value[:100]

    # =============================================================
    # URL HASH
    # =============================================================

    @staticmethod
    def _url_hash(url: str) -> str:
        """
        Create a stable short hash for the URL.

        This prevents collisions such as:

            /product?id=1
            /product?id=2

        from overwriting each other.
        """

        return hashlib.sha256(
            url.encode("utf-8", errors="ignore")
        ).hexdigest()[:12]

    # =============================================================
    # SCREENSHOT
    # =============================================================

    async def capture(
        self,
        page,
        url: str,
        page_number: Optional[int] = None,
    ) -> Optional[str]:
        """
        Capture the currently rendered Playwright page.

        Parameters
        ----------
        page:
            Playwright Page instance.

        url:
            Current/final page URL.

        page_number:
            Optional unique crawler page number.

        Returns
        -------
        str | None
            Absolute screenshot path when successful.
        """

        if page is None:
            logger.debug(
                "SCREENSHOT",
                "Capture skipped: page is None",
            )
            return None

        try:
            if page.is_closed():
                logger.debug(
                    "SCREENSHOT",
                    "Capture skipped: page is closed",
                )
                return None

            # -----------------------------------------------------
            # Determine actual browser URL
            # -----------------------------------------------------

            try:
                current_url = page.url or url
            except Exception:
                current_url = url

            if not current_url:
                current_url = "unknown_page"

                       # -----------------------------------------------------
            # Screenshot number
            #
            # The crawler owns page identity.
            # A screenshot without an explicit page number is not
            # assigned an invented crawler page number.
            # -----------------------------------------------------

            if page_number is None:
                logger.warning(
                    "SCREENSHOT",
                    (
                        "Capture skipped: crawler did not provide "
                        "an authoritative page number."
                    ),
                )
                return None

            number = int(page_number)

            # -----------------------------------------------------
            # Safe filename
            # -----------------------------------------------------

            safe_url = self._safe_name(
                current_url
                .replace("https://", "")
                .replace("http://", "")
            )

            url_hash = self._url_hash(
                current_url
            )

            filename = (
                f"page_{number:04d}_"
                f"{safe_url}_"
                f"{url_hash}.png"
            )

            path = self.output / filename

            # -----------------------------------------------------
            # Capture
            #
            # Playwright captures the currently rendered browser
            # state, including DOM changes made by JavaScript.
            # -----------------------------------------------------

            await page.screenshot(
                path=str(path),
                full_page=True,
                animations="disabled",
            )

            # -----------------------------------------------------
            # Verify file actually exists
            # -----------------------------------------------------

            if not path.exists():
                logger.error(
                    "SCREENSHOT",
                    f"Screenshot was not created: {path}",
                )
                return None

            logger.info(
                "SCREENSHOT",
                (
                    f"Captured page #{number}: "
                    f"{current_url} -> {path}"
                ),
            )

            return str(path.resolve())

        except Exception as exc:

            logger.error(
                "SCREENSHOT",
                (
                    f"Failed for {url}: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            return None
