"""
===============================================================================
AVAF Pro
Comment Extractor

Responsible ONLY for extracting HTML comments.

Extracts:
    • HTML comments

Ignores:
    • Empty comments

Returns:
    ExtractorResult[str]
===============================================================================
"""

from __future__ import annotations

import re

from ..base_extractor import BaseExtractor
from ..model import ExtractorResult


class CommentExtractor(BaseExtractor):
    """
    Passive HTML comment extractor.
    """

    COMMENT_REGEX = re.compile(
        r"<!--(.*?)-->",
        re.DOTALL,
    )

    def __init__(self) -> None:
        super().__init__()

    # ==========================================================
    # Public API
    # ==========================================================

    def extract(
        self,
        html: str,
    ) -> ExtractorResult:

        self.start()

        try:

            comments = self.COMMENT_REGEX.findall(html)

            self.set_total(len(comments))

            for comment in comments:

                comment = comment.strip()

                if not comment:

                    self.ignore()

                    continue

                self.add_item(comment)

        except Exception as exc:

            self.error(exc)

            self.warning(
                "Unable to extract HTML comments."
            )

        return self.finish()