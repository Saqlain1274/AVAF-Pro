"""
===============================================================================
AVAF Pro

Application Models

High-level crawler models shared across AVAF Pro.

Consumed By
-----------
✓ Validation Engine
✓ Reporting Engine
✓ Dashboard
✓ Exporters

DiscoveryResult remains the single source of truth for extracted
technical information.
===============================================================================
"""

from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field

from typing import Any

from phase1_scanning_detection.discovery.model import DiscoveryResult


# =============================================================================
# PAGE RESULT
# =============================================================================

@dataclass(slots=True)
class PageResult:
    """
    Represents one completely processed web page.
    """

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    url: str

    final_url: str

    title: str

    status: int

    depth: int

    # ---------------------------------------------------------
    # Rendering
    # ---------------------------------------------------------

    screenshot: str = ""

    html: str = ""

    render_time: float = 0.0

    # ---------------------------------------------------------
    # Discovery
    # ---------------------------------------------------------

    discovery: DiscoveryResult = field(
        default_factory=DiscoveryResult
    )

    # ---------------------------------------------------------
    # Fingerprints
    # ---------------------------------------------------------

    dom_hash: str = ""

    content_hash: str = ""

    # ---------------------------------------------------------
    # Extra Information
    # ---------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def to_dict(self) -> dict:

        return asdict(self)
