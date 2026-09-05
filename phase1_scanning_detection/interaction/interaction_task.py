"""
===============================================================================
AVAF PRO

Interaction Model

Represents a single browser interaction discovered by the
Interaction Engine.

Examples
--------
✓ Click Button
✓ Click Link
✓ Open Menu
✓ Expand Accordion
✓ Submit Form
✓ Select Option
✓ Hover Element
✓ Scroll Page

This file contains ONLY data models.

Never
-----
✘ Execute interactions
✘ Make decisions
✘ Access Playwright
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ==========================================================
# PRIORITY LEVELS
# ==========================================================

class InteractionPriority:

    CRITICAL = 100
    HIGH = 75
    NORMAL = 50
    LOW = 25
    BACKGROUND = 0


# ==========================================================
# INTERACTION TASK
# ==========================================================

@dataclass(slots=True, order=True)
class InteractionTask:
    """
    Single browser interaction scheduled by the
    Interaction Engine.
    """

    # Scheduler
    priority: int

    # Action
    action: str = field(compare=False)

    # Target
    selector: str = field(
        default="",
        compare=False
    )

    element: Any = field(
        default=None,
        compare=False
    )

    # Metadata
    description: str = field(
        default="",
        compare=False
    )

    score: int = field(
        default=0,
        compare=False
    )

    # Safety
    safe: bool = field(
        default=True,
        compare=False
    )

    runtime_only: bool = field(
        default=True,
        compare=False
    )

    # Runtime state
    executed: bool = field(
        default=False,
        compare=False
    )

    success: bool = field(
        default=False,
        compare=False
    )

    error: str = field(
        default="",
        compare=False
    )

    # ======================================================
    # Helpers
    # ======================================================

    def mark_success(self):

        self.executed = True
        self.success = True

    def mark_failure(self, message: str):

        self.executed = True
        self.success = False
        self.error = message