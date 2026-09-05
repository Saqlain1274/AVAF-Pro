"""
===============================================================================
Attack Vector

Represents one injectable point discovered during Phase 1.

This model is attack-agnostic.
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AttackVector:
    """
    Represents one attack surface.
    """

    # Target
    url: str
    method: str

    # Injection point
    parameter: str
    parameter_type: str

    # Nested parameter path (optional)
    parameter_path: str = ""

    # Original value

    # Original value
    original_value: Any = None

    # Request components
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    params: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    json: dict = field(default_factory=dict)

    files: dict = field(default_factory=dict)

    # HTTP Content-Type
    content_type: str = ""

    # File upload capability
    #
    # True when Phase 1 identifies this vector as a multipart/file-upload
    # injection point. FileUploadAttack uses this capability to determine
    # whether the vector is applicable.
    is_file_upload: bool = False

    metadata: dict = field(default_factory=dict)