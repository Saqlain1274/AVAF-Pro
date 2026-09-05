"""
attack_context.py

Shared runtime intelligence for the Phase-2 Validation Engine.

This object is populated once before validation starts and is
shared by every validator (SQLi, XSS, LFI, etc.).

Author: AVAF Pro
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(slots=True)
class AttackContext:
    """
    Shared runtime intelligence.

    Every validator receives the SAME context object.
    Nothing inside this class performs attacks.
    """

    # ------------------------------------------------------------------
    # Target Information
    # ------------------------------------------------------------------

    target_url: str
    final_url: str = ""

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    server: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None
    database: Optional[str] = None

    technologies: Set[str] = field(default_factory=set)

    # ------------------------------------------------------------------
    # Runtime Discovery
    # ------------------------------------------------------------------

    runtime_forms: List[Any] = field(default_factory=list)

    runtime_endpoints: List[Any] = field(default_factory=list)

    xhr_endpoints: Set[str] = field(default_factory=set)

    graphql_endpoints: Set[str] = field(default_factory=set)

    websocket_endpoints: Set[str] = field(default_factory=set)

    uploads: List[Any] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    authenticated: bool = False

    cookies: Dict[str, str] = field(default_factory=dict)

    csrf_tokens: Dict[str, str] = field(default_factory=dict)

    headers: Dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Runtime Behaviour
    # ------------------------------------------------------------------

    javascript_enabled: bool = True

    dom_loaded: bool = False

    spa_application: bool = False

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    baseline_status: Optional[int] = None

    baseline_length: Optional[int] = None

    baseline_hash: Optional[str] = None

    baseline_response_time: Optional[float] = None

    # ------------------------------------------------------------------
    # Validation Cache
    # ------------------------------------------------------------------

    evidence_cache: Dict[str, Any] = field(default_factory=dict)

    successful_payloads: Dict[str, Any] = field(default_factory=dict)

    failed_payloads: Set[str] = field(default_factory=set)

    response_cache: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    metadata: Dict[str, Any] = field(default_factory=dict)