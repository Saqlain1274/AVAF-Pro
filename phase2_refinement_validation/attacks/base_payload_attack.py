"""
===============================================================================
Base Payload Attack

Reusable implementation for payload-based attacks.

Responsibilities
----------------
✔ Generate payloads
✔ Execute shared attack pipeline
✔ Delegate detection to attack-specific detector

Used by:
    - SQL Injection
    - XSS
    - LFI
    - RFI
    - XXE
    - SSRF
    - Command Injection
    - NoSQL Injection
    - LDAP Injection
    - File Upload
    - Open Redirect
===============================================================================
"""

from __future__ import annotations

from abc import ABC

from phase2_refinement_validation.attacks.base_attack import BaseAttack
from phase2_refinement_validation.engine.attack_engine import AttackEngine


class BasePayloadAttack(
    BaseAttack,
    AttackEngine,
    ABC,
):
    """
    Base class for all payload-based attacks.
    """

    payload_provider = None

    detector = None

    def generate_payloads(
        self,
        vector,
    ):

        if self.payload_provider is None:
            raise RuntimeError(
                "payload_provider is not configured."
            )

        return self.payload_provider.generate(
            vector
        )

    def execute(
        self,
        vector,
        context,
    ):

        if self.detector is None:
            raise RuntimeError(
                "detector is not configured."
            )

        return self.execute_pipeline(
            vector=vector,
            context=context,
            detector=self.detector,
        )