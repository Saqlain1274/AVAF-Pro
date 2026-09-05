"""
===============================================================================
SQL Injection Internal Models

Private models used only by the SQL Injection plugin.

These models must never be used by the framework.
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SQLiEvidence:
    """
    Internal SQL Injection evidence.
    """

    dbms: str

    indicator: str

    payload: str

    matched_text: str