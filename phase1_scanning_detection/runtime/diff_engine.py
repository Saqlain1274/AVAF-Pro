"""
===============================================================================
AVAF PRO

Response Difference Engine

Purpose
-------
Compares two HTTP responses and produces a normalized difference model.

Used by:
    • SQL Injection Validation
    • XSS Validation
    • Authentication Testing
    • Replay Engine
    • Behaviour Analysis

===============================================================================
"""


class DiffEngine:

    @staticmethod
    def compare(original, replay):

        return {

            "status_changed":
                original.status != replay.status,

            "length_changed":
                original.length != replay.length,

            "hash_changed":
                original.body_hash != replay.body_hash,

            "headers_changed":
                original.headers != replay.headers,

            "redirect_changed":
                getattr(original, "redirect_url", "")
                !=
                getattr(replay, "redirect_url", ""),

            "content_type_changed":
                getattr(original, "content_type", "")
                !=
                getattr(replay, "content_type", ""),

            "cookies_changed":
                getattr(original, "cookies", {})
                !=
                getattr(replay, "cookies", {}),

            "is_identical":
                (
                    original.status == replay.status
                    and
                    original.length == replay.length
                    and
                    original.body_hash == replay.body_hash
                )

        }