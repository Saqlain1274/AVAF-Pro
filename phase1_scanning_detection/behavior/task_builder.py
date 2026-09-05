"""
===============================================================================
AVAF PRO

Task Builder

Purpose
-------
Convert prioritized assets into BehaviorTask objects.

Responsibilities
----------------
✓ Create BehaviorTask
✓ Preserve metadata
✓ Normalize fields

Never
-----
✘ Analyze DOM
✘ Score assets
✘ Execute interactions
===============================================================================
"""

from __future__ import annotations

from phase1_scanning_detection.behavior.behavior_engine import BehaviorTask


class TaskBuilder:

    def __init__(self):

        pass

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def build(

        self,

        assets: list,

    ) -> list:

        tasks = []

        for asset in assets:

            task = self._build(asset)

            if task:

                tasks.append(task)

        return tasks

    # ==========================================================
    # BUILD ONE TASK
    # ==========================================================

    def _build(

        self,

        asset: dict,

    ):

        data = asset["asset"]

        return BehaviorTask(

            priority=asset["priority"],

            action=asset["type"],

            selector=self.selector(data),

            description=asset["type"],

            element=data.get(

                "element"

            ),

            metadata=data,

        )

    # ==========================================================
    # Selector
    # ==========================================================

    def selector(

        self,

        asset,

    ):

        if not isinstance(asset, dict):

            return ""

        return (

            asset.get("action")

            or asset.get("href")

            or asset.get("endpoint")

            or asset.get("url")

            or asset.get("route")

            or asset.get("name")

            or asset.get("text")

            or ""

        )