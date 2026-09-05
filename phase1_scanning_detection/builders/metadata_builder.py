"""
===============================================================================
AVAF PRO

Metadata Builder

Purpose
-------
Build PageResult metadata.

Responsibilities
----------------
✓ Runtime metadata
✓ Behavior metadata
✓ Interaction metadata
✓ Runtime artifacts
✓ Parameters

Never
-----
✘ Build PageResult
✘ Parse runtime
✘ Queue URLs
===============================================================================
"""

from __future__ import annotations


class MetadataBuilder:

    def __init__(self):

        pass

    # ======================================================
    # PUBLIC
    # ======================================================

    def build(

        self,

        runtime,

        behavior=None,

        interaction=None,

    ) -> dict:

        metadata = {}

        metadata["behavior"] = behavior

        metadata["interaction"] = interaction

        metadata["parameters"] = self._parameters(

            runtime,

        )

        metadata["runtime_artifacts"] = (

            runtime.runtime_data.get(

                "artifacts",

                {},

            )

        )

        metadata["statistics"] = (

            runtime.statistics

        )

        metadata["events"] = len(

            runtime.events

        )

        return metadata

    # ======================================================
    # PARAMETERS
    # ======================================================

    def _parameters(

        self,

        runtime,

    ):

        artifacts = runtime.runtime_data.get(

            "artifacts",

            {},

        )

        return list(

            artifacts.get(

                "parameters",

                [],

            )

        )