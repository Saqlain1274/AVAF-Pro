"""
===============================================================================
AVAF Pro

Evidence Engine

Responsibilities
----------------
✔ Merge validator evidence
✔ Remove duplicates
✔ Keep strongest evidence
✔ Normalize evidence

===============================================================================
"""

from __future__ import annotations

from collections import defaultdict

from ..models.evidence import (
    Evidence,
    AttackEvidence,
)


class EvidenceEngine:

    def build(

        self,

        evidences: list[Evidence],

    ) -> list[Evidence]:

        grouped = defaultdict(list)

        # ---------------------------------------------------------
        # Group by Vulnerability + URL + Parameter
        # ---------------------------------------------------------

        for evidence in evidences:

            key = (

                evidence.vulnerability,

                evidence.url,

                evidence.parameter,

            )

            grouped[key].append(evidence)

        merged = []

        # ---------------------------------------------------------
        # Merge
        # ---------------------------------------------------------

        for items in grouped.values():

            merged.append(

                self._merge(items)

            )

        return merged

    # =============================================================
    # MERGE
    # =============================================================

    def _merge(

        self,

        evidences: list[Evidence],

    ) -> Evidence:

        base = evidences[0]

        attacks = []

        seen = set()

        highest = base.confidence

        for evidence in evidences:

            highest = max(

                highest,

                evidence.confidence,

            )

            for attack in evidence.attacks:

                key = (

                    attack.payload,

                    tuple(attack.matched_rules),

                    tuple(attack.indicators),

                )

                if key in seen:

                    continue

                seen.add(key)

                attacks.append(attack)

        return Evidence(

            vulnerability=base.vulnerability,

            url=base.url,

            parameter=base.parameter,

            confidence=highest,

            attacks=attacks,

        )