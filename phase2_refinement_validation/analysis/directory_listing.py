"""
===============================================================================
Directory Listing Analyzer
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.base_analyzer import BaseAnalyzer
from phase2_refinement_validation.models.attack_result import AttackResult


DIRECTORY_SIGNATURES = (

    "<title>Index of",

    "Directory Listing For",

    "Parent Directory",

)


class DirectoryListingAnalyzer(BaseAnalyzer):

    id = "directory_listing"

    name = "Directory Listing"

    def analyze(self, response, context):

        findings = []

        body = getattr(response, "text", "").lower()

        for signature in DIRECTORY_SIGNATURES:

            if signature.lower() in body:

                findings.append(

                    AttackResult(

                        attack="directory_listing",

                        vector=None,

                        payload=None,

                        evidence=signature,

                        indicator="Directory Listing Enabled",

                        confidence=1.0,

                    )

                )

        return findings