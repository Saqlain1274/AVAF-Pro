"""
AVAF PRO

Runtime Analyzer

Purpose
-------
Analyze runtime artifacts exported by RuntimeCollector.

Responsibilities
----------------
✓ Routes
✓ API Endpoints
✓ Fetch
✓ XHR
✓ GraphQL
✓ Uploads
✓ WebSockets
✓ Runtime Forms
✓ Runtime Parameters

Never
-----
✘ Playwright
✘ DOM
✘ Queue
✘ Build Tasks
"""

from __future__ import annotations


class RuntimeAnalyzer:

    def __init__(self):

        pass

    # =====================================================
    # Public API
    # =====================================================

    def analyze(
        self,
        runtime: dict,
    ) -> dict:

        if not runtime:

            return {}

        artifacts = runtime.get(

            "artifacts",

            {}

        )

        return {

            "routes": self.routes(artifacts),

            "endpoints": self.endpoints(artifacts),

            "fetch": self.fetch(artifacts),

            "xhr": self.xhr(artifacts),

            "graphql": self.graphql(artifacts),

            "uploads": self.uploads(artifacts),

            "websockets": self.websockets(artifacts),

            "forms": self.forms(artifacts),

            "parameters": self.parameters(artifacts),

        }

    # =====================================================
    # Routes
    # =====================================================

    def routes(self, artifacts):

        return list(

            artifacts.get(

                "routes",

                []

            )

        )

    # =====================================================
    # Endpoints
    # =====================================================

    def endpoints(self, artifacts):

        return list(

            artifacts.get(

                "endpoints",

                []

            )

        )

    # =====================================================
    # Fetch
    # =====================================================

    def fetch(self, artifacts):

        return list(

            artifacts.get(

                "fetch",

                []

            )

        )

    # =====================================================
    # XHR
    # =====================================================

    def xhr(self, artifacts):

        return list(

            artifacts.get(

                "xhr",

                []

            )

        )

    # =====================================================
    # GraphQL
    # =====================================================

    def graphql(self, artifacts):

        return list(

            artifacts.get(

                "graphql",

                []

            )

        )

    # =====================================================
    # Uploads
    # =====================================================

    def uploads(self, artifacts):

        return list(

            artifacts.get(

                "uploads",

                []

            )

        )

    # =====================================================
    # WebSockets
    # =====================================================

    def websockets(self, artifacts):

        return list(

            artifacts.get(

                "websockets",

                []

            )

        )

    # =====================================================
    # Forms
    # =====================================================

    def forms(self, artifacts):

        return list(

            artifacts.get(

                "forms",

                []

            )

        )

    # =====================================================
    # Parameters
    # =====================================================

    def parameters(self, artifacts):

        return list(

            artifacts.get(

                "parameters",

                []

            )

        )