"""
===============================================================================
AVAF PRO

Behavioral Evidence Priority Engine
===============================================================================

Purpose
-------
Rank evidence that was actually observed by the browser-driven Phase-1
discovery pipeline.

This component does NOT discover anything.

It does NOT:
    - generate URLs
    - guess routes
    - recognize predefined application paths
    - use endpoint wordlists
    - infer application functionality from names
    - scan JavaScript source for endpoint strings
    - scan arbitrary HTML for endpoint strings
    - attack the target
    - validate vulnerabilities

Priority is based only on evidence characteristics already supplied by the
browser observation pipeline.

Examples of legitimate evidence:

    - visible interactive DOM controls
    - forms actually rendered in the DOM
    - password/file inputs actually rendered
    - observed browser navigation
    - observed XHR
    - observed fetch
    - observed WebSocket traffic
    - observed runtime route transitions
    - observed form submissions
    - observed parameters
    - observed GraphQL traffic
    - observed request methods
    - observed state transitions

The engine only ranks existing evidence.

It never creates evidence.
===============================================================================
"""

from __future__ import annotations


class PriorityEngine:
    """
    Rank browser-observed evidence.

    The engine is intentionally semantic-neutral.

    It does not care whether an application calls something:
        login
        admin
        search
        upload
        checkout
        dashboard
        etc.

    Those names are not security evidence by themselves.

    Structural and behavioral observations are what matter.
    """

    def __init__(self):
        pass

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def build(
        self,
        dom_assets: dict | None,
        runtime_assets: dict | None,
    ) -> list:
        """
        Build a ranked list from already observed evidence.

        No discovery occurs here.
        """

        dom_assets = (
            dom_assets
            if isinstance(dom_assets, dict)
            else {}
        )

        runtime_assets = (
            runtime_assets
            if isinstance(runtime_assets, dict)
            else {}
        )

        assets = []

        assets.extend(
            self.score_forms(
                dom_assets.get("forms", [])
            )
        )

        assets.extend(
            self.score_inputs(
                dom_assets.get("inputs", [])
            )
        )

        assets.extend(
            self.score_buttons(
                dom_assets.get("buttons", [])
            )
        )

        assets.extend(
            self.score_links(
                dom_assets.get("links", [])
            )
        )

        assets.extend(
            self.score_runtime(
                runtime_assets
            )
        )

        return sorted(
            assets,
            key=lambda item: item.get(
                "priority",
                0,
            ),
            reverse=True,
        )

    # ==========================================================
    # FORMS
    # ==========================================================

    # ==========================================================
    # Forms
    # ==========================================================

    def score_forms(self, forms):

        scored = []

        for form in forms:

            method = str(
                form.get(
                    "method",
                    "GET",
                )
            ).upper()

            inputs = form.get(
                "inputs",
                0,
            )

            try:
                input_count = int(inputs)
            except (TypeError, ValueError):
                input_count = 0

            priority = 60

            if method == "POST":
                priority += 15

            if input_count > 0:
                priority += min(
                    input_count * 3,
                    15,
                )

            priority = min(
                priority,
                95,
            )

            scored.append({
                "type": "form",
                "priority": priority,
                "asset": form,
            })

        return scored

    # ==========================================================
    # Inputs
    # ==========================================================

    def score_inputs(self, inputs):

        scored = []

        for inp in inputs:

            input_type = str(
                inp.get(
                    "type",
                    "text",
                )
            ).lower()

            priority = 35

            # These are actual DOM control types.
            # No application path/name assumptions are used.

            if input_type == "password":
                priority = 90

            elif input_type == "file":
                priority = 85

            elif input_type == "email":
                priority = 75

            elif input_type == "search":
                priority = 70

            elif input_type == "hidden":
                priority = 65

            elif input_type in {
                "text",
                "number",
                "url",
                "tel",
            }:
                priority = 60

            scored.append({
                "type": "input",
                "priority": priority,
                "asset": inp,
            })

        return scored

    # ==========================================================
    # Buttons
    # ==========================================================

    def score_buttons(self, buttons):

        scored = []

        for button in buttons:

            role = str(
                button.get(
                    "role",
                    "",
                )
            ).lower()

            text = str(
                button.get(
                    "text",
                    "",
                )
            ).strip()

            priority = 50

            if role == "button":
                priority += 5

            if text:
                priority += 5

            scored.append({
                "type": "button",
                "priority": min(
                    priority,
                    70,
                ),
                "asset": button,
            })

        return scored

    # ==========================================================
    # Links
    # ==========================================================

    def score_links(self, links):

        scored = []

        for link in links:

            href = str(
                link.get(
                    "href",
                    "",
                )
            ).strip()

            text = str(
                link.get(
                    "text",
                    "",
                )
            ).strip()

            priority = 45

            # A link with an actual observed destination is useful.
            if href:
                priority += 10

            # Visible text provides additional interaction context.
            if text:
                priority += 5

            scored.append({
                "type": "link",
                "priority": min(
                    priority,
                    65,
                ),
                "asset": link,
            })

        return scored

    # ==========================================================
    # Runtime
    # ==========================================================

    def score_runtime(self, runtime):

        scored = []

        if not isinstance(
            runtime,
            dict,
        ):
            return scored

        # Runtime categories represent actual browser observations.
        #
        # Priority is based on observation type, NOT endpoint names.

        mapping = {
            "graphql": 90,
            "endpoints": 88,
            "routes": 85,
            "uploads": 84,
            "fetch": 82,
            "xhr": 82,
            "websockets": 80,
            "forms": 78,
            "parameters": 85,
            "navigations": 90,
            "observed_navigations": 90,
            "navigation_routes": 90,
            "dynamic_routes": 88,
        }

        for category, priority in mapping.items():

            values = runtime.get(
                category,
                [],
            )

            if values is None:
                continue

            if isinstance(
                values,
                dict,
            ):
                values = values.get(
                    "items",
                    [],
                )

            if not isinstance(
                values,
                (list, tuple, set),
            ):
                values = [values]

            for asset in values:

                if asset is None:
                    continue

                scored.append({
                    "type": category,
                    "priority": priority,
                    "asset": asset,
                })

        return scored
    
    # ==========================================================
    # RUNTIME EVIDENCE
    # ==========================================================

    def score_runtime(
        self,
        runtime: dict | None,
    ) -> list:
        """
        Rank runtime evidence according to the observation mechanism.

        These categories are not guessed from URL names. They are supplied
        by the browser/runtime instrumentation.
        """

        if not isinstance(
            runtime,
            dict,
        ):
            return []

        scored = []

        priority_by_source = {
            "graphql": 88,
            "websockets": 86,
            "xhr": 84,
            "fetch": 84,
            "endpoints": 82,
            "routes": 80,
            "uploads": 80,
            "forms": 78,
            "parameters": 76,
        }

        for category, base_priority in (
            priority_by_source.items()
        ):

            observations = runtime.get(
                category,
                [],
            )

            if not isinstance(
                observations,
                (list, tuple, set),
            ):
                continue

            for observation in observations:

                priority = self._behavioral_adjustment(
                    base_priority,
                    observation,
                )

                scored.append(
                    {
                        "type": category,
                        "priority": priority,
                        "asset": observation,
                    }
                )

        return scored

    # ==========================================================
    # BEHAVIORAL ADJUSTMENT
    # ==========================================================

    @staticmethod
    def _behavioral_adjustment(
        base_priority: int,
        observation,
    ) -> int:
        """
        Adjust priority using properties of the observation itself.

        This deliberately avoids URL/path/name heuristics.
        """

        priority = int(
            base_priority
        )

        if isinstance(
            observation,
            dict,
        ):

            method = str(
                observation.get(
                    "method",
                    "",
                )
                or ""
            ).upper()

            source = str(
                observation.get(
                    "source",
                    "",
                )
                or ""
            ).lower()

            # Observed state-changing HTTP methods are stronger evidence
            # than passive GET traffic.
            if method in {
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            }:
                priority += 8

            # Evidence explicitly tied to an actual browser action is
            # stronger than an undifferentiated passive observation.
            if source in {
                "click",
                "form-submit",
                "interaction",
                "browser-action",
                "dom-interaction",
            }:
                priority += 5

        return min(
            priority,
            100,
        )

    # ==========================================================
    # SAFE INTEGER CONVERSION
    # ==========================================================

    @staticmethod
    def _safe_int(value) -> int:

        try:
            return max(
                int(value),
                0,
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0