from __future__ import annotations

from phase2_refinement_validation.validators.base_validator import BaseValidator

from ..payloads.sqli import SQLiPayloads

from ..models.evidence import Evidence


class SQLiValidator(BaseValidator):

    NAME = "SQLI"

    def __init__(

        self,

        http_client,

        analyzer,

        scorer,

    ):

        self.http = http_client

        self.analyzer = analyzer

        self.scorer = scorer

    # ==========================================================
    # MAIN
    # ==========================================================

    def validate(

        self,

        context,

        plan,

    ):

        baseline = self._baseline(

            context,

            plan,

        )

        if baseline is None:

            return None

        evidence = []

        for group in SQLiPayloads.groups():

            for payload in group.payloads:

                attack = self._attack(

                    context,

                    plan,

                    payload,

                )

                result = self.analyzer.compare(

                    baseline,

                    attack,

                    payload,

                )

                if not result.confirmed:

                    continue

                result.technique = group.name

                evidence.append(result)

        if not evidence:

            return None

        confidence = self.scorer.calculate(

            evidence

        )

        return Evidence(

            vulnerability=self.NAME,

            url=plan.url,

            parameter=plan.parameter,

            confidence=confidence,

            attacks=evidence,

        )

    # ==========================================================
    # BASELINE
    # ==========================================================

    def _baseline(

        self,

        context,

        plan,

    ):

        return self.http.send(

            method=plan.method,

            url=plan.url,

            parameter=plan.parameter,

            value=plan.original_value,

            location=plan.location,

        )

    # ==========================================================
    # ATTACK
    # ==========================================================

    def _attack(

        self,

        context,

        plan,

        payload,

    ):

        return self.http.send(

            method=plan.method,

            url=plan.url,

            parameter=plan.parameter,

            value=payload,

            location=plan.location,

        )