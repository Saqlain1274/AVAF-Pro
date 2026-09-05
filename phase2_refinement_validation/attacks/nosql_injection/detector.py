from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import NOSQL_INDICATORS


class NoSQLDetector:

    def detect(
        self,
        vector,
        payload,
        response,
    ):

        body = ""

        if hasattr(response, "text"):
            body = response.text or ""
        elif isinstance(response, str):
            body = response

        for indicator in NOSQL_INDICATORS:

            if indicator.lower() in body.lower():

                return AttackResult(
                    attack="nosql_injection",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator=indicator,
                    confidence=0.85,
                )

        return None