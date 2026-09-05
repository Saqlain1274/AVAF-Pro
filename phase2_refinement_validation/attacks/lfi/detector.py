from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import FILE_INDICATORS


class LFIDetector:

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

        for indicator in FILE_INDICATORS:

            if indicator in body:

                return AttackResult(
                    attack="lfi",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator=indicator,
                    confidence=0.85,
                )

        return None