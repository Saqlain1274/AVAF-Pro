from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import REFLECTION_INDICATORS


class XSSDetector:

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

        for indicator in REFLECTION_INDICATORS:

            if indicator in body:

                return AttackResult(
                    attack="xss",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator="payload_reflected",
                    confidence=0.60,
                )

        return None