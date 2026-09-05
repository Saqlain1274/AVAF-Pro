from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import COMMAND_INDICATORS


class CommandInjectionDetector:

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

        for indicator in COMMAND_INDICATORS:

            if indicator in body:

                return AttackResult(
                    attack="command_injection",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator=indicator,
                    confidence=0.90,
                )

        return None