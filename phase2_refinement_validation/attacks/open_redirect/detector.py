from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import REDIRECT_STATUS_CODES


class OpenRedirectDetector:

    def detect(
        self,
        vector,
        payload,
        response,
    ):

        status = getattr(response, "status_code", None)

        headers = getattr(response, "headers", {})

        location = headers.get("Location", "")

        if (
            status in REDIRECT_STATUS_CODES
            and payload in location
        ):

            return AttackResult(
                attack="open_redirect",
                vector=vector,
                payload=payload,
                evidence=location,
                indicator="Location Header",
                confidence=0.95,
            )

        return None