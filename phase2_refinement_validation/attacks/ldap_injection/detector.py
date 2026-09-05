from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import LDAP_INDICATORS


class LDAPDetector:

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

        for indicator in LDAP_INDICATORS:

            if indicator.lower() in body.lower():

                return AttackResult(
                    attack="ldap_injection",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator=indicator,
                    confidence=0.85,
                )

        return None