from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import OpenRedirectPayloadProvider
from .detector import OpenRedirectDetector


class OpenRedirectAttack(BasePayloadAttack):

    id = "open_redirect"

    name = "Open Redirect"

    capability = None

    def __init__(self):

        self.payload_provider = OpenRedirectPayloadProvider()

        self.detector = OpenRedirectDetector()

    def supports(
        self,
        vector,
    ) -> bool:
        parameter_type = str(
            getattr(vector, "parameter_type", "") or ""
        ).strip().lower()
    
        parameter = str(
            getattr(vector, "parameter", "") or ""
        ).strip().lower()
    
        if parameter_type not in {
            "query",
            "form",
            "json",
            "xml",
        }:
            return False
    
        redirect_names = {
            "url",
            "uri",
            "redirect",
            "redirect_url",
            "redirect_uri",
            "return",
            "return_url",
            "return_uri",
            "next",
            "continue",
            "continue_url",
            "target",
            "destination",
            "dest",
            "callback",
            "to",
        }
    
        return parameter in redirect_names