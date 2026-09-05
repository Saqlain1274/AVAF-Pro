from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .detector import SSRFDetector
from .payloads import SSRFPayloadProvider


class SSRFAttack(BasePayloadAttack):

    id = "ssrf"

    name = "Server-Side Request Forgery"

    capability = None

    def __init__(self):

        self.payload_provider = SSRFPayloadProvider()

        self.detector = SSRFDetector()

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
            "cookie",
        }:
            return False
    
        destination_names = {
            "url",
            "uri",
            "target",
            "endpoint",
            "host",
            "hostname",
            "callback",
            "callback_url",
            "webhook",
            "webhook_url",
            "redirect",
            "redirect_url",
            "proxy",
            "proxy_url",
            "destination",
            "resource",
            "image_url",
            "avatar_url",
            "feed_url",
            "link",
        }
    
        return parameter in destination_names