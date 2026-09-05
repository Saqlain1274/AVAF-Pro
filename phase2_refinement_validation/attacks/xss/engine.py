from phase2_refinement_validation.attacks.base_payload_attack import (
    BasePayloadAttack,
)

from .detector import XSSDetector
from .payloads import XSSPayloadProvider


class XSSAttack(BasePayloadAttack):

    id = "xss"

    name = "Cross Site Scripting"

    capability = None

    def __init__(self):

        self.payload_provider = XSSPayloadProvider()

        self.detector = XSSDetector()

    def supports(
        self,
        vector,
    ):
        parameter_type = str(
            getattr(vector, "parameter_type", "") or ""
        ).lower()
    
        if parameter_type not in {
            "query",
            "form",
            "json",
            "xml",
        }:
            return False
    
        parameter = str(
            getattr(vector, "parameter", "") or ""
        ).lower()
    
        protocol_parameters = {
            "eio",
            "transport",
            "t",
            "sid",
            "callback",
            "socket",
        }
    
        if parameter in protocol_parameters:
            return False
    
        reflection_names = {
            "q",
            "query",
            "search",
            "keyword",
            "name",
            "title",
            "message",
            "comment",
            "text",
            "content",
            "description",
            "value",
            "input",
            "redirect",
            "url",
        }
    
        return parameter in reflection_names    