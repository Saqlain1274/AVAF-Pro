from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import RFIPayloadProvider
from .detector import RFIDetector


class RFIAttack(BasePayloadAttack):

    id = "rfi"

    name = "Remote File Inclusion"

    capability = None

    def __init__(self):

        self.payload_provider = RFIPayloadProvider()

        self.detector = RFIDetector()

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
    
        remote_resource_names = {
            "file",
            "filename",
            "filepath",
            "path",
            "page",
            "document",
            "template",
            "include",
            "resource",
            "url",
            "uri",
            "module",
            "load",
        }
    
        return parameter in remote_resource_names