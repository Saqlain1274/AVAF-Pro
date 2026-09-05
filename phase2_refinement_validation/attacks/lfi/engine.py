from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import LFIPayloadProvider
from .detector import LFIDetector


class LFIAttack(BasePayloadAttack):

    id = "lfi"

    name = "Local File Inclusion"

    capability = None

    def __init__(self):

        self.payload_provider = LFIPayloadProvider()
        self.detector = LFIDetector()

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
    
        file_names = {
            "file",
            "filename",
            "filepath",
            "path",
            "page",
            "document",
            "template",
            "include",
            "resource",
            "view",
            "module",
            "dir",
            "directory",
            "folder",
            "load",
        }
    
        return parameter in file_names