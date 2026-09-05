from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .detector import SQLiDetector
from .payloads import SQLiPayloadProvider


class SQLInjectionAttack(BasePayloadAttack):

    id = "sqli"

    name = "SQL Injection"

    capability = None

    def __init__(self):

        self.detector = SQLiDetector()
        self.payload_provider = SQLiPayloadProvider()

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
            "cookie",
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
    
        # Parameters that commonly represent application data.
        data_names = {
            "id",
            "uid",
            "user",
            "userid",
            "username",
            "email",
            "name",
            "search",
            "query",
            "keyword",
            "q",
            "category",
            "product",
            "item",
            "page",
            "sort",
            "order",
            "filter",
            "account",
            "accountid",
            "postid",
            "productid",
        }
    
        return parameter in data_names