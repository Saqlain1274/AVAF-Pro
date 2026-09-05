from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import NoSQLPayloadProvider
from .detector import NoSQLDetector


class NoSQLInjectionAttack(BasePayloadAttack):

    id = "nosql_injection"
    name = "NoSQL Injection"

    def __init__(self):
        self.payload_provider = NoSQLPayloadProvider()
        self.detector = NoSQLDetector()

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
    
        protocol_parameters = {
            "eio",
            "sid",
            "t",
            "transport",
            "callback",
            "jsonp",
            "timestamp",
            "_",
        }
    
        if parameter in protocol_parameters:
            return False
    
        nosql_names = {
            "id",
            "uid",
            "user",
            "username",
            "userid",
            "account",
            "account_id",
            "email",
            "name",
            "search",
            "query",
            "filter",
            "where",
            "sort",
            "field",
            "value",
            "key",
        }
    
        return parameter in nosql_names