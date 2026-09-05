from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import LDAPPayloadProvider
from .detector import LDAPDetector


class LDAPInjectionAttack(BasePayloadAttack):

    id = "ldap_injection"

    name = "LDAP Injection"

    capability = None

    def __init__(self):

        self.payload_provider = LDAPPayloadProvider()

        self.detector = LDAPDetector()

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
    
        ldap_names = {
            "user",
            "username",
            "uid",
            "userid",
            "login",
            "account",
            "email",
            "mail",
            "cn",
            "dn",
            "filter",
            "search",
            "query",
            "name",
            "group",
            "member",
        }
    
        return parameter in ldap_names