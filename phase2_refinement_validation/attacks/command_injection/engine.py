from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .detector import CommandInjectionDetector
from .payloads import CommandInjectionPayloadProvider


class CommandInjectionAttack(BasePayloadAttack):

    id = "command_injection"

    name = "Command Injection"

    capability = None

    def __init__(self):

        self.payload_provider = CommandInjectionPayloadProvider()
        self.detector = CommandInjectionDetector()

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
            "header",
        }:
            return False
    
        parameter = str(
            getattr(vector, "parameter", "") or ""
        ).lower()
    
        url = str(
            getattr(vector, "url", "") or ""
        ).lower()
    
        # Do not treat protocol/control parameters as normal
        # application command-injection inputs.
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
    
        # Stronger indicators that the input may represent a
        # command/path/file operation.
        command_context_names = {
            "cmd",
            "command",
            "exec",
            "execute",
            "commandline",
            "shell",
            "ping",
            "host",
            "hostname",
            "ip",
            "path",
            "file",
            "filename",
            "target",
            "dir",
            "directory",
        }
    
        if parameter in command_context_names:
            return True
    
        # Do not claim applicability merely because the parameter
        # happens to be query/form/json/etc.
        return False    