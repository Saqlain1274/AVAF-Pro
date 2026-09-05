from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .detector import XXEDetector
from .payloads import XXEPayloadProvider


class XXEAttack(BasePayloadAttack):

    id = "xxe"

    name = "XML External Entity"

    capability = None

    def __init__(self):

        self.payload_provider = XXEPayloadProvider()

        self.detector = XXEDetector()

    def supports(
        self,
        vector,
    ):

        """
        XXE only applies to XML-based request bodies.
        """

        content_type = getattr(vector, "content_type", "")

        return "xml" in content_type.lower()