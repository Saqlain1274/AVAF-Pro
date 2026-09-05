from phase2_refinement_validation.attacks.base_payload_attack import BasePayloadAttack

from .payloads import FileUploadPayloadProvider
from .detector import FileUploadDetector


class FileUploadAttack(BasePayloadAttack):

    id = "file_upload"

    name = "File Upload"

    capability = None

    def __init__(self):

        self.payload_provider = FileUploadPayloadProvider()

        self.detector = FileUploadDetector()

    def supports(
        self,
        vector,
    ):

        """
        Execute only if the attack vector represents a file upload endpoint.
        """

        return getattr(vector, "is_file_upload", False)