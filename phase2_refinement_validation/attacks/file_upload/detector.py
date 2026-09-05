from phase2_refinement_validation.models.attack_result import AttackResult

from .indicators import UPLOAD_INDICATORS


class FileUploadDetector:

    def detect(
        self,
        vector,
        payload,
        response,
    ):

        body = ""

        if hasattr(response, "text"):
            body = response.text or ""
        elif isinstance(response, str):
            body = response

        for indicator in UPLOAD_INDICATORS:

            if indicator.lower() in body.lower():

                return AttackResult(
                    attack="file_upload",
                    vector=vector,
                    payload=payload,
                    evidence=indicator,
                    indicator=indicator,
                    confidence=0.80,
                )

        return None