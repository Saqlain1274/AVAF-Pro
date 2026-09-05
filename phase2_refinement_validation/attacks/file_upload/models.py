from dataclasses import dataclass


@dataclass(slots=True)
class UploadEvidence:

    filename: str

    location: str

    matched_text: str