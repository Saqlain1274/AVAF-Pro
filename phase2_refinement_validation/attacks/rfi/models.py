from dataclasses import dataclass


@dataclass(slots=True)
class RFIEvidence:

    payload: str

    matched_text: str