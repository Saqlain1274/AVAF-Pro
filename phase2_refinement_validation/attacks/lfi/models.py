from dataclasses import dataclass


@dataclass(slots=True)
class LFIEvidence:

    payload: str

    matched_text: str