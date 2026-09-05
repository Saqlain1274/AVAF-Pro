from dataclasses import dataclass


@dataclass(slots=True)
class XXEEvidence:

    payload: str

    matched_text: str