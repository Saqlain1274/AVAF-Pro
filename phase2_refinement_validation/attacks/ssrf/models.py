from dataclasses import dataclass


@dataclass(slots=True)
class SSRFEvidence:

    payload: str

    matched_text: str