from dataclasses import dataclass


@dataclass(slots=True)
class XSSEvidence:

    payload: str

    reflected_text: str