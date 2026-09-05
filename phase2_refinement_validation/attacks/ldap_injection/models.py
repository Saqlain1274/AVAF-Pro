from dataclasses import dataclass


@dataclass(slots=True)
class LDAPEvidence:

    payload: str

    matched_text: str