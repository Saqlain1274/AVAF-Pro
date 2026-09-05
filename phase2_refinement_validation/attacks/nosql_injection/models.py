from dataclasses import dataclass


@dataclass(slots=True)
class NoSQLEvidence:

    payload: str

    matched_text: str