from dataclasses import dataclass


@dataclass(slots=True)
class CommandInjectionEvidence:

    payload: str

    matched_text: str